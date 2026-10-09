import secrets
import datetime
import asyncio
import anyio
import resend
from fastapi import BackgroundTasks, HTTPException, status
from redis.asyncio import Redis

from app.core.config import Settings
from app.core.tasks import fire_and_log

OTP_TTL_SECONDS = 5 * 60
OTP_RATE_LIMIT_SECONDS = 60
current=75

# A 6-digit code is only a million possibilities, so the code itself is not
# the defence - limiting guesses is. After this many wrong attempts the code
# is burned and the attacker has to request a new one, which the 60s limit
# plus the hourly cap below make slow enough to be useless.
MAX_VERIFY_ATTEMPTS = 5
# Bounds the "request a fresh code every 60s and keep grinding" loop.
MAX_REQUESTS_PER_HOUR = 10
REQUEST_WINDOW_SECONDS = 60 * 60


def normalize_email(email: str) -> str:
    """Lowercase and strip +tag local-part addressing so name+1@x and name@x
    resolve to the same account (closes an easy multi-account loophole)."""
    local, _, domain = email.strip().lower().partition("@")
    local = local.split("+", 1)[0]
    return f"{local}@{domain}"


def normalize_phone(phone: str) -> str:
    """Normalize an Indian mobile number to E.164 (+919876543210).

    Accepts what people actually type: spaces, dashes, a leading 0, a +91 or 91
    country prefix. Rejects anything that isn't a valid Indian mobile, which
    start with 6-9. Raises HTTPException so callers can pass user input
    straight through.
    """
    digits = "".join(ch for ch in phone if ch.isdigit())

    # Strip the country code or a domestic trunk '0' to get the 10-digit number.
    if len(digits) == 12 and digits.startswith("91"):
        digits = digits[2:]
    elif len(digits) == 11 and digits.startswith("0"):
        digits = digits[1:]

    if len(digits) != 10 or digits[0] not in "6789":
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Enter a valid 10-digit Indian mobile number.",
        )
    return f"+91{digits}"


def assert_allowed_domain(email: str, settings: Settings, action: str = "sign up") -> None:
    """Require an institute address.

    Applied to the customer login routes and, separately, to placing an order.
    Stall owners are deliberately exempt - they sign in through their own routes
    with any address - so this is no longer a property of merely holding an
    account, and the places that need it have to say so.

    `action` only shapes the message. "Only @x addresses may sign up" is the
    wrong sentence to show someone who is signed in and pressing Pay.
    """
    domain = email.rsplit("@", 1)[-1].lower()
    if domain != settings.allowed_email_domain.lower():
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"Only @{settings.allowed_email_domain} email addresses may {action}.",
        )


# Both the code and the per-address throttle are keyed on the email alone, with
# no room for which route asked. That is on purpose. Namespacing them per route
# would let one address draw a fresh allowance of codes from each one, doubling
# what the hourly cap is there to bound; and a code cannot be usefully redeemed
# on the wrong route anyway, because the customer verify route checks the domain
# before it checks the code.
def _otp_key(email: str) -> str:
    return f"otp:code:{email}"


def _rate_limit_key(email: str) -> str:
    return f"otp:rl:{email}"


def _attempt_key(email: str) -> str:
    return f"otp:fail:{email}"


def _hourly_key(email: str) -> str:
    return f"otp:hr:{email}"

async def reset_current_counter_at_utc_midnight():
    global current    
    while True:
        # 1. Get current time in UTC
        now_utc = datetime.datetime.now(datetime.timezone.utc)
        
        # 2. Calculate the next midnight UTC
        tomorrow_utc = now_utc + datetime.timedelta(days=1)
        next_midnight_utc = datetime.datetime(
            tomorrow_utc.year, tomorrow_utc.month, tomorrow_utc.day, 
            0, 0, 0, tzinfo=datetime.timezone.utc
        )
        
        # 3. Calculate exact seconds remaining until the reset
        seconds_to_wait = (next_midnight_utc - now_utc).total_seconds()
        
        # 4. Sleep asynchronously (non-blocking) until midnight UTC
        await asyncio.sleep(seconds_to_wait)
        
        # 5. Reset the global variable
        current = 0
        print(f"[{datetime.datetime.now()}] Success: Reset 'current' counter back to 0.")
        
        # Avoid race conditions if clocks drift slightly
        await asyncio.sleep(2)





def _send_code_email(email: str, code: str, settings: Settings, current_count: int) -> None:
    """The blocking Resend call, isolated so it can be run off the event loop."""
    resend.api_key = settings.resend_api_key if current_count<=100 else settings.resend_api_key_two
    resend.Emails.send(
        {
            "from": settings.resend_from_email,
            "to": [email],
            "subject": "Your Hungry Birds login code",
            "html": (
                f"<p>Your Hungry Birds login code is:</p>"
                f"<h2>{code}</h2>"
                f"<p>It expires in 5 minutes. If you didn't request this, ignore this email.</p>"
            ),
        }
    )


async def send_code_email(email: str, code: str, settings: Settings, current_count: int) -> None:
    """Send a login code, without holding the event loop while Resend thinks.

    `resend.Emails.send` is synchronous `requests` under the hood. Called
    directly from an async handler it blocks every other request in flight for
    the length of the round trip, which on one container is the whole service.
    """
    if not settings.resend_api_key:
        return
    await anyio.to_thread.run_sync(_send_code_email, email, code, settings, current_count)


async def request_otp(
    email: str,
    redis: Redis,
    settings: Settings,
    background: BackgroundTasks | None = None,
) -> str | None:
    """Generates and stores an OTP and arranges for it to be emailed.

    Returns the code only when OTP_DEBUG_ECHO is enabled, for local-dev
    convenience.

    The email is a background task, not part of this request. It used to be an
    unguarded synchronous call in the middle of this function, which meant a
    Resend outage did not merely fail to deliver one code - it turned *signing
    in* into a 500 for everybody, which is the worst possible thing to lose when
    email is already the thing that has broken.
    """
    remaining = await redis.ttl(_rate_limit_key(email))
    if remaining and remaining > 0:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            f"Please wait {remaining}s before requesting another code.",
            headers={"Retry-After": str(remaining)},
        )

    # Without an hourly cap, an attacker can mint a fresh code every 60s and
    # keep guessing indefinitely, which defeats the per-code attempt limit.
    hourly = await redis.incr(_hourly_key(email))
    if hourly == 1:
        await redis.expire(_hourly_key(email), REQUEST_WINDOW_SECONDS)
    if hourly > MAX_REQUESTS_PER_HOUR:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "Too many codes requested for this address. Try again later.",
        )

    # --- REDIS RESEND QUOTA TRACKING SYSTEM ---
    resend_counter_key = "resend:daily:usage"
    
    # 1. Check if the counter key already exists in Redis
    counter_exists = await redis.exists(resend_counter_key)
    
    if not counter_exists:
        # Seed the counter at your current progress of 80 instead of starting at 1
        await redis.set(resend_counter_key, 85)
        current_count = 85
        
        # Calculate exactly how many seconds remain until the next UTC Midnight reset
        now_utc = datetime.datetime.now(datetime.timezone.utc)
        tomorrow_utc = now_utc + datetime.timedelta(days=1)
        next_midnight_utc = datetime.datetime(
            tomorrow_utc.year, tomorrow_utc.month, tomorrow_utc.day, 
            0, 0, 0, tzinfo=datetime.timezone.utc
        )
        seconds_to_utc_midnight = int((next_midnight_utc - now_utc).total_seconds())
        
        # Set the key to self-destruct right at UTC Midnight
        await redis.expire(resend_counter_key, seconds_to_utc_midnight)
    else:
        # If the key already exists, simply increment it atomically (80 -> 81 -> 82...)
        current_count = await redis.incr(resend_counter_key)
        
        # If it rolls over to 1 (meaning it was wiped by the midnight expiration rule),
        # re-apply the expiration window for the new day
        if current_count == 1:
            now_utc = datetime.datetime.now(datetime.timezone.utc)
            tomorrow_utc = now_utc + datetime.timedelta(days=1)
            next_midnight_utc = datetime.datetime(
                tomorrow_utc.year, tomorrow_utc.month, tomorrow_utc.day, 
                0, 0, 0, tzinfo=datetime.timezone.utc
            )
            seconds_to_utc_midnight = int((next_midnight_utc - now_utc).total_seconds())
            await redis.expire(resend_counter_key, seconds_to_utc_midnight)
    # ------------------------------------------

    code = f"{secrets.randbelow(1_000_000):06d}"
    await redis.set(_otp_key(email), code, ex=OTP_TTL_SECONDS)
    await redis.set(_rate_limit_key(email), "1", ex=OTP_RATE_LIMIT_SECONDS)
    # A new code starts a fresh attempt budget.
    await redis.delete(_attempt_key(email))

    # Pass the current_count to send_code_email so it can switch keys at > 100
    if background is not None:
        background.add_task(
            fire_and_log, "send_code_email", lambda: send_code_email(email, code, settings, current_count)
        )
    else:
        # No request to hang the task off (a script, or a test). Still guarded,
        # so a dead Resend cannot propagate out of here.
        await fire_and_log("send_code_email", lambda: send_code_email(email, code, settings, current_count))

    return code if settings.debug_echo_enabled else None



async def verify_otp(email: str, code: str, redis: Redis) -> bool:
    """Checks a code, counting wrong guesses and burning the code once too
    many pile up.

    Returns False for an ordinary bad/expired code. Raises 429 once the
    attempt budget is spent, so the caller can tell the user to request a new
    one rather than letting them keep grinding.
    """
    attempts = int(await redis.get(_attempt_key(email)) or 0)
    if attempts >= MAX_VERIFY_ATTEMPTS:
        await redis.delete(_otp_key(email))
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "Too many incorrect codes. Request a new one.",
        )

    stored = await redis.get(_otp_key(email))
    if stored is None or not secrets.compare_digest(stored, code):
        # Counter lives as long as the code, so a fresh code resets the budget.
        failures = await redis.incr(_attempt_key(email))
        if failures == 1:
            await redis.expire(_attempt_key(email), OTP_TTL_SECONDS)
        if failures >= MAX_VERIFY_ATTEMPTS:
            await redis.delete(_otp_key(email))
        return False

    await redis.delete(_otp_key(email))
    await redis.delete(_attempt_key(email))
    return True
