from decimal import Decimal
from functools import lru_cache

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str
    redis_url: str

    resend_api_key: str = ""
    resend_from_email: str = "Hungry Birds <onboarding@resend.dev>"
    resend_api_key_two: str=""
    resend_from_email_two: str = "Hungry Birds <onboarding@resend.dev>"

    jwt_secret: str
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60
    refresh_token_expire_days: int = 30
    # Riders have no refresh flow: they sign in at the start of a shift and must
    # not be logged out mid-delivery. Regenerating their password is what revokes
    # a token early, so a long life here is not an un-endable session.
    rider_token_expire_days: int = 14

    # "development" unlocks local conveniences (permissive CORS, the OTP debug
    # echo). Anything else - including the default - is treated as production,
    # so a deployment is safe unless someone deliberately declares otherwise.
    environment: str = "production"

    allowed_email_domain: str = "bitmesra.ac.in"

    # Makes this address an admin at startup, creating the account if it does not
    # exist yet. It breaks a deadlock that otherwise makes a fresh deployment
    # impossible to administer: promote_admin.py needs a user who has already
    # logged in, logging in needs an OTP email, and configuring email is itself
    # an admin task. Someone has to be let in first.
    #
    # Only the role is granted - no password, no session. It is idempotent, so
    # leaving it set is harmless, and it grants nothing to anybody who cannot
    # already set environment variables on this deployment (who could grant
    # themselves admin regardless).
    bootstrap_admin_email: str = ""

    # Lets an admin sign in with a password instead of waiting on an OTP email,
    # which matters because the admin is the account you need when email itself
    # is the thing that is broken. Empty disables the endpoint entirely, so the
    # extra way in does not exist unless it is deliberately configured.
    # Generate with: python scripts/set_admin_password.py
    admin_password_hash: str = ""

    # Returns login codes in API responses. That is a complete authentication
    # bypass, so it is honoured only in development; see debug_echo_enabled.
    otp_debug_echo: bool = False

    # How many reverse proxies sit in front of this app. Railway is exactly one.
    # Used to find the real client address for rate limiting without trusting
    # the part of X-Forwarded-For that a caller can forge - see client_ip().
    # 0 means nothing is in front and the header is ignored entirely.
    trusted_proxy_count: int = 1

    # Bodies larger than this are refused before they are parsed, so a single
    # request cannot chew through memory.
    max_request_bytes: int = 256 * 1024

    # A blanket per-IP ceiling across the whole API, on top of the per-endpoint
    # limits. Generous enough that ordinary browsing never notices it.
    global_rate_limit_requests: int = 300
    global_rate_limit_seconds: int = 60

    cloudinary_cloud_name: str = ""
    cloudinary_api_key: str = ""
    cloudinary_api_secret: str = ""
    cloudinary_upload_folder: str = "hungry_birds"

    # --- Firebase Cloud Messaging -------------------------------------------
    # Empty means "not configured", and the notification service then does
    # nothing rather than raising - the same convention as resend_api_key and
    # cloudinary_api_secret. A stall that gets no push still sees the order the
    # moment it opens the app, so this failing quietly is the right default.
    #
    # firebase_service_account_json is the whole service-account JSON file, as
    # one string. It is a credential: keep it in Railway's variables, never in
    # the repo.
    fcm_project_id: str = ""
    firebase_service_account_json: str = ""

    # --- Payments ------------------------------------------------------------
    # "razorpay" takes real money. "mock" confirms every payment instantly
    # without contacting anybody, so the rest of the system - the stall's queue,
    # the push, assignment, the handover code - can be exercised before the
    # gateway credentials exist.
    #
    # There is no safe default but the real one, so this is not inferred from
    # anything. Mock mode is on only when somebody has typed it into an
    # environment variable, and the app logs a warning on every boot while it is.
    payments_mode: str = "razorpay"

    # --- Razorpay (payments) -------------------------------------------------
    # Was Cashfree until the gateway swap; see the Payments section of README.md
    # for why.
    #
    # Three values, not two, and the third is the one that is easy to get wrong.
    # Razorpay signs webhooks with a secret you choose when registering the
    # webhook in their dashboard, which is *not* the API key secret. Cashfree
    # used one value for both, and collapsing them here would mean either
    # checking forged webhooks against the API credential or refusing to boot
    # without a webhook that may not be registered yet.
    #
    # key_id is handed to the browser with the payment session - it is Razorpay's
    # publishable half and is meant to be public. The other two never leave this
    # process.
    razorpay_key_id: str = ""
    razorpay_key_secret: str = ""
    razorpay_webhook_secret: str = ""
    # No environment setting, deliberately: Razorpay serves test and live from
    # one host and the key prefix (rzp_test_ / rzp_live_) decides which account
    # the call lands in. There is nothing to keep in sync, so there is nothing to
    # drift.

    # How long a customer has to finish paying. Must stay comfortably below the
    # local sweep window, so we never give up on an order the gateway would still
    # accept money for.
    payment_window_minutes: int = 15

    # --- Pay on delivery -----------------------------------------------------
    # Riders collecting at the door, cash or UPI. On because it was asked for,
    # but kept as one variable so it can be switched off in seconds if cash goes
    # wrong on a launch day - a stall cooking food that is never paid for is the
    # exposure this carries, and that is worth a kill switch.
    #
    # Delivery orders only. Dine-in is paid up front, because the student is
    # standing at the counter and there is no rider to collect from them.
    cod_enabled: bool = True

    # --- Cashback ------------------------------------------------------------
    # A launch promotion, and the first thing in this project that *creates*
    # money rather than moving money a customer already owes. Every number is a
    # setting so a rate change is a Railway variable rather than a deploy.
    #
    # Earned on completion, spendable only at the kind of kitchen it came from.
    # See the Cashback section of README.md for the whole scheme.
    cashback_normal_percent: int = 20
    cashback_normal_cap: Decimal = Decimal("40")
    cashback_gourmet_percent: int = 60
    cashback_gourmet_cap: Decimal = Decimal("90")

    # Which stall is the special one, matched on its name because that is how
    # the user identifies it. Empty - the default - means no stall is Gourmet, so
    # the 60% tier is off until somebody names it. That is the safe direction:
    # the expensive rate cannot be handed out by accident.
    gourmet_kitchen_name: str = ""

    # How long a credit lasts. Read at the moment of earning and frozen onto the
    # row, never consulted again - so changing this cannot retroactively kill or
    # revive a balance a student was already promised a date for.
    cashback_expiry_days: int = 30

    # When the flat rate is meant to become a probability distribution.
    #
    # **Currently inert, deliberately.** The distribution has not been specified
    # yet and the user asked to keep flat 20/60 until it is, so this is read and
    # threaded through rate_for() without changing what it returns. The risk is
    # worth stating: a date that passes unnoticed means full promotional rates
    # keep being paid. Empty means no end date is set at all.
    cashback_end_date: str = ""

    # Where Razorpay posts webhooks, and the base for any link we send out.
    # Must be the public URL of this deployment.
    public_base_url: str = ""

    # Empty means send no CORS headers at all, which is correct in production:
    # the backend serves the web app itself, so every call is same-origin and
    # no other site has any business calling this API. Set it to a
    # comma-separated origin list only if a separate frontend host is added.
    cors_origins: str = ""

    @field_validator("otp_debug_echo", mode="before")
    @classmethod
    def blank_means_off(cls, value):
        """Treat an empty environment variable as false rather than refusing to boot.

        Clearing a variable in a hosting dashboard usually means emptying it, not
        deleting the row, and pydantic rejects "" for a bool - so the obvious way to
        turn one of these off takes the whole service down on the next deploy
        instead. That happened with SEED_DEMO_DATA, which this validator was
        written for: the app would not start, and the error named a demo-data flag
        rather than anything to do with the deploy that failed. That setting is
        gone now, but the lesson is the reason this is still here.

        Deliberately not applied to cod_enabled, whose default is true: "blank"
        there could mean either "I unset it" or "I turned it off", and guessing
        wrong either silently loses cash orders or silently allows them.

        Only applied to the flag, not to the string settings. For those, empty
        already means off and is handled where they are read.
        """
        if isinstance(value, str) and not value.strip():
            return False
        return value

    @field_validator("jwt_secret")
    @classmethod
    def secret_long_enough(cls, value: str) -> str:
        """Refuse to start on an HMAC key shorter than its own hash.

        HS256 keys shorter than 32 bytes weaken the signature below the strength
        of SHA-256 itself (RFC 7518 section 3.2), and nothing about a short one
        looks wrong at runtime: tokens sign, verify and work. PyJWT only started
        warning about it in 2.15, and a warning in a log nobody reads is not a
        control. The access token is the whole authentication system, so this
        fails at boot instead.
        """
        if len(value.encode()) < 32:
            raise ValueError(
                "JWT_SECRET must be at least 32 bytes - generate one with "
                "`python -c 'import secrets; print(secrets.token_urlsafe(48))'`"
            )
        return value

    @field_validator("database_url")
    @classmethod
    def use_async_driver(cls, value: str) -> str:
        """Railway (and most hosts) inject a plain postgres:// URL, but the
        async engine needs the asyncpg driver spelled out."""
        for prefix in ("postgresql+asyncpg://", "postgresql+psycopg://"):
            if value.startswith(prefix):
                return value
        if value.startswith("postgres://"):
            return value.replace("postgres://", "postgresql+asyncpg://", 1)
        if value.startswith("postgresql://"):
            return value.replace("postgresql://", "postgresql+asyncpg://", 1)
        return value

    @field_validator("payments_mode")
    @classmethod
    def known_payments_mode(cls, value: str) -> str:
        """A typo here must not fall back to taking real money, nor to giving food
        away. Refusing to boot is the only outcome that is wrong in neither
        direction."""
        mode = value.strip().lower()
        if mode not in ("razorpay", "mock"):
            raise ValueError('PAYMENTS_MODE must be "razorpay" or "mock"')
        return mode

    @property
    def payments_mock(self) -> bool:
        """Every payment confirms instantly and no money moves."""
        return self.payments_mode == "mock"

    @property
    def razorpay_configured(self) -> bool:
        """Whether we hold credentials to ask Razorpay for money."""
        return bool(self.razorpay_key_id and self.razorpay_key_secret)

    @property
    def razorpay_webhook_configured(self) -> bool:
        """Whether we can verify that a webhook really came from Razorpay.

        The webhook route is gated on *this*, separately from the two above, and
        the distinction is load-bearing. The signing secret is the only thing
        standing between an open POST endpoint and anyone on the internet marking
        any order paid. A route that accepted webhooks without it would check
        every forgery against an empty HMAC key.

        It is also why this is its own setting rather than a property of being
        configured: credentials can be in place days before somebody registers
        the webhook in the dashboard, and during that window the honest answer is
        that we cannot verify anybody.
        """
        return bool(self.razorpay_webhook_secret)

    @property
    def payments_enabled(self) -> bool:
        """Whether an order can be paid for at all, by any means."""
        return self.payments_mock or self.razorpay_configured

    @property
    def push_enabled(self) -> bool:
        return bool(self.fcm_project_id and self.firebase_service_account_json)

    @property
    def is_development(self) -> bool:
        return self.environment.strip().lower() in {"development", "dev", "local"}

    @property
    def debug_echo_enabled(self) -> bool:
        """OTP codes echoed in responses - development only.

        Deliberately gated on two settings rather than one. OTP_DEBUG_ECHO is
        the kind of variable that gets copied into a production environment by
        accident, and on its own it would hand anyone a login as anyone,
        including the admin. Requiring ENVIRONMENT=development as well means
        that mistake is inert.
        """
        return self.otp_debug_echo and self.is_development

    @property
    def cors_origin_list(self) -> list[str]:
        if self.cors_origins.strip() == "*":
            return ["*"]
        origins = [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]
        if not origins and self.is_development:
            # The web app runs on Vite's port in development while the API is
            # on this one, so local work does need cross-origin access.
            return [
                "http://localhost:5173",
                "http://127.0.0.1:5173",
                "http://localhost:4173",
                "http://127.0.0.1:4173",
            ]
        return origins


@lru_cache
def get_settings() -> Settings:
    return Settings()
