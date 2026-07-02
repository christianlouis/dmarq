import json
import logging
import secrets
from functools import lru_cache
from typing import List, Optional, Union

# Try to import from pydantic_settings first (newer versions)
try:
    from pydantic import EmailStr, validator  # pylint: disable=ungrouped-imports
    from pydantic_settings import BaseSettings
except ImportError:
    # Fall back to older pydantic version
    from pydantic import BaseSettings, EmailStr, validator

logger = logging.getLogger(__name__)


class Settings(BaseSettings):
    """Application settings"""

    # Base
    PROJECT_NAME: str = "DMARQ"
    API_V1_STR: str = "/api/v1"
    ENVIRONMENT: str = "development"
    DEMO_MODE: bool = False
    PUBLIC_BASE_URL: Optional[str] = None
    # Self-hosted installs default to a single workspace. Enable this for SaaS,
    # ISP/MSP, or admin deployments that need explicit workspace switching.
    MULTI_WORKSPACE_UI_ENABLED: bool = False

    # Database
    # Default to a sub-directory so the SQLite file lives in a location that
    # can be persisted via a Docker volume mount (e.g. /app/data).
    DATABASE_URL: str = "sqlite:///./data/dmarq.db"

    # JWT Authentication
    SECRET_KEY: Optional[str] = None
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60  # 1 hour

    # CORS
    BACKEND_CORS_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:5173"]

    # IMAP Settings
    IMAP_SERVER: Optional[str] = None
    IMAP_PORT: int = 993
    IMAP_USERNAME: Optional[str] = None
    IMAP_PASSWORD: Optional[str] = None
    IMAP_FOLDER: str = "INBOX"
    DELETE_IMPORTED_EMAILS: bool = False

    # Admin User
    FIRST_SUPERUSER: Optional[EmailStr] = None
    FIRST_SUPERUSER_PASSWORD: Optional[str] = None

    # Optional Cloudflare Integration
    CLOUDFLARE_API_TOKEN: Optional[str] = None
    CLOUDFLARE_ZONE_ID: Optional[str] = None
    CLOUDFLARE_OAUTH_CLIENT_ID: Optional[str] = None
    CLOUDFLARE_OAUTH_CLIENT_SECRET: Optional[str] = None
    CLOUDFLARE_OAUTH_SCOPES: str = "zone.read dns.read"
    HETZNER_DNS_API_TOKEN: Optional[str] = None
    HETZNER_API_TOKEN: Optional[str] = None
    LINODE_API_TOKEN: Optional[str] = None
    LINODE_TOKEN: Optional[str] = None
    AWS_PROFILE: Optional[str] = None
    AWS_REGION: Optional[str] = None
    DMARQ_ROUTE53_PROFILE: Optional[str] = None
    DMARQ_ROUTE53_ROLE_ARN: Optional[str] = None
    DMARQ_ROUTE53_EXTERNAL_ID: Optional[str] = None
    POSTMARK_ACCOUNT_TOKEN: Optional[str] = None
    WEBHOOK_SECRET: Optional[str] = None

    # Optional sender reputation feed lookups. Disabled by default because many
    # reputation providers require explicit terms, credentials, and volume limits.
    SOURCE_REPUTATION_FEEDS_ENABLED: bool = False
    SOURCE_REPUTATION_FEEDS: Optional[str] = None
    SOURCE_REPUTATION_SPAMHAUS_DQS_ZONE: Optional[str] = None
    SOURCE_REPUTATION_FEED_TIMEOUT_SECONDS: float = 2.0
    SOURCE_REPUTATION_FEED_CACHE_SECONDS: int = 86_400
    SOURCE_REPUTATION_FEED_MAX_IPS: int = 100

    # Optional Stripe Billing integration. Self-hosted and provider-billed
    # deployments work without these values.
    STRIPE_SECRET_KEY: Optional[str] = None
    STRIPE_WEBHOOK_SECRET: Optional[str] = None
    STRIPE_PRICE_PLAN_MAP: Optional[str] = None
    STRIPE_API_BASE_URL: str = "https://api.stripe.com/v1"

    # Admin API Key (optional)
    # If set, this key is used directly instead of generating a random one at startup.
    # Use: openssl rand -hex 32
    ADMIN_API_KEY: Optional[str] = None

    # ── Authentication mode ───────────────────────────────────────────────────
    # Set AUTH_DISABLED=true to run without any authentication.
    # Every request is treated as an anonymous admin.
    #
    # ⚠️  Only use this for local development or deployments that are protected
    #     by an external auth proxy (e.g. Authelia, OAuth2 Proxy, Traefik Forward Auth).
    #     Never expose an AUTH_DISABLED instance directly to the internet.
    AUTH_DISABLED: bool = False
    ALLOW_AUTH_DISABLED_IN_PRODUCTION: bool = False
    # Optional explicit auth mode.  Keep unset/"auto" for backwards-compatible
    # Logto auto-detection.  Supported values: auto, disabled, logto, oidc,
    # authentik, trusted_proxy.
    AUTH_MODE: str = "auto"

    # ── Generic OIDC / Authentik OIDC ────────────────────────────────────────
    # DMARQ can authenticate directly against any standards-based OIDC provider.
    # For Authentik, set AUTH_MODE=authentik and the AUTHENTIK_* values below.
    OIDC_ISSUER_URL: Optional[str] = None
    OIDC_CLIENT_ID: Optional[str] = None
    OIDC_CLIENT_SECRET: Optional[str] = None
    OIDC_REDIRECT_URI: Optional[str] = None
    OIDC_SCOPES: str = "openid email profile"
    OIDC_PROVIDER_LABEL: str = "OpenID Connect"
    OIDC_SKIP_SSL_VERIFY: bool = False
    ALLOW_OIDC_SKIP_SSL_VERIFY_IN_PRODUCTION: bool = False
    OIDC_ALLOWED_EMAILS: Optional[str] = None
    OIDC_ALLOWED_DOMAINS: Optional[str] = None

    AUTHENTIK_ISSUER_URL: Optional[str] = None
    AUTHENTIK_CLIENT_ID: Optional[str] = None
    AUTHENTIK_CLIENT_SECRET: Optional[str] = None
    AUTHENTIK_REDIRECT_URI: Optional[str] = None
    AUTHENTIK_SCOPES: str = "openid email profile"
    AUTHENTIK_ALLOWED_EMAILS: Optional[str] = None
    AUTHENTIK_ALLOWED_DOMAINS: Optional[str] = None

    # ── Trusted proxy / Authentik Outpost mode ───────────────────────────────
    # Use only when DMARQ is reachable exclusively through the trusted proxy.
    AUTH_TRUSTED_PROXY_ENABLED: bool = False
    AUTH_TRUSTED_PROXY_PROVIDER: str = "authentik"
    AUTH_TRUSTED_PROXY_EMAIL_HEADER: str = "X-Authentik-Email"
    AUTH_TRUSTED_PROXY_NAME_HEADER: str = "X-Authentik-Name"
    AUTH_TRUSTED_PROXY_USERNAME_HEADER: str = "X-Authentik-Username"
    AUTH_TRUSTED_PROXY_SUBJECT_HEADER: str = "X-Authentik-Uid"
    AUTH_TRUSTED_PROXY_GROUPS_HEADER: str = "X-Authentik-Groups"
    AUTH_TRUSTED_PROXY_ALLOWED_EMAILS: Optional[str] = None
    AUTH_TRUSTED_PROXY_ALLOWED_DOMAINS: Optional[str] = None

    # ── Logto OIDC ────────────────────────────────────────────────────────────
    # Set these to enable Logto-based authentication.
    # LOGTO_ENDPOINT:    the base URL of your Logto instance,
    #                    e.g. "https://your-tenant.logto.app" or a self-hosted URL.
    # LOGTO_APP_ID:      the Client ID of the "Traditional Web" application in Logto.
    # LOGTO_APP_SECRET:  the Client Secret of the same application.
    # LOGTO_REDIRECT_URI (optional): override the default callback URL.
    #                    Defaults to <base_url>/api/v1/auth/callback.
    # LOGTO_SKIP_SSL_VERIFY (optional): set to true only when connecting to a
    #                    self-hosted Logto endpoint with a self-signed certificate.
    #                    Defaults to false so TLS certificates are verified.
    LOGTO_ENDPOINT: Optional[str] = None
    LOGTO_APP_ID: Optional[str] = None
    LOGTO_APP_SECRET: Optional[str] = None
    LOGTO_REDIRECT_URI: Optional[str] = None
    LOGTO_SKIP_SSL_VERIFY: bool = False
    ALLOW_LOGTO_SKIP_SSL_VERIFY_IN_PRODUCTION: bool = False

    @property
    def logto_configured(self) -> bool:
        """Return True when the minimum Logto settings are present."""
        return bool(self.LOGTO_ENDPOINT and self.LOGTO_APP_ID and self.LOGTO_APP_SECRET)

    @property
    def generic_oidc_configured(self) -> bool:
        """Return True when the generic OIDC settings are present."""
        return bool(self.OIDC_ISSUER_URL and self.OIDC_CLIENT_ID and self.OIDC_CLIENT_SECRET)

    @property
    def authentik_configured(self) -> bool:
        """Return True when Authentik direct OIDC settings are present."""
        return bool(
            self.AUTHENTIK_ISSUER_URL and self.AUTHENTIK_CLIENT_ID and self.AUTHENTIK_CLIENT_SECRET
        )

    @property
    def trusted_proxy_configured(self) -> bool:
        """Return True when trusted proxy authentication is explicitly enabled."""
        return self.AUTH_TRUSTED_PROXY_ENABLED or self.AUTH_MODE.strip().lower() in {
            "trusted_proxy",
            "authentik_proxy",
            "proxy",
        }

    @property
    def active_auth_provider(self) -> str:
        """Return the configured browser authentication provider."""
        mode = (self.AUTH_MODE or "auto").strip().lower()
        if self.AUTH_DISABLED or mode in {"disabled", "none", "off", "no_auth"}:
            return "disabled"
        if mode in {"trusted_proxy", "authentik_proxy", "proxy"}:
            return "trusted_proxy"
        if mode == "logto":
            return "logto"
        if mode in {"authentik", "authentik_oidc"}:
            return "authentik"
        if mode in {"oidc", "generic_oidc", "multi_user_oidc", "single_external_user"}:
            return "oidc"
        if self.trusted_proxy_configured:
            return "trusted_proxy"
        if self.logto_configured:
            return "logto"
        if self.authentik_configured:
            return "authentik"
        if self.generic_oidc_configured:
            return "oidc"
        return "unconfigured"

    @property
    def auth_configured(self) -> bool:
        """Return True when browser authentication has a usable path."""
        return self.active_auth_provider in {
            "disabled",
            "logto",
            "authentik",
            "oidc",
            "trusted_proxy",
        }

    @property
    def auth_provider_label(self) -> str:
        """Return a short UI label for the active auth provider."""
        provider = self.active_auth_provider
        if provider == "disabled":
            return "No authentication"
        if provider == "logto":
            return "Logto"
        if provider == "authentik":
            return "Authentik"
        if provider == "trusted_proxy":
            proxy = (self.AUTH_TRUSTED_PROXY_PROVIDER or "trusted proxy").strip()
            return "Authentik Outpost" if proxy.lower() == "authentik" else proxy
        if provider == "oidc":
            return self.OIDC_PROVIDER_LABEL or "OpenID Connect"
        return "Not configured"

    @property
    def is_production(self) -> bool:
        """Return True when the app is explicitly running in production mode."""
        return self.ENVIRONMENT.strip().lower() in {"prod", "production"}

    @validator("ADMIN_API_KEY", pre=True, always=True)
    @classmethod
    def validate_admin_api_key(
        cls, v: Optional[str]
    ) -> Optional[str]:  # pylint: disable=no-self-argument
        """Warn if ADMIN_API_KEY is set but too short."""
        if v is not None and len(v) < 32:
            logger.warning(
                "ADMIN_API_KEY is too short (%s characters). "
                "Recommended minimum is 32 characters for security. "
                "Generate a strong key with: openssl rand -hex 32",
                len(v),
            )
        return v or None

    @validator("SECRET_KEY", pre=True, always=True)
    def validate_secret_key(  # pylint: disable=no-self-argument
        cls, v: Optional[str], values
    ) -> str:
        """Validate and generate SECRET_KEY if not provided."""
        # Default insecure key that should never be used
        DEFAULT_INSECURE_KEY = "CHANGE_THIS_TO_A_RANDOM_SECRET_IN_PRODUCTION"
        environment = str(values.get("ENVIRONMENT", "development")).strip().lower()
        is_production = environment in {"prod", "production"}

        if v is None or v == "" or v == DEFAULT_INSECURE_KEY:
            if is_production:
                raise ValueError(
                    "SECRET_KEY must be set to a stable random value when ENVIRONMENT=production."
                )
            # Generate a secure random key
            generated_key = secrets.token_hex(32)
            logger.warning(
                "SECRET_KEY not configured or using default value! "
                "Generated a random key for this session. "
                "For production, set SECRET_KEY in your .env file using: "
                "openssl rand -hex 32"
            )
            return generated_key

        # Check if key is too short
        if len(v) < 32:
            if is_production:
                raise ValueError(
                    "SECRET_KEY must be at least 32 characters when ENVIRONMENT=production."
                )
            logger.warning(
                "SECRET_KEY is too short (%s characters). "
                "Recommended minimum is 32 characters for security.",
                len(v),
            )

        return v

    @validator("BACKEND_CORS_ORIGINS", pre=True)
    def assemble_cors_origins(  # pylint: disable=no-self-argument
        cls, v: Union[str, List[str]]
    ) -> List[str]:
        if isinstance(v, str):
            v = v.strip()
            if not v:
                return []
            if v.startswith("["):
                return json.loads(v)
            return [i.strip() for i in v.split(",") if i.strip()]
        if isinstance(v, list):
            return v
        raise ValueError(v)

    class Config:
        env_file = ".env"
        case_sensitive = True
        env_ignore_empty = True


@lru_cache()
def get_settings() -> Settings:
    """
    Get application settings from environment variables or .env file
    """
    return Settings()
