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

    # Admin User
    FIRST_SUPERUSER: Optional[EmailStr] = None
    FIRST_SUPERUSER_PASSWORD: Optional[str] = None

    # Optional Cloudflare Integration
    CLOUDFLARE_API_TOKEN: Optional[str] = None
    CLOUDFLARE_ZONE_ID: Optional[str] = None

    # Admin API Key (optional)
    # If set, this key is used directly instead of generating a random one at startup.
    # Use: openssl rand -hex 32
    ADMIN_API_KEY: Optional[str] = None

    # ── Logto OIDC ────────────────────────────────────────────────────────────
    # Set these to enable Logto-based authentication.
    # LOGTO_ENDPOINT:    the base URL of your Logto instance,
    #                    e.g. "https://your-tenant.logto.app" or a self-hosted URL.
    # LOGTO_APP_ID:      the Client ID of the "Traditional Web" application in Logto.
    # LOGTO_APP_SECRET:  the Client Secret of the same application.
    # LOGTO_REDIRECT_URI (optional): override the default callback URL.
    #                    Defaults to <base_url>/api/v1/auth/callback.
    LOGTO_ENDPOINT: Optional[str] = None
    LOGTO_APP_ID: Optional[str] = None
    LOGTO_APP_SECRET: Optional[str] = None
    LOGTO_REDIRECT_URI: Optional[str] = None

    @property
    def logto_configured(self) -> bool:
        """Return True when the minimum Logto settings are present."""
        return bool(self.LOGTO_ENDPOINT and self.LOGTO_APP_ID and self.LOGTO_APP_SECRET)

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
    def validate_secret_key(cls, v: Optional[str]) -> str:  # pylint: disable=no-self-argument
        """Validate and generate SECRET_KEY if not provided."""
        # Default insecure key that should never be used
        DEFAULT_INSECURE_KEY = "CHANGE_THIS_TO_A_RANDOM_SECRET_IN_PRODUCTION"

        if v is None or v == "" or v == DEFAULT_INSECURE_KEY:
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
