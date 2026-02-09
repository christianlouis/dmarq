import logging
import secrets
from functools import lru_cache
from typing import List, Optional, Union

# Try to import from pydantic_settings first (newer versions)
try:
    from pydantic import EmailStr, validator
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
    DATABASE_URL: str = "sqlite:///./dmarq.db"

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

    @validator("SECRET_KEY", pre=True, always=True)
    def validate_secret_key(cls, v: Optional[str]) -> str:
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
                f"SECRET_KEY is too short ({len(v)} characters). "
                "Recommended minimum is 32 characters for security."
            )

        return v

    @validator("BACKEND_CORS_ORIGINS", pre=True)
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",")]
        elif isinstance(v, (list, str)):
            return v
        raise ValueError(v)

    class Config:
        env_file = ".env"
        case_sensitive = True


@lru_cache()
def get_settings() -> Settings:
    """
    Get application settings from environment variables or .env file
    """
    return Settings()
