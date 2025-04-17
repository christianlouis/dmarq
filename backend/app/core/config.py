from functools import lru_cache
from typing import Optional, List, Union

# Try to import from pydantic_settings first (newer versions)
try:
    from pydantic_settings import BaseSettings
    from pydantic import EmailStr, validator
except ImportError:
    # Fall back to older pydantic version
    from pydantic import BaseSettings, EmailStr, validator


class Settings(BaseSettings):
    """Application settings"""
    
    # Base
    PROJECT_NAME: str = "DMARQ"
    API_V1_STR: str = "/api/v1"
    
    # Database
    DATABASE_URL: str = "sqlite:///./dmarq.db"
    
    # JWT Authentication
    SECRET_KEY: str = "CHANGE_THIS_TO_A_RANDOM_SECRET_IN_PRODUCTION"
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