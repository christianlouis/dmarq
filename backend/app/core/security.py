from datetime import datetime, timedelta
from typing import Any, Union, Optional
import secrets
import logging

from fastapi import HTTPException, Security, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, APIKeyHeader
from jose import jwt, JWTError
from passlib.context import CryptContext

from app.core.config import get_settings

settings = get_settings()
logger = logging.getLogger(__name__)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Security schemes for authentication
security_bearer = HTTPBearer(auto_error=False)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

# In-memory API keys storage
# ⚠️ WARNING: This is a simple in-memory implementation suitable for:
# - Development and testing environments
# - Single-instance deployments
# - MVP/prototype applications
# 
# ⚠️ NOT SUITABLE FOR PRODUCTION when:
# - Running multiple application instances (keys not shared)
# - Requiring key persistence across restarts
# - Needing key rotation and management
#
# For production, implement:
# - Database-backed key storage (with encryption at rest)
# - Redis or similar distributed cache for shared key storage
# - Integration with external secret management (AWS Secrets Manager, HashiCorp Vault, etc.)
# - Proper key rotation policies
_api_keys = set()

logger.warning(
    "Using in-memory API key storage. "
    "Keys will be lost on restart. "
    "Not suitable for production multi-instance deployments."
)


def generate_api_key() -> str:
    """
    Generate a secure random API key.
    
    Returns:
        A 32-character hexadecimal API key
    """
    return secrets.token_hex(32)


def add_api_key(api_key: str) -> bool:
    """
    Add an API key to the valid keys set.
    
    Args:
        api_key: The API key to add
        
    Returns:
        True if key was added, False if it already existed
    """
    if api_key in _api_keys:
        return False
    _api_keys.add(api_key)
    logger.info(f"API key added (ends with: ...{api_key[-8:]})")
    return True


def verify_api_key(api_key: str) -> bool:
    """
    Verify an API key is valid.
    
    Args:
        api_key: The API key to verify
        
    Returns:
        True if key is valid, False otherwise
    """
    return api_key in _api_keys


async def get_api_key(
    api_key_header: Optional[str] = Security(api_key_header)
) -> str:
    """
    Dependency to verify API key authentication.
    
    Args:
        api_key_header: API key from X-API-Key header
        
    Returns:
        The validated API key
        
    Raises:
        HTTPException: If API key is missing or invalid
    """
    if not api_key_header:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    
    if not verify_api_key(api_key_header):
        logger.warning(f"Invalid API key attempt: ...{api_key_header[-8:] if len(api_key_header) >= 8 else 'invalid'}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    
    return api_key_header


async def verify_token(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(security_bearer)
) -> dict:
    """
    Dependency to verify JWT token authentication.
    
    Args:
        credentials: Bearer token from Authorization header
        
    Returns:
        Decoded token payload
        
    Raises:
        HTTPException: If token is missing or invalid
    """
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    token = credentials.credentials
    
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        return payload
    except JWTError as e:
        logger.warning(f"Invalid JWT token: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def require_admin_auth(
    api_key: Optional[str] = Security(api_key_header),
    bearer: Optional[HTTPAuthorizationCredentials] = Security(security_bearer)
) -> dict:
    """
    Dependency to require either API key or JWT token authentication for admin endpoints.
    
    Checks API key first, then falls back to JWT token.
    
    Args:
        api_key: Optional API key from X-API-Key header
        bearer: Optional JWT token from Authorization header
        
    Returns:
        Authentication context (api_key or token payload)
        
    Raises:
        HTTPException: If no valid authentication is provided
    """
    # Try API key first
    if api_key and verify_api_key(api_key):
        return {"auth_type": "api_key", "api_key": api_key}
    
    # Try JWT token
    if bearer:
        try:
            payload = jwt.decode(
                bearer.credentials, 
                settings.SECRET_KEY, 
                algorithms=[settings.ALGORITHM]
            )
            return {"auth_type": "jwt", "payload": payload}
        except JWTError as e:
            logger.warning(f"Invalid JWT token: {str(e)}")
    
    # No valid authentication provided
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required. Provide either X-API-Key header or Bearer token.",
        headers={"WWW-Authenticate": "ApiKey, Bearer"},
    )


def create_access_token(
    subject: Union[str, Any], expires_delta: timedelta = None
) -> str:
    """
    Create a JWT access token for authentication
    """
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode = {"exp": expire, "sub": str(subject)}
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a password against its hash
    """
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """
    Hash a password
    """
    return pwd_context.hash(password)