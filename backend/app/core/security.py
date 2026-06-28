import logging
import os
import secrets
from datetime import datetime, timedelta
from typing import Any, Callable, Optional, Union

from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import get_db
from app.services.api_tokens import find_api_token, parse_scopes, record_api_token_use

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

# Check if running in production mode and warn
if os.getenv("ENVIRONMENT", "development").lower() == "production":
    logger.error(
        "CRITICAL: Running in PRODUCTION mode with in-memory API key storage! "
        "This is NOT recommended for production. "
        "Implement database-backed or Redis-based key storage for production deployments."
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
    logger.info("API key added (length: %d chars)", len(api_key))
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


async def get_api_key(api_key_value: Optional[str] = Security(api_key_header)) -> str:
    """
    Dependency to verify API key authentication.

    Args:
        api_key_header: API key from X-API-Key header

    Returns:
        The validated API key

    Raises:
        HTTPException: If API key is missing or invalid
    """
    if not api_key_value:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    if not verify_api_key(api_key_value):
        suffix = api_key_value[-8:] if len(api_key_value) >= 8 else "invalid"
        logger.warning("Invalid API key attempt: ...%s", suffix)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    return api_key_value


async def verify_token(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(security_bearer),
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
        logger.warning("Invalid JWT token: %s", str(e))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from e


async def require_admin_auth(
    request: Request,
    api_key: Optional[str] = Security(api_key_header),
    bearer: Optional[HTTPAuthorizationCredentials] = Security(security_bearer),
) -> dict:
    """
    Dependency to require authentication for admin/API endpoints.

    Accepts (in priority order):
    1. ``AUTH_DISABLED=true`` env var – passes through with a synthetic context.
    2. ``dmarq_session`` cookie – set after a successful Logto login.
    3. ``X-API-Key`` header    – static admin key for programmatic access.
    4. ``Authorization: Bearer <token>`` header – app-issued JWT.

    Returns an authentication context dict describing how the request was
    authenticated.  Raises ``HTTP 401`` when no valid credential is present.
    """
    # 0. Auth globally disabled
    if settings.AUTH_DISABLED:
        return {"auth_type": "disabled"}

    # 1. Session cookie (Logto-backed app session)
    from app.core.logto import SESSION_COOKIE, decode_session_token  # local import

    session_token = request.cookies.get(SESSION_COOKIE)
    if session_token:
        user_id = decode_session_token(session_token)
        if user_id is not None:
            return {"auth_type": "session", "user_id": user_id}

    # 2. Static admin API key
    if api_key and verify_api_key(api_key):
        return {"auth_type": "api_key"}

    # 3. Bearer JWT (app-issued; also covers Bearer tokens set by older clients)
    if bearer:
        from app.core.logto import decode_session_token as _dec  # local import

        user_id = _dec(bearer.credentials)
        if user_id is not None:
            return {"auth_type": "bearer", "user_id": user_id}

        # Fallback: legacy python-jose JWT (pre-Logto API keys / CI tokens)
        try:
            payload = jwt.decode(
                bearer.credentials, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
            )
            return {"auth_type": "jwt", "payload": payload}
        except JWTError as e:
            logger.warning("Invalid Bearer JWT: %s", str(e))

    # No valid authentication
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required. Provide a session cookie, X-API-Key header, or Bearer token.",
        headers={"WWW-Authenticate": "ApiKey, Bearer"},
    )


def require_api_token_scope(required_scope: str) -> Callable:
    """Build a dependency that requires a scoped persistent API token."""

    async def _require_api_token_scope(
        request: Request,
        db: Session = Depends(get_db),
        api_key: Optional[str] = Security(api_key_header),
    ) -> dict:
        if not api_key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing API token",
                headers={"WWW-Authenticate": "ApiKey"},
            )

        token = find_api_token(db, api_key)
        if token is None:
            logger.warning("Invalid public API token attempt")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API token",
                headers={"WWW-Authenticate": "ApiKey"},
            )

        scopes = parse_scopes(token.scopes)
        if required_scope not in scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"API token requires scope: {required_scope}",
            )

        client_host = request.client.host if request.client else None
        record_api_token_use(db, token, ip_address=client_host)
        return {
            "auth_type": "api_token",
            "token_id": token.id,
            "workspace_id": token.workspace_id,
            "token_name": token.name,
            "scopes": sorted(scopes),
        }

    return _require_api_token_scope


def _api_token_context_for_scope(
    db: Session,
    *,
    request: Request,
    api_key: Optional[str],
    required_scope: str,
    auth_type: str,
) -> Optional[dict]:
    """Return a scoped persistent API-token auth context when the key matches."""
    if not api_key:
        return None

    token = find_api_token(db, api_key)
    if token is None:
        return None

    scopes = parse_scopes(token.scopes)
    if required_scope not in scopes:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"API token requires scope: {required_scope}",
        )

    client_host = request.client.host if request.client else None
    record_api_token_use(db, token, ip_address=client_host)
    return {
        "auth_type": auth_type,
        "token_id": token.id,
        "workspace_id": token.workspace_id,
        "token_name": token.name,
        "scopes": sorted(scopes),
    }


def require_provider_auth(required_scope: str) -> Callable:
    """Build a dependency accepting provider API tokens or administrator auth."""

    async def _require_provider_auth(
        request: Request,
        db: Session = Depends(get_db),
        api_key: Optional[str] = Security(api_key_header),
        bearer: Optional[HTTPAuthorizationCredentials] = Security(security_bearer),
    ) -> dict:
        token_context = _api_token_context_for_scope(
            db,
            request=request,
            api_key=api_key,
            required_scope=required_scope,
            auth_type="provider_api_token",
        )
        if token_context is not None:
            return token_context
        return await require_admin_auth(request, api_key=api_key, bearer=bearer)

    return _require_provider_auth


def create_access_token(subject: Union[str, Any], expires_delta: timedelta = None) -> str:
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
