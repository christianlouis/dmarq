"""Persistent scoped API token helpers."""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, List, Optional, Set

import bcrypt
from sqlalchemy.orm import Session

from app.models.api_token import APIToken

READ_REPORTS_SCOPE = "reports:read"
READ_POSTURE_SCOPE = "posture:read"
READ_TLS_SCOPE = "tls-reports:read"

PUBLIC_READ_SCOPES = {
    READ_REPORTS_SCOPE,
    READ_POSTURE_SCOPE,
    READ_TLS_SCOPE,
}


@dataclass
class CreatedAPIToken:
    """Return value for newly created API tokens."""

    token: APIToken
    secret: str


def normalize_scopes(scopes: Iterable[str]) -> List[str]:
    """Normalize and validate requested API token scopes."""
    normalized = sorted({scope.strip().lower() for scope in scopes if scope and scope.strip()})
    invalid = [scope for scope in normalized if scope not in PUBLIC_READ_SCOPES]
    if invalid:
        raise ValueError(f"Unsupported API token scope: {', '.join(invalid)}")
    if not normalized:
        raise ValueError("At least one API token scope is required")
    return normalized


def scopes_to_string(scopes: Iterable[str]) -> str:
    """Serialize scopes for storage."""
    return ",".join(normalize_scopes(scopes))


def parse_scopes(value: str) -> Set[str]:
    """Parse stored scope text into a set."""
    return {scope.strip().lower() for scope in (value or "").split(",") if scope.strip()}


def generate_public_api_key() -> str:
    """Generate an operator-facing API token secret."""
    return f"dmarq_{secrets.token_urlsafe(32)}"


def hash_api_key(secret: str) -> str:
    """Hash an API token for database storage."""
    return bcrypt.hashpw(secret.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_api_key_secret(secret: str, hashed_secret: str) -> bool:
    """Return True when a raw API token matches the stored hash."""
    try:
        return bcrypt.checkpw(secret.encode("utf-8"), hashed_secret.encode("utf-8"))
    except ValueError:
        return False


def create_api_token(db: Session, *, name: str, scopes: Iterable[str]) -> CreatedAPIToken:
    """Create a persistent API token and return the raw secret once."""
    clean_name = name.strip()
    if not clean_name:
        raise ValueError("Token name is required")
    secret = generate_public_api_key()
    token = APIToken(
        name=clean_name,
        key_hash=hash_api_key(secret),
        key_prefix=secret[:12],
        scopes=scopes_to_string(scopes),
        active=True,
    )
    db.add(token)
    db.commit()
    db.refresh(token)
    return CreatedAPIToken(token=token, secret=secret)


def find_api_token(db: Session, secret: str) -> Optional[APIToken]:
    """Return the active token row matching *secret*, if any."""
    if not secret:
        return None
    candidates = (
        db.query(APIToken)
        .filter(APIToken.key_prefix == secret[:12], APIToken.active == True)  # noqa: E712
        .all()
    )
    for token in candidates:
        if verify_api_key_secret(secret, token.key_hash):
            return token
    return None


def record_api_token_use(db: Session, token: APIToken, *, ip_address: Optional[str]) -> None:
    """Persist minimal audit data for a successful API token use."""
    token.last_used_at = datetime.utcnow()
    token.last_used_ip = ip_address
    token.usage_count = int(token.usage_count or 0) + 1
    db.commit()


def revoke_api_token(db: Session, token_id: int) -> bool:
    """Deactivate an API token by id."""
    token = db.query(APIToken).filter(APIToken.id == token_id).first()
    if token is None or not token.active:
        return False
    token.active = False
    token.revoked_at = datetime.utcnow()
    db.commit()
    return True


def token_to_dict(token: APIToken) -> dict:
    """Return an API-safe token representation without the secret hash."""
    return {
        "id": token.id,
        "name": token.name,
        "key_prefix": token.key_prefix,
        "scopes": sorted(parse_scopes(token.scopes)),
        "active": token.active,
        "created_at": token.created_at.isoformat() if token.created_at else None,
        "last_used_at": token.last_used_at.isoformat() if token.last_used_at else None,
        "last_used_ip": token.last_used_ip,
        "usage_count": token.usage_count,
        "revoked_at": token.revoked_at.isoformat() if token.revoked_at else None,
    }
