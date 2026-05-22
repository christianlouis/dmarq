import base64
import hashlib
from functools import lru_cache
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken

from app.core.config import get_settings

ENCRYPTED_SECRET_PREFIX = "enc:v1:"


@lru_cache(maxsize=1)
def _get_fernet() -> Fernet:
    """Build a Fernet instance from the stable application secret key."""
    secret_key = get_settings().SECRET_KEY
    digest = hashlib.sha256(secret_key.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def is_encrypted_secret(value: Optional[str]) -> bool:
    return bool(value and value.startswith(ENCRYPTED_SECRET_PREFIX))


def encrypt_secret(value: Optional[str]) -> Optional[str]:
    """Encrypt a secret for database storage, preserving empty and encrypted values."""
    if value is None or value == "":
        return value
    if is_encrypted_secret(value):
        return value

    token = _get_fernet().encrypt(value.encode("utf-8")).decode("ascii")
    return f"{ENCRYPTED_SECRET_PREFIX}{token}"


def decrypt_secret(value: Optional[str]) -> Optional[str]:
    """Return plaintext for encrypted values and legacy plaintext unchanged."""
    if value is None or value == "":
        return value
    if not is_encrypted_secret(value):
        return value

    token = value[len(ENCRYPTED_SECRET_PREFIX) :]
    try:
        return _get_fernet().decrypt(token.encode("ascii")).decode("utf-8")
    except InvalidToken as exc:
        raise ValueError(
            "Stored credential could not be decrypted with the configured SECRET_KEY"
        ) from exc
