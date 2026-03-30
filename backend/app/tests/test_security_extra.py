"""
Additional tests for app.core.security covering JWT, password utilities,
create_access_token, and require_admin_auth branches not yet exercised.
"""

from datetime import timedelta

import pytest
from jose import jwt

from app.core.security import (
    add_api_key,
    create_access_token,
    generate_api_key,
    verify_token,
)

# ---------------------------------------------------------------------------
# create_access_token
# ---------------------------------------------------------------------------


class TestCreateAccessToken:
    def test_returns_decodable_token(self):
        from app.core.config import get_settings

        settings = get_settings()
        token = create_access_token("test-subject")
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        assert payload["sub"] == "test-subject"

    def test_custom_expiry_is_respected(self):
        import time

        from app.core.config import get_settings

        settings = get_settings()
        delta = timedelta(seconds=60)
        token = create_access_token("user@example.com", expires_delta=delta)
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        # exp should be roughly `now + 60 seconds` (within a 2-second tolerance)
        assert abs(payload["exp"] - (int(time.time()) + 60)) <= 2


# ---------------------------------------------------------------------------
# verify_token (JWT bearer dependency)
# ---------------------------------------------------------------------------


class TestVerifyToken:
    @pytest.mark.asyncio
    async def test_valid_token_returns_payload(self):
        token = create_access_token("unit-test-user")

        from fastapi.security import HTTPAuthorizationCredentials

        creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
        payload = await verify_token(creds)
        assert payload["sub"] == "unit-test-user"

    @pytest.mark.asyncio
    async def test_no_credentials_raises_401(self):
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            await verify_token(None)
        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_invalid_token_raises_401(self):
        from fastapi import HTTPException
        from fastapi.security import HTTPAuthorizationCredentials

        creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials="invalid.token.here")
        with pytest.raises(HTTPException) as exc_info:
            await verify_token(creds)
        assert exc_info.value.status_code == 401


# ---------------------------------------------------------------------------
# require_admin_auth – branches: valid API key, valid JWT, no auth
# ---------------------------------------------------------------------------


class TestRequireAdminAuth:
    """Unit tests for the require_admin_auth dependency."""

    def _make_request(self, cookies: dict = None):
        """Build a minimal mock Request with optional cookies."""
        from unittest.mock import MagicMock

        req = MagicMock()
        req.cookies = cookies or {}
        return req

    @pytest.mark.asyncio
    async def test_valid_api_key_returns_auth_context(self):
        from app.core.security import require_admin_auth

        key = generate_api_key()
        add_api_key(key)
        try:
            result = await require_admin_auth(
                request=self._make_request(), api_key=key, bearer=None
            )
            assert result["auth_type"] == "api_key"
        finally:
            from app.core.security import _api_keys

            _api_keys.discard(key)

    @pytest.mark.asyncio
    async def test_valid_jwt_returns_auth_context(self):
        from app.core.security import require_admin_auth

        token = create_access_token("admin-user")
        from fastapi.security import HTTPAuthorizationCredentials

        creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
        result = await require_admin_auth(request=self._make_request(), api_key=None, bearer=creds)
        assert result["auth_type"] == "jwt"
        assert result["payload"]["sub"] == "admin-user"

    @pytest.mark.asyncio
    async def test_invalid_jwt_and_no_api_key_raises_401(self):
        from fastapi import HTTPException
        from fastapi.security import HTTPAuthorizationCredentials

        from app.core.security import require_admin_auth

        creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials="bad.token.value")
        with pytest.raises(HTTPException) as exc_info:
            await require_admin_auth(request=self._make_request(), api_key=None, bearer=creds)
        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_no_auth_at_all_raises_401(self):
        from fastapi import HTTPException

        from app.core.security import require_admin_auth

        with pytest.raises(HTTPException) as exc_info:
            await require_admin_auth(request=self._make_request(), api_key=None, bearer=None)
        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_valid_session_cookie_returns_auth_context(self):
        """A valid dmarq_session cookie should authenticate successfully."""
        from app.core.logto import create_session_token
        from app.core.security import require_admin_auth

        token = create_session_token(user_id=42)
        result = await require_admin_auth(
            request=self._make_request(cookies={"dmarq_session": token}),
            api_key=None,
            bearer=None,
        )
        assert result["auth_type"] == "session"
        assert result["user_id"] == 42


# ---------------------------------------------------------------------------
# get_api_key dependency
# ---------------------------------------------------------------------------


class TestGetApiKeyDependency:
    @pytest.mark.asyncio
    async def test_missing_key_raises_401(self):
        from fastapi import HTTPException

        from app.core.security import get_api_key

        with pytest.raises(HTTPException) as exc_info:
            await get_api_key(None)
        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_invalid_key_raises_401(self):
        from fastapi import HTTPException

        from app.core.security import get_api_key

        with pytest.raises(HTTPException) as exc_info:
            await get_api_key("this-key-does-not-exist")
        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_valid_key_returns_key(self):
        from app.core.security import _api_keys, get_api_key

        key = generate_api_key()
        add_api_key(key)
        try:
            result = await get_api_key(key)
            assert result == key
        finally:
            _api_keys.discard(key)
