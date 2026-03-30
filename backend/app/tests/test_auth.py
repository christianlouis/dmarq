"""
Tests for the Logto-based authentication layer.

These tests exercise:
- Session-token creation and decoding (app.core.logto)
- CookieStorage read/write/delete semantics
- sync_logto_user DB upsert logic
- /api/v1/auth/me – authenticated and unauthenticated
- /api/v1/auth/sign-in – Logto not configured → 503
- /api/v1/auth/sign-out – always clears the session cookie

All tests use the in-memory SQLite fixture from conftest.py.
Logto SDK calls are mocked so no live Logto instance is needed.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from app.core.logto import (
    SESSION_COOKIE,
    CookieStorage,
    create_session_token,
    decode_session_token,
    sync_logto_user,
)
from app.models.user import User

# ── Session token helpers ─────────────────────────────────────────────────────


class TestSessionToken:
    def test_roundtrip(self):
        token = create_session_token(user_id=7)
        assert decode_session_token(token) == 7

    def test_invalid_token_returns_none(self):
        assert decode_session_token("not.a.token") is None

    def test_wrong_type_returns_none(self):
        """A generic JWT without the dmarq_session type claim should be rejected."""
        from jose import jwt

        from app.core.config import get_settings

        s = get_settings()
        payload = {"sub": "5", "type": "other"}
        bad_token = jwt.encode(payload, s.SECRET_KEY, algorithm=s.ALGORITHM)
        assert decode_session_token(bad_token) is None


# ── CookieStorage ─────────────────────────────────────────────────────────────


class TestCookieStorage:
    def _make_request(self, cookies: dict = None):
        req = MagicMock()
        req.cookies = cookies or {}
        return req

    def _make_response(self):
        from starlette.responses import Response

        return Response()

    def test_get_from_request_cookies(self):
        req = self._make_request({"logto_idToken": "abc123"})
        storage = CookieStorage(req)
        assert storage.get("idToken") == "abc123"

    def test_pending_write_shadows_cookie(self):
        req = self._make_request({"logto_idToken": "old"})
        storage = CookieStorage(req)
        storage.set("idToken", "new")
        assert storage.get("idToken") == "new"

    def test_delete_shadows_cookie(self):
        req = self._make_request({"logto_idToken": "exists"})
        storage = CookieStorage(req)
        storage.delete("idToken")
        assert storage.get("idToken") is None

    def test_apply_to_response_sets_cookies(self):
        storage = CookieStorage(self._make_request())
        storage.set("idToken", "tok123")
        resp = self._make_response()
        storage.apply_to_response(resp)
        # Cookie header should contain the key
        header_str = str(resp.headers.get("set-cookie", ""))
        assert "logto_idToken" in header_str

    def test_apply_to_response_deletes_cookies(self):
        req = self._make_request({"logto_idToken": "old"})
        storage = CookieStorage(req)
        storage.delete("idToken")
        resp = self._make_response()
        storage.apply_to_response(resp)
        header_str = str(resp.headers.get("set-cookie", ""))
        assert "logto_idToken" in header_str
        # A deleted cookie is set with max-age=0
        assert "Max-Age=0" in header_str or "expires" in header_str.lower()


# ── sync_logto_user ───────────────────────────────────────────────────────────


class TestSyncLogtoUser:
    def _claims(self, sub="logto-sub-1", email="user@example.com", name="Test User"):
        claims = MagicMock()
        claims.sub = sub
        claims.email = email
        claims.name = name
        claims.username = None
        claims.picture = None
        claims.email_verified = True
        return claims

    def test_creates_new_user(self, db_session):
        claims = self._claims()
        user = sync_logto_user(claims, db_session)
        assert user.id is not None
        assert user.logto_id == "logto-sub-1"
        assert user.email == "user@example.com"
        assert user.full_name == "Test User"
        assert user.is_superuser is True

    def test_returns_existing_user_by_logto_id(self, db_session):
        # Create user first
        claims = self._claims()
        user1 = sync_logto_user(claims, db_session)
        uid = user1.id

        # Second call with same sub → same user, no duplicate
        user2 = sync_logto_user(claims, db_session)
        assert user2.id == uid
        total = db_session.query(User).count()
        assert total == 1

    def test_links_existing_user_by_email(self, db_session):
        """Legacy user with matching email but no logto_id gets linked."""
        legacy = User(email="user@example.com", is_active=True, is_superuser=True)
        db_session.add(legacy)
        db_session.commit()

        claims = self._claims(sub="new-sub", email="user@example.com")
        user = sync_logto_user(claims, db_session)

        assert user.id == legacy.id
        assert user.logto_id == "new-sub"

    def test_updates_profile_on_subsequent_login(self, db_session):
        claims = self._claims(name="Old Name")
        sync_logto_user(claims, db_session)

        claims2 = self._claims(name="New Name")
        user = sync_logto_user(claims2, db_session)
        assert user.full_name == "New Name"


# ── /api/v1/auth/me ───────────────────────────────────────────────────────────


class TestAuthMeEndpoint:
    def test_me_unauthenticated_returns_401(self, client: TestClient):
        res = client.get("/api/v1/auth/me")
        assert res.status_code == 401

    def test_me_with_valid_session_returns_user(self, client: TestClient, db_session):
        # Create a user in the DB
        user = User(
            email="me@example.com",
            logto_id="sub-me",
            is_active=True,
            is_superuser=True,
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)

        token = create_session_token(user.id)
        res = client.get("/api/v1/auth/me", cookies={SESSION_COOKIE: token})
        assert res.status_code == 200
        data = res.json()
        assert data["email"] == "me@example.com"
        assert data["logto_id"] == "sub-me"

    def test_me_with_invalid_session_returns_401(self, client: TestClient):
        res = client.get("/api/v1/auth/me", cookies={SESSION_COOKIE: "garbage"})
        assert res.status_code == 401

    def test_me_with_inactive_user_returns_401(self, client: TestClient, db_session):
        user = User(
            email="inactive@example.com",
            logto_id="sub-inactive",
            is_active=False,
            is_superuser=True,
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)

        token = create_session_token(user.id)
        res = client.get("/api/v1/auth/me", cookies={SESSION_COOKIE: token})
        assert res.status_code == 401


# ── /api/v1/auth/sign-in ─────────────────────────────────────────────────────


class TestSignInEndpoint:
    def test_sign_in_without_logto_config_returns_503(self, client: TestClient):
        """When Logto is not configured the endpoint must return 503."""
        with patch("app.api.api_v1.endpoints.auth.settings") as mock_settings:
            mock_settings.logto_configured = False
            res = client.get("/api/v1/auth/sign-in", follow_redirects=False)
        assert res.status_code == 503


# ── /api/v1/auth/sign-out ────────────────────────────────────────────────────


class TestSignOutEndpoint:
    def test_sign_out_clears_session_cookie(self, client: TestClient):
        """Sign-out must delete the dmarq_session cookie regardless of Logto config."""
        token = create_session_token(user_id=1)
        # Use allow_redirects=False so we see the redirect response with cookies
        res = client.get(
            "/api/v1/auth/sign-out",
            cookies={SESSION_COOKIE: token},
            follow_redirects=False,
        )
        # Should redirect (to /login or Logto end_session)
        assert res.status_code in (302, 307)
        # The session cookie must be cleared (max-age=0 or expires in past)
        set_cookie = res.headers.get("set-cookie", "")
        assert SESSION_COOKIE in set_cookie
        assert "Max-Age=0" in set_cookie or "max-age=0" in set_cookie
