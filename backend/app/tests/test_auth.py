"""
Tests for the Logto-based authentication layer.

These tests exercise:
- Session-token creation and decoding (app.core.logto)
- CookieStorage read/write/delete semantics
- sync_logto_user DB upsert logic
- /api/v1/auth/me – authenticated and unauthenticated
- /api/v1/auth/sign-in – Logto not configured → 503
- /api/v1/auth/sign-out – always clears the session cookie
- SSL bypass patching (_apply_logto_ssl_patch)

All tests use the in-memory SQLite fixture from conftest.py.
Logto SDK calls are mocked so no live Logto instance is needed.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

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


# ── /api/v1/auth/callback ────────────────────────────────────────────────────


class TestCallbackEndpoint:
    """Tests for the Logto OIDC authorization-code callback handler."""

    def _make_mock_claims(self):
        claims = MagicMock()
        claims.sub = "logto-sub-callback"
        claims.email = "callback@example.com"
        claims.name = "Callback User"
        claims.username = None
        claims.picture = None
        claims.email_verified = True
        return claims

    def _mock_client(self, handle_error=None, claims_error=None, claims=None):
        """Build a mock LogtoClient with configurable side effects."""
        mock_client = MagicMock()
        if handle_error:
            mock_client.handleSignInCallback = AsyncMock(side_effect=handle_error)
        else:
            mock_client.handleSignInCallback = AsyncMock()
        if claims_error:
            mock_client.getIdTokenClaims.side_effect = claims_error
        elif claims is not None:
            mock_client.getIdTokenClaims.return_value = claims
        return mock_client

    def test_callback_without_logto_config_returns_503(self, client: TestClient):
        """When Logto is not configured the callback must return 503."""
        with patch("app.api.api_v1.endpoints.auth.settings") as mock_settings:
            mock_settings.logto_configured = False
            res = client.get("/api/v1/auth/callback", follow_redirects=False)
        assert res.status_code == 503

    def test_callback_handle_signin_error_redirects_to_callback_failed(self, client: TestClient):
        """If handleSignInCallback raises, redirect to /login?error=callback_failed."""
        mock_client = self._mock_client(handle_error=Exception("bad state"))
        with patch("app.api.api_v1.endpoints.auth.settings") as mock_settings:
            mock_settings.logto_configured = True
            with patch("app.api.api_v1.endpoints.auth.make_logto_client", return_value=mock_client):
                res = client.get("/api/v1/auth/callback?code=bad", follow_redirects=False)
        assert res.status_code == 302
        assert "callback_failed" in res.headers["location"]

    def test_callback_get_claims_error_redirects_to_token_error(self, client: TestClient):
        """If getIdTokenClaims raises, redirect to /login?error=token_error."""
        mock_client = self._mock_client(claims_error=Exception("claims unavailable"))
        with patch("app.api.api_v1.endpoints.auth.settings") as mock_settings:
            mock_settings.logto_configured = True
            with patch("app.api.api_v1.endpoints.auth.make_logto_client", return_value=mock_client):
                res = client.get("/api/v1/auth/callback?code=x", follow_redirects=False)
        assert res.status_code == 302
        assert "token_error" in res.headers["location"]

    def test_callback_success_issues_session_cookie_and_redirects_to_root(self, client: TestClient):
        """Successful callback must issue the dmarq_session cookie and redirect to /."""
        claims = self._make_mock_claims()
        mock_client = self._mock_client(claims=claims)
        with patch("app.api.api_v1.endpoints.auth.settings") as mock_settings:
            mock_settings.logto_configured = True
            with patch("app.api.api_v1.endpoints.auth.make_logto_client", return_value=mock_client):
                res = client.get("/api/v1/auth/callback?code=good", follow_redirects=False)
        assert res.status_code == 302
        assert res.headers["location"] == "/"
        set_cookie = res.headers.get("set-cookie", "")
        assert SESSION_COOKIE in set_cookie

    def test_callback_success_respects_logto_next_cookie(self, client: TestClient):
        """After a successful callback the user is redirected to the stored next URL."""
        claims = self._make_mock_claims()
        mock_client = self._mock_client(claims=claims)
        with patch("app.api.api_v1.endpoints.auth.settings") as mock_settings:
            mock_settings.logto_configured = True
            with patch("app.api.api_v1.endpoints.auth.make_logto_client", return_value=mock_client):
                res = client.get(
                    "/api/v1/auth/callback?code=good",
                    cookies={"logto_next": "/dashboard"},
                    follow_redirects=False,
                )
        assert res.status_code == 302
        assert res.headers["location"] == "/dashboard"


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


# ── AUTH_DISABLED mode ────────────────────────────────────────────────────────


class TestAuthDisabled:
    """Verify the AUTH_DISABLED=true no-auth fallback mode."""

    def test_me_returns_synthetic_admin_when_auth_disabled(self, client: TestClient):
        """With AUTH_DISABLED, /me must return the synthetic admin profile."""
        with patch("app.api.api_v1.endpoints.auth.settings") as mock_settings:
            mock_settings.AUTH_DISABLED = True
            res = client.get("/api/v1/auth/me")
        assert res.status_code == 200
        data = res.json()
        assert data["is_superuser"] is True
        assert data["auth_disabled"] is True
        assert data["email"] == "admin@localhost"

    def test_sign_out_redirects_to_root_when_auth_disabled(self, client: TestClient):
        """With AUTH_DISABLED, sign-out should redirect to / (no Logto session to clear)."""
        with patch("app.api.api_v1.endpoints.auth.settings") as mock_settings:
            mock_settings.AUTH_DISABLED = True
            res = client.get("/api/v1/auth/sign-out", follow_redirects=False)
        assert res.status_code == 302
        assert res.headers["location"] == "/"

    def test_require_admin_auth_passes_when_disabled(self):
        """require_admin_auth must return a synthetic context when AUTH_DISABLED=True."""
        import asyncio
        from unittest.mock import MagicMock

        from app.core.security import require_admin_auth

        with patch("app.core.security.settings") as mock_settings:
            mock_settings.AUTH_DISABLED = True
            mock_req = MagicMock()
            mock_req.cookies = {}
            result = asyncio.get_event_loop().run_until_complete(
                require_admin_auth(request=mock_req, api_key=None, bearer=None)
            )
        assert result["auth_type"] == "disabled"

    def test_middleware_passes_all_requests_when_auth_disabled(self, client: TestClient):
        """The auth middleware must let every request through when AUTH_DISABLED=True."""
        # The middleware does `from app.core.config import get_settings` inside dispatch,
        # so we patch the canonical location used at call time.
        with patch("app.core.config.get_settings") as mock_get_settings:
            mock_cfg = MagicMock()
            mock_cfg.AUTH_DISABLED = True
            mock_get_settings.return_value = mock_cfg
            # Even without a session cookie, the middleware lets the request through.
            # The endpoint itself then handles auth (API key or 401), but it must
            # never be a 302 redirect from the middleware.
            res = client.get("/settings", follow_redirects=False)
            assert res.status_code != 302


# ── Static asset bypass ───────────────────────────────────────────────────────


class TestStaticAssetBypass:
    """Static assets must never be redirected to the login page."""

    @staticmethod
    def _logto_configured_mock():
        mock_cfg = MagicMock()
        mock_cfg.AUTH_DISABLED = False
        mock_cfg.logto_configured = True
        return mock_cfg

    def test_favicon_not_redirected_to_login(self, client: TestClient):
        """GET /favicon.ico without a session must pass through (not redirect to /login)."""
        with patch("app.core.config.get_settings") as mock_get_settings:
            mock_get_settings.return_value = self._logto_configured_mock()
            res = client.get("/favicon.ico", follow_redirects=False)
        assert res.status_code != 302

    def test_png_asset_not_redirected_to_login(self, client: TestClient):
        """GET /logo.png without a session must pass through."""
        with patch("app.core.config.get_settings") as mock_get_settings:
            mock_get_settings.return_value = self._logto_configured_mock()
            res = client.get("/logo.png", follow_redirects=False)
        assert res.status_code != 302

    def test_protected_page_still_redirected(self, client: TestClient):
        """GET /dashboard without a session must still redirect to /login."""
        with patch("app.core.config.get_settings") as mock_get_settings:
            mock_get_settings.return_value = self._logto_configured_mock()
            res = client.get("/dashboard", follow_redirects=False)
        assert res.status_code == 302
        assert res.headers["location"].startswith("/login")


# ── SSL bypass patch ──────────────────────────────────────────────────────────


class TestApplyLogtoSslPatch:
    """_apply_logto_ssl_patch should extend both the aiohttp and PyJWKClient patches."""

    def test_no_patch_when_ssl_verify_enabled(self):
        """When LOGTO_SKIP_SSL_VERIFY is False the function must not modify aiohttp."""
        import aiohttp

        original = aiohttp.ClientSession

        mock_settings = MagicMock()
        mock_settings.LOGTO_SKIP_SSL_VERIFY = False

        with patch("app.core.logto.settings", mock_settings):
            from app.core.logto import _apply_logto_ssl_patch

            _apply_logto_ssl_patch()

        assert aiohttp.ClientSession is original

    def test_aiohttp_patched_when_ssl_skip_enabled(self):
        """When LOGTO_SKIP_SSL_VERIFY is True the aiohttp.ClientSession must be replaced."""
        import aiohttp

        original = aiohttp.ClientSession

        mock_settings = MagicMock()
        mock_settings.LOGTO_SKIP_SSL_VERIFY = True

        with patch("app.core.logto.settings", mock_settings):
            from app.core.logto import _apply_logto_ssl_patch

            _apply_logto_ssl_patch()

        try:
            assert aiohttp.ClientSession is not original
        finally:
            # Restore so later tests are not affected.
            aiohttp.ClientSession = original

    def test_pyjwkclient_patched_when_ssl_skip_enabled(self):
        """When LOGTO_SKIP_SSL_VERIFY is True, PyJWKClient in logto.OidcCore must be
        replaced with a subclass that injects a non-verifying ssl_context."""
        import logto.OidcCore as _oidc_module
        from jwt import PyJWKClient

        original_pyjwkclient = _oidc_module.PyJWKClient

        mock_settings = MagicMock()
        mock_settings.LOGTO_SKIP_SSL_VERIFY = True

        with patch("app.core.logto.settings", mock_settings):
            from app.core.logto import _apply_logto_ssl_patch

            _apply_logto_ssl_patch()

        try:
            patched = _oidc_module.PyJWKClient
            assert patched is not PyJWKClient, "PyJWKClient should be replaced"
            assert issubclass(patched, PyJWKClient), "Replacement must subclass PyJWKClient"
        finally:
            _oidc_module.PyJWKClient = original_pyjwkclient

    def test_pyjwkclient_patch_injects_ssl_context(self):
        """The patched PyJWKClient must pass ssl_context to its parent when constructed."""
        import ssl

        import logto.OidcCore as _oidc_module

        original_pyjwkclient = _oidc_module.PyJWKClient

        mock_settings = MagicMock()
        mock_settings.LOGTO_SKIP_SSL_VERIFY = True

        with patch("app.core.logto.settings", mock_settings):
            from app.core.logto import _apply_logto_ssl_patch

            _apply_logto_ssl_patch()

        try:
            instance = _oidc_module.PyJWKClient("https://example.com/.well-known/jwks.json")
            assert instance.ssl_context is not None
            assert isinstance(instance.ssl_context, ssl.SSLContext)
            assert instance.ssl_context.verify_mode == ssl.CERT_NONE
        finally:
            _oidc_module.PyJWKClient = original_pyjwkclient
