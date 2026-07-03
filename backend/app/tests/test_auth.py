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

import logging
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.api.api_v1.endpoints.auth import _create_next_cookie
from app.core.auth_providers import (
    ExternalIdentityClaims,
    OIDCProviderConfig,
    _normalize_role_claims,
    auth_provider_registry,
    configured_oidc_provider,
    create_oidc_state,
    decode_oidc_state,
    exchange_oidc_callback,
    normalize_external_claims,
    sync_external_user,
    trusted_proxy_claims_from_request,
    trusted_proxy_auth_context,
)
from app.core.config import Settings, get_settings
from app.core.logto import (
    SESSION_COOKIE,
    CookieStorage,
    create_session_token,
    decode_session_token,
    sync_logto_user,
)
from app.models.organization import Organization, OrganizationMembership
from app.models.user import User
from app.models.workspace import Workspace
from app.models.workspace_access import WorkspaceMembership

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


# ── Authentik / generic OIDC helpers ─────────────────────────────────────────


class TestExternalAuthProviders:
    def test_auth_provider_registry_exposes_required_modes(self):
        settings = Settings(
            AUTH_MODE="authentik",
            AUTHENTIK_ISSUER_URL="https://idp.example.test/application/o/dmarq",
            AUTHENTIK_CLIENT_ID="client-id",
            AUTHENTIK_CLIENT_SECRET="client-secret",
        )

        providers = {entry["provider"]: entry for entry in auth_provider_registry(settings)}

        assert providers["disabled"]["status"] == "ready"
        assert providers["local"]["status"] == "planned"
        assert providers["logto"]["auth_mode"] == "logto"
        assert providers["authentik"]["configured"] is True
        assert providers["authentik"]["active"] is True
        assert providers["oidc"]["auth_mode"] == "oidc"
        assert providers["keycloak"]["status"] == "ready_via_generic_oidc"
        assert providers["cloudflare_access"]["auth_mode"] == "trusted_proxy"
        assert providers["akamai_eaa"]["status"] == "planned"

    def test_authentik_config_selects_direct_oidc_provider(self):
        settings = Settings(
            AUTH_MODE="authentik",
            AUTHENTIK_ISSUER_URL="https://idp.example.test/application/o/dmarq",
            AUTHENTIK_CLIENT_ID="client-id",
            AUTHENTIK_CLIENT_SECRET="client-secret",
            AUTHENTIK_GROUP_WORKSPACE_ROLE_MAP="dmarq-admins=primary:workspace_owner",
            AUTHENTIK_GROUP_ORGANIZATION_ROLE_MAP="dmarq-admins=customer-one:organization_owner",
        )

        provider = configured_oidc_provider(settings)

        assert settings.active_auth_provider == "authentik"
        assert provider is not None
        assert provider.provider == "authentik"
        assert provider.label == "Authentik"
        assert provider.issuer_url == "https://idp.example.test/application/o/dmarq"
        assert provider.group_workspace_role_map == "dmarq-admins=primary:workspace_owner"
        assert (
            provider.group_organization_role_map == "dmarq-admins=customer-one:organization_owner"
        )

    def test_generic_oidc_config_selects_provider_label(self):
        settings = Settings(
            AUTH_MODE="oidc",
            OIDC_ISSUER_URL="https://idp.example.test",
            OIDC_CLIENT_ID="client-id",
            OIDC_CLIENT_SECRET="client-secret",
            OIDC_PROVIDER_LABEL="Keycloak",
        )

        provider = configured_oidc_provider(settings)

        assert settings.active_auth_provider == "oidc"
        assert provider is not None
        assert provider.label == "Keycloak"

    def test_generic_oidc_presets_require_explicit_provider_match(self):
        settings = Settings(
            AUTH_MODE="oidc",
            OIDC_ISSUER_URL="https://idp.example.test/realms/dmarq",
            OIDC_CLIENT_ID="client-id",
            OIDC_CLIENT_SECRET="client-secret",
            OIDC_PROVIDER_LABEL="Keycloak",
        )

        providers = {entry["provider"]: entry for entry in auth_provider_registry(settings)}

        assert providers["oidc"]["configured"] is True
        assert providers["keycloak"]["configured"] is True
        assert providers["entra_id"]["configured"] is False
        assert providers["google_workspace"]["configured"] is False

    def test_oidc_state_round_trip(self):
        settings = Settings(SECRET_KEY="s" * 32)
        token = create_oidc_state("/domains", settings)

        payload = decode_oidc_state(token, settings)

        assert payload is not None
        assert payload["next"] == "/domains"

    def test_normalize_external_claims_applies_domain_allowlist(self):
        claims = normalize_external_claims(
            "authentik",
            {
                "sub": "authentik-user-1",
                "email": "owner@example.com",
                "name": "Owner",
                "preferred_username": "owner",
                "email_verified": True,
            },
            allowed_domains="example.com",
        )

        assert claims.provider == "authentik"
        assert claims.subject == "authentik-user-1"
        assert claims.email == "owner@example.com"
        assert claims.username == "owner"
        assert claims.email_verified is True

    def test_normalize_external_claims_rejects_unlisted_email(self):
        with pytest.raises(HTTPException) as exc:
            normalize_external_claims(
                "authentik",
                {"sub": "authentik-user-1", "email": "owner@other.test"},
                allowed_domains="example.com",
            )

        assert exc.value.status_code == 403

    def test_normalize_external_claims_extracts_idp_role_claims(self):
        claims = normalize_external_claims(
            "authentik",
            {
                "sub": "authentik-user-1",
                "email": "owner@example.com",
                "groups": ["dmarq-admins", "billing"],
                "dmarq_workspace_roles": {
                    "primary": "workspace_owner",
                    "secondary": "analyst",
                    "ignored": "root",
                },
                "dmarq_organization_roles": [
                    {"organization": "customer-one", "role": "organization_owner"},
                    "customer-two:auditor",
                    "ignored:root",
                ],
            },
            allowed_domains="example.com",
        )

        assert claims.groups == ("dmarq-admins", "billing")
        assert claims.workspace_roles == (
            ("primary", "workspace_owner"),
            ("secondary", "analyst"),
        )
        assert claims.organization_roles == (
            ("customer-one", "organization_owner"),
            ("customer-two", "auditor"),
        )

    def test_normalize_external_claims_applies_group_role_mappings(self):
        claims = normalize_external_claims(
            "authentik",
            {
                "sub": "authentik-user-1",
                "email": "owner@example.com",
                "groups": ["DMARQ-Admins", "billing"],
                "dmarq_workspace_roles": {"primary": "workspace_owner"},
            },
            allowed_domains="example.com",
            group_workspace_role_map=(
                "dmarq-admins=primary:workspace_owner,"
                "billing=secondary:analyst,"
                "ignored=primary:workspace_owner,"
                "billing=bad:root"
            ),
            group_organization_role_map="dmarq-admins=customer-one:organization_owner",
        )

        assert claims.groups == ("DMARQ-Admins", "billing")
        assert claims.workspace_roles == (
            ("primary", "workspace_owner"),
            ("secondary", "analyst"),
        )
        assert claims.organization_roles == (("customer-one", "organization_owner"),)

    def test_normalize_external_claims_preserves_explicit_role_precedence(self):
        claims = normalize_external_claims(
            "authentik",
            {
                "sub": "authentik-user-1",
                "email": "owner@example.com",
                "groups": ["dmarq-admins", "auditors"],
                "dmarq_workspace_roles": {"primary": "analyst"},
                "dmarq_organization_roles": {"customer-one": "auditor"},
            },
            allowed_domains="example.com",
            group_workspace_role_map=(
                "dmarq-admins=primary:workspace_owner," "auditors=secondary:analyst"
            ),
            group_organization_role_map=(
                "dmarq-admins=customer-one:organization_owner," "auditors=customer-two:auditor"
            ),
        )

        assert claims.workspace_roles == (
            ("primary", "analyst"),
            ("secondary", "analyst"),
        )
        assert claims.organization_roles == (
            ("customer-one", "auditor"),
            ("customer-two", "auditor"),
        )

    def test_normalize_external_claims_logs_invalid_group_role_mappings(self, caplog):
        with caplog.at_level(logging.WARNING, logger="app.core.auth_providers"):
            claims = normalize_external_claims(
                "authentik",
                {
                    "sub": "authentik-user-1",
                    "email": "owner@example.com",
                    "groups": ["dmarq-admins"],
                },
                allowed_domains="example.com",
                group_workspace_role_map=(
                    "malformed-entry," "dmarq-admins=primary:root," "dmarq-admins=missing-separator"
                ),
            )

        assert claims.workspace_roles == ()
        assert "malformed group-role mapping entry at position=1" in caplog.text
        assert "invalid target at position=2" in caplog.text
        assert "without a target at position=3" in caplog.text
        assert "primary:root" not in caplog.text
        assert "owner@example.com" not in caplog.text

    def test_normalize_role_claims_accepts_strings_and_deduplicates_pairs(self):
        roles = _normalize_role_claims(
            [
                "primary:workspace_owner",
                "primary=workspace_owner",
                {"slug": "secondary", "role": "analyst"},
                "missing-separator",
                {"slug": "", "role": "analyst"},
                {"slug": "ignored", "role": "root"},
            ],
            allowed_roles={"workspace_owner", "analyst"},
        )

        assert roles == (
            ("primary", "workspace_owner"),
            ("secondary", "analyst"),
        )

    def test_normalize_role_claims_accepts_single_string_claims(self):
        roles = _normalize_role_claims(
            "primary:workspace_owner,secondary=analyst,ignored=root",
            allowed_roles={"workspace_owner", "analyst"},
        )

        assert roles == (
            ("primary", "workspace_owner"),
            ("secondary", "analyst"),
        )

    def test_sync_external_user_uses_provider_scoped_subject(self, db_session):
        user = sync_external_user(
            ExternalIdentityClaims(
                provider="authentik",
                subject="authentik-user-1",
                email="owner@example.com",
                name="Owner",
                username="owner",
                email_verified=True,
            ),
            db_session,
        )

        assert user.id is not None
        assert user.logto_id == "authentik:authentik-user-1"
        assert user.email == "owner@example.com"
        assert user.full_name == "Owner"

    def test_sync_external_user_applies_workspace_and_org_roles(self, db_session):
        organization = Organization(slug="customer-one", name="Customer One")
        workspace = Workspace(slug="primary", name="Primary", organization=organization)
        db_session.add_all([organization, workspace])
        db_session.commit()

        user = sync_external_user(
            ExternalIdentityClaims(
                provider="authentik",
                subject="authentik-user-1",
                email="owner@example.com",
                name="Owner",
                workspace_roles=(("primary", "workspace_owner"),),
                organization_roles=(("customer-one", "organization_owner"),),
            ),
            db_session,
        )

        workspace_membership = (
            db_session.query(WorkspaceMembership)
            .filter_by(workspace_id=workspace.id, user_id=user.id)
            .one()
        )
        organization_membership = (
            db_session.query(OrganizationMembership)
            .filter_by(organization_id=organization.id, user_id=user.id)
            .one()
        )

        assert user.is_superuser is False
        assert user.workspace_id == workspace.id
        assert workspace_membership.role == "workspace_owner"
        assert workspace_membership.active is True
        assert organization_membership.role == "organization_owner"
        assert organization_membership.active is True

    def test_sync_external_user_applies_group_mapped_roles(self, db_session):
        organization = Organization(slug="customer-one", name="Customer One")
        workspace = Workspace(slug="primary", name="Primary", organization=organization)
        db_session.add_all([organization, workspace])
        db_session.commit()

        claims = normalize_external_claims(
            "authentik",
            {
                "sub": "authentik-user-1",
                "email": "owner@example.com",
                "groups": ["dmarq-admins"],
            },
            group_workspace_role_map="dmarq-admins=primary:workspace_owner",
            group_organization_role_map="dmarq-admins=customer-one:organization_owner",
        )
        user = sync_external_user(claims, db_session)

        assert (
            db_session.query(WorkspaceMembership)
            .filter_by(workspace_id=workspace.id, user_id=user.id)
            .one()
            .role
            == "workspace_owner"
        )
        assert (
            db_session.query(OrganizationMembership)
            .filter_by(organization_id=organization.id, user_id=user.id)
            .one()
            .role
            == "organization_owner"
        )

    def test_sync_external_user_demotes_fallback_superuser_with_role_claims(self, db_session):
        organization = Organization(slug="customer-one", name="Customer One")
        workspace = Workspace(slug="primary", name="Primary", organization=organization)
        user = User(
            logto_id="authentik:authentik-user-1",
            email="owner@example.com",
            is_active=True,
            is_superuser=True,
        )
        db_session.add_all([organization, workspace, user])
        db_session.commit()

        synced = sync_external_user(
            ExternalIdentityClaims(
                provider="authentik",
                subject="authentik-user-1",
                email="owner@example.com",
                workspace_roles=(("primary", "workspace_owner"),),
            ),
            db_session,
        )

        assert synced.id == user.id
        assert synced.is_superuser is False
        assert (
            db_session.query(WorkspaceMembership)
            .filter_by(workspace_id=workspace.id, user_id=user.id)
            .one()
            .role
            == "workspace_owner"
        )

    def test_sync_external_user_links_existing_email_and_updates_memberships(self, db_session):
        organization = Organization(slug="customer-one", name="Customer One")
        workspace = Workspace(slug="primary", name="Primary", organization=organization)
        user = User(
            email="owner@example.com",
            is_active=True,
            is_superuser=True,
        )
        db_session.add_all([organization, workspace, user])
        db_session.flush()
        db_session.add_all(
            [
                WorkspaceMembership(
                    workspace_id=workspace.id,
                    user_id=user.id,
                    role="analyst",
                    active=False,
                ),
                OrganizationMembership(
                    organization_id=organization.id,
                    user_id=user.id,
                    role="auditor",
                    active=False,
                ),
            ]
        )
        db_session.commit()

        synced = sync_external_user(
            ExternalIdentityClaims(
                provider="authentik",
                subject="authentik-user-1",
                email="owner@example.com",
                workspace_roles=(("primary", "workspace_owner"),),
                organization_roles=(("customer-one", "organization_owner"),),
            ),
            db_session,
        )

        workspace_membership = (
            db_session.query(WorkspaceMembership)
            .filter_by(workspace_id=workspace.id, user_id=user.id)
            .one()
        )
        organization_membership = (
            db_session.query(OrganizationMembership)
            .filter_by(organization_id=organization.id, user_id=user.id)
            .one()
        )
        assert synced.id == user.id
        assert synced.logto_id == "authentik:authentik-user-1"
        assert workspace_membership.role == "workspace_owner"
        assert workspace_membership.active is True
        assert organization_membership.role == "organization_owner"
        assert organization_membership.active is True

    def test_sync_external_user_ignores_unknown_claim_targets(self, db_session):
        user = sync_external_user(
            ExternalIdentityClaims(
                provider="authentik",
                subject="authentik-user-1",
                email="owner@example.com",
                workspace_roles=(("missing", "workspace_owner"),),
                organization_roles=(("missing-org", "organization_owner"),),
            ),
            db_session,
        )

        assert user.is_superuser is False
        assert db_session.query(WorkspaceMembership).count() == 0
        assert db_session.query(OrganizationMembership).count() == 0

    def test_trusted_proxy_auth_context_uses_authentik_headers(self):
        settings = Settings(
            AUTH_MODE="trusted_proxy",
            AUTH_TRUSTED_PROXY_ALLOWED_DOMAINS="example.com",
        )
        request = MagicMock()
        request.headers = {
            "X-Authentik-Email": "owner@example.com",
            "X-Authentik-Uid": "authentik-user-1",
            "X-Authentik-Name": "Owner",
            "X-Authentik-Username": "owner",
        }

        context = trusted_proxy_auth_context(request, settings)

        assert context == {
            "auth_type": "trusted_proxy",
            "provider": "authentik",
            "sub": "authentik:authentik-user-1",
            "email": "owner@example.com",
            "name": "Owner",
            "username": "owner",
        }

    def test_trusted_proxy_claims_apply_group_role_mappings(self):
        settings = Settings(
            AUTH_MODE="trusted_proxy",
            AUTH_TRUSTED_PROXY_ALLOWED_DOMAINS="example.com",
            AUTH_TRUSTED_PROXY_GROUP_WORKSPACE_ROLE_MAP="dmarq-admins=primary:workspace_owner",
            AUTH_TRUSTED_PROXY_GROUP_ORGANIZATION_ROLE_MAP=(
                "dmarq-admins=customer-one:organization_owner"
            ),
        )
        request = MagicMock()
        request.headers = {
            "X-Authentik-Email": "owner@example.com",
            "X-Authentik-Uid": "authentik-user-1",
            "X-Authentik-Groups": "dmarq-admins,other",
        }

        claims = trusted_proxy_claims_from_request(request, settings)

        assert claims is not None
        assert claims.groups == ("dmarq-admins", "other")
        assert claims.workspace_roles == (("primary", "workspace_owner"),)
        assert claims.organization_roles == (("customer-one", "organization_owner"),)

    @pytest.mark.asyncio
    async def test_oidc_callback_rejects_unverified_id_token_without_userinfo(self):
        provider = OIDCProviderConfig(
            provider="oidc",
            label="OpenID Connect",
            issuer_url="https://idp.example.test",
            client_id="client-id",
            client_secret="client-secret",
            redirect_uri=None,
            scopes="openid email profile",
            skip_ssl_verify=False,
        )
        request = MagicMock()
        request.base_url = "https://dmarq.example.test/"
        token_response = MagicMock()
        token_response.raise_for_status = MagicMock()
        token_response.json.return_value = {
            "id_token": "header.payload.signature",
            "access_token": "access-token",
        }

        with (
            patch(
                "app.core.auth_providers.fetch_oidc_discovery",
                new=AsyncMock(
                    return_value={
                        "authorization_endpoint": "https://idp.example.test/auth",
                        "token_endpoint": "https://idp.example.test/token",
                    }
                ),
            ),
            patch("httpx.AsyncClient.post", new=AsyncMock(return_value=token_response)),
        ):
            with pytest.raises(HTTPException) as exc:
                await exchange_oidc_callback(request, provider, code="callback-code")

        assert exc.value.status_code == 401
        assert "unvalidated ID-token claims" in exc.value.detail


class TestAuthProviderEndpoint:
    def test_auth_providers_endpoint_reports_active_authentik(self, client: TestClient):
        from app.api.api_v1.endpoints import auth as auth_endpoint

        endpoint_settings = Settings(
            AUTH_MODE="authentik",
            AUTHENTIK_ISSUER_URL="https://idp.example.test/application/o/dmarq",
            AUTHENTIK_CLIENT_ID="client-id",
            AUTHENTIK_CLIENT_SECRET="client-secret",
        )

        with patch.object(auth_endpoint, "settings", endpoint_settings):
            res = client.get("/api/v1/auth/providers")

        assert res.status_code == 200
        data = res.json()
        assert data["active_provider"] == "authentik"
        assert data["active_label"] == "Authentik"
        assert data["auth_configured"] is True
        providers = {entry["provider"]: entry for entry in data["providers"]}
        assert providers["authentik"]["configured"] is True
        assert providers["keycloak"]["status"] == "ready_via_generic_oidc"


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
        next_cookie = _create_next_cookie("/dashboard")
        with patch("app.api.api_v1.endpoints.auth.settings") as mock_settings:
            real_settings = get_settings()
            mock_settings.logto_configured = True
            mock_settings.SECRET_KEY = real_settings.SECRET_KEY
            mock_settings.ALGORITHM = real_settings.ALGORITHM
            with patch("app.api.api_v1.endpoints.auth.make_logto_client", return_value=mock_client):
                res = client.get(
                    "/api/v1/auth/callback?code=good",
                    cookies={"logto_next": next_cookie},
                    follow_redirects=False,
                )
        assert res.status_code == 302
        assert res.headers["location"] == "/dashboard"

    def test_callback_ignores_tampered_logto_next_cookie(self, client: TestClient):
        """Unsigned or tampered next cookies must not control the post-login redirect."""
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
        assert res.headers["location"] == "/"


# ── /api/v1/auth/sign-in ─────────────────────────────────────────────────────


class TestSignInEndpoint:
    def test_sign_in_without_logto_config_returns_503(self, client: TestClient):
        """When Logto is not configured the endpoint must return 503."""
        with patch("app.api.api_v1.endpoints.auth.settings") as mock_settings:
            mock_settings.logto_configured = False
            res = client.get("/api/v1/auth/sign-in", follow_redirects=False)
        assert res.status_code == 503

    def test_trusted_proxy_sign_in_uses_fixed_local_redirect(self, client: TestClient):
        """Trusted-proxy mode must not redirect to caller-controlled destinations."""
        with patch("app.api.api_v1.endpoints.auth.settings") as mock_settings:
            mock_settings.active_auth_provider = "trusted_proxy"
            res = client.get(
                "/api/v1/auth/sign-in?next=/domains",
                follow_redirects=False,
            )

        assert res.status_code == 302
        assert res.headers["location"] == "/"


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
            result = asyncio.run(require_admin_auth(request=mock_req, api_key=None, bearer=None))
        assert result["auth_type"] == "disabled"

    def test_require_admin_auth_accepts_trusted_proxy_headers(self):
        """Trusted proxy mode accepts explicitly configured Authentik headers."""
        import asyncio
        from unittest.mock import MagicMock

        from app.core.config import Settings
        from app.core.security import require_admin_auth

        trusted_settings = Settings(
            AUTH_MODE="trusted_proxy",
            AUTH_TRUSTED_PROXY_ALLOWED_DOMAINS="example.com",
        )
        mock_req = MagicMock()
        mock_req.cookies = {}
        mock_req.headers = {
            "X-Authentik-Email": "owner@example.com",
            "X-Authentik-Uid": "authentik-user-1",
        }
        with patch("app.core.security.settings", trusted_settings):
            result = asyncio.run(require_admin_auth(request=mock_req, api_key=None, bearer=None))

        assert result["auth_type"] == "trusted_proxy"
        assert result["email"] == "owner@example.com"
        assert result["sub"] == "authentik:authentik-user-1"

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
