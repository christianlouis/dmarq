"""Tests for mail-service sender-domain discovery and import."""

import asyncio
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from app.models.domain import Domain
from app.models.setting import Setting
from app.services import mail_service_imports
from app.services.mail_service_imports import MailServiceImportError
from app.services.organizations import OrganizationPlanLimitError

DOMAIN = "example.com"


async def _fake_postmark_get(path, _token):
    if path.startswith("/domains"):
        return {
            "Domains": [
                {
                    "ID": 123,
                    "Name": DOMAIN,
                    "DKIMVerified": True,
                    "ReturnPathDomainVerified": True,
                    "DKIMPendingHost": "pm._domainkey.example.com",
                    "DKIMPendingTextValue": "k=rsa; p=abc",
                    "ReturnPathDomain": "pm-bounces.example.com",
                    "ReturnPathDomainCNAMEValue": "pm.mtasv.net",
                }
            ]
        }
    if path.startswith("/senders"):
        return {
            "SenderSignatures": [
                {
                    "ID": 456,
                    "EmailAddress": "billing@pending.example",
                    "Confirmed": False,
                    "Domain": "pending.example",
                    "DKIMHost": "pm._domainkey.pending.example",
                    "DKIMTextValue": "k=rsa; p=pending",
                }
            ]
        }
    return {}


def test_postmark_token_uses_secret_setting(db_session):
    db_session.add(
        Setting(
            key="postmark.account_token",
            value="encrypted-token",
            category="postmark",
        )
    )
    db_session.commit()

    with patch("app.services.mail_service_imports.decrypt_secret", return_value="token"):
        assert mail_service_imports.get_postmark_account_token(db_session) == "token"


def test_postmark_token_falls_back_to_environment(db_session):
    class FakeSettings:
        POSTMARK_ACCOUNT_TOKEN = "env-token"

    with patch("app.services.mail_service_imports.get_settings", return_value=FakeSettings()):
        assert mail_service_imports.get_postmark_account_token(db_session) == "env-token"


def test_mail_service_helpers_handle_empty_values(db_session):
    assert mail_service_imports._domain_from_email(None) is None
    assert mail_service_imports._domain_from_email("not-an-email") is None
    assert mail_service_imports._verification_state(False, False) == "pending"
    assert not mail_service_imports._postmark_domain_records({})
    assert not mail_service_imports.mail_service_context_from_domain(None)
    assert not mail_service_imports.mail_service_context_from_domain(
        Domain(name="plain.example", description="plain domain")
    )
    assert mail_service_imports._existing_domain_names(db_session, []) == set()


def test_postmark_get_success_and_json_error(monkeypatch):
    class FakeResponse:
        def __init__(self, fail_json=False):
            self.fail_json = fail_json

        def raise_for_status(self):
            return None

        def json(self):
            if self.fail_json:
                raise ValueError("bad json")
            return {"ok": True}

    class FakeClient:
        fail_json = False

        def __init__(self, timeout):
            self.timeout = timeout

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def get(self, url, headers):
            assert url.endswith("/domains")
            assert headers["X-Postmark-Account-Token"] == "token"
            return FakeResponse(fail_json=self.fail_json)

    monkeypatch.setattr(mail_service_imports.httpx, "AsyncClient", FakeClient)
    assert asyncio.run(mail_service_imports._postmark_get("/domains", "token")) == {"ok": True}

    FakeClient.fail_json = True
    with pytest.raises(MailServiceImportError, match="Postmark discovery failed"):
        asyncio.run(mail_service_imports._postmark_get("/domains", "token"))


def test_postmark_discovery_requires_token(db_session):
    with patch("app.services.mail_service_imports.get_postmark_account_token", return_value=None):
        with pytest.raises(LookupError, match="Postmark account token is not configured"):
            asyncio.run(mail_service_imports.discover_postmark_sender_domains(db_session))


def test_postmark_discovery_skips_empty_items_and_merges_sender_state(db_session):
    async def fake_postmark_get(path, _token):
        if path.startswith("/domains"):
            return {
                "Domains": [
                    {"ID": 0, "Name": ""},
                    {"ID": 1, "Name": "merge.example", "DKIMVerified": False},
                ]
            }
        if path.startswith("/senders"):
            return {
                "SenderSignatures": [
                    {"ID": 0, "Confirmed": True},
                    {
                        "ID": 2,
                        "EmailAddress": "sender@merge.example",
                        "Confirmed": True,
                        "DKIMHost": "pm._domainkey.merge.example",
                        "DKIMTextValue": "k=rsa; p=merge",
                    },
                ]
            }
        return {}

    with (
        patch("app.services.mail_service_imports.get_postmark_account_token", return_value="token"),
        patch("app.services.mail_service_imports._postmark_get", new=fake_postmark_get),
    ):
        result = asyncio.run(mail_service_imports.discover_postmark_sender_domains(db_session))

    assert len(result) == 1
    assert result[0]["domain"] == "merge.example"
    assert result[0]["verification_state"] == "verified"
    assert result[0]["required_dns_records"][0]["purpose"] == "dkim"


def test_postmark_import_preview_paginates_sender_domains(db_session):
    async def fake_postmark_get(path, _token):
        if path == "/domains?count=500&offset=0":
            return {
                "TotalCount": 2,
                "Domains": [
                    {"ID": 1, "Name": "one.example", "DKIMVerified": True},
                ],
            }
        if path == "/domains?count=500&offset=1":
            return {
                "TotalCount": 2,
                "Domains": [
                    {"ID": 2, "Name": "two.example", "DKIMVerified": True},
                ],
            }
        if path == "/senders?count=500&offset=0":
            return {"TotalCount": 0, "SenderSignatures": []}
        return {}

    with (
        patch("app.services.mail_service_imports.get_postmark_account_token", return_value="token"),
        patch("app.services.mail_service_imports._postmark_get", new=fake_postmark_get),
    ):
        result = asyncio.run(
            mail_service_imports.preview_mail_service_import(db_session, provider="postmark")
        )

    assert [item["domain"] for item in result["domains"]] == ["one.example", "two.example"]


def test_postmark_import_preview_preserves_false_verification(db_session):
    async def fake_postmark_get(path, _token):
        if path.startswith("/domains"):
            return {
                "Domains": [
                    {
                        "ID": 1,
                        "Name": "partial.example",
                        "DKIMVerified": True,
                        "ReturnPathDomainVerified": False,
                        "SPFVerified": True,
                    }
                ]
            }
        if path.startswith("/senders"):
            return {"SenderSignatures": []}
        return {}

    with (
        patch("app.services.mail_service_imports.get_postmark_account_token", return_value="token"),
        patch("app.services.mail_service_imports._postmark_get", new=fake_postmark_get),
    ):
        result = asyncio.run(
            mail_service_imports.preview_mail_service_import(db_session, provider="postmark")
        )

    assert result["domains"][0]["verification_state"] == "partial"


def test_postmark_import_preview_returns_sender_domains(db_session):
    db_session.add(
        Domain(
            name=DOMAIN,
            active=True,
            verified=True,
        )
    )
    db_session.commit()

    with (
        patch("app.services.mail_service_imports.get_postmark_account_token", return_value="token"),
        patch("app.services.mail_service_imports._postmark_get", new=_fake_postmark_get),
    ):
        result = asyncio.run(
            mail_service_imports.preview_mail_service_import(db_session, provider="postmark")
        )

    assert result["provider"] == "postmark"
    assert result["provider_name"] == "Postmark"
    assert result["total_discovered"] == 2
    assert result["importable_count"] == 1
    imported = next(item for item in result["domains"] if item["domain"] == DOMAIN)
    pending = next(item for item in result["domains"] if item["domain"] == "pending.example")
    assert imported["verification_state"] == "verified"
    assert imported["imported"] is True
    assert imported["required_dns_records"][0]["purpose"] == "dkim"
    assert pending["verification_state"] == "pending"
    assert pending["required_dns_records"][0]["name"] == "pm._domainkey.pending.example"


def test_postmark_import_creates_domain_with_context(db_session):
    async def fake_discover(_db, **_kwargs):
        return [
            {
                "provider": "postmark",
                "provider_name": "Postmark",
                "external_id": "domain-1",
                "domain": "new.example",
                "verification_state": "verified",
                "required_dns_records": [],
                "imported": False,
            }
        ]

    with patch(
        "app.services.mail_service_imports.discover_postmark_sender_domains",
        new=fake_discover,
    ):
        first = asyncio.run(
            mail_service_imports.import_mail_service_domains(
                db_session,
                provider="postmark",
                requested_domains=["new.example"],
            )
        )
        second = asyncio.run(
            mail_service_imports.import_mail_service_domains(
                db_session,
                provider="postmark",
                requested_domains=["new.example"],
            )
        )

    domain = db_session.query(Domain).filter(Domain.name == "new.example").one()
    context = mail_service_imports.mail_service_context_from_domain(domain)
    assert first["imported"] == ["new.example"]
    assert second["existing"] == ["new.example"]
    assert domain.verified is True
    assert "Postmark (verified)" in domain.description
    assert context[0]["provider_name"] == "Postmark"
    assert context[0]["verification_state"] == "verified"


def test_mail_service_import_rejects_unsupported_provider(db_session):
    with pytest.raises(LookupError, match="Unsupported mail service import"):
        asyncio.run(
            mail_service_imports.preview_mail_service_import(db_session, provider="sendgrid")
        )


def test_mail_service_import_treats_existing_global_domain_as_existing(db_session):
    db_session.add(Domain(name="shared.example", active=True, verified=True))
    db_session.commit()

    async def fake_discover(_db, **_kwargs):
        return [
            {
                "provider": "postmark",
                "provider_name": "Postmark",
                "external_id": "domain-1",
                "domain": "shared.example",
                "verification_state": "verified",
                "required_dns_records": [],
                "imported": False,
            }
        ]

    with patch(
        "app.services.mail_service_imports.discover_postmark_sender_domains",
        new=fake_discover,
    ):
        result = asyncio.run(
            mail_service_imports.import_mail_service_domains(
                db_session,
                provider="postmark",
                requested_domains=["shared.example"],
                workspace_id=12345,
            )
        )

    assert result["imported"] == []
    assert result["existing"] == ["shared.example"]
    assert db_session.query(Domain).filter(Domain.name == "shared.example").count() == 1


def test_create_imported_domain_handles_unique_race(db_session):
    db_session.add(Domain(name="race.example", active=True, verified=True))
    db_session.commit()

    result = mail_service_imports._create_imported_domain(
        db_session,
        name="race.example",
        provider_name="Postmark",
        state="verified",
        workspace_id=1,
    )

    assert result == "existing"


def test_mail_service_import_skips_unrequested_domains(db_session):
    async def fake_discover(_db, **_kwargs):
        return [
            {
                "provider": "postmark",
                "provider_name": "Postmark",
                "external_id": "domain-1",
                "domain": "wanted.example",
                "verification_state": "verified",
                "required_dns_records": [],
                "imported": False,
            },
            {
                "provider": "postmark",
                "provider_name": "Postmark",
                "external_id": "domain-2",
                "domain": "skipped.example",
                "verification_state": "verified",
                "required_dns_records": [],
                "imported": False,
            },
        ]

    with patch(
        "app.services.mail_service_imports.discover_postmark_sender_domains",
        new=fake_discover,
    ):
        result = asyncio.run(
            mail_service_imports.import_mail_service_domains(
                db_session,
                provider="postmark",
                requested_domains=["wanted.example"],
            )
        )

    assert result["imported"] == ["wanted.example"]
    assert result["skipped"] == ["skipped.example"]


def test_mail_service_import_provider_list_endpoint(authed_client: TestClient):
    response = authed_client.get("/api/v1/domains/mail-services/import/providers")

    assert response.status_code == 200
    assert response.json()["providers"] == [{"id": "postmark", "name": "Postmark"}]


def test_mail_service_import_endpoint_rejects_unsupported_provider(authed_client: TestClient):
    with patch(
        "app.api.api_v1.endpoints.domains.preview_mail_service_import",
        new=AsyncMock(side_effect=LookupError("Unsupported mail service import: sendgrid")),
    ):
        response = authed_client.get("/api/v1/domains/mail-services/import/sendgrid/preview")

    assert response.status_code == 400
    assert response.json()["detail"] == "Unsupported mail service import: sendgrid"


def test_mail_service_import_endpoint_returns_preview(authed_client: TestClient):
    with patch(
        "app.api.api_v1.endpoints.domains.preview_mail_service_import",
        new=AsyncMock(
            return_value={
                "provider": "postmark",
                "provider_name": "Postmark",
                "domains": [
                    {
                        "provider": "postmark",
                        "provider_name": "Postmark",
                        "external_id": "domain-1",
                        "domain": DOMAIN,
                        "verification_state": "verified",
                        "imported": False,
                        "importable": True,
                        "required_dns_records": [
                            {
                                "record_type": "TXT",
                                "name": "pm._domainkey.example.com",
                                "value": "k=rsa; p=abc",
                                "purpose": "dkim",
                            }
                        ],
                        "source": "mail_service_sender",
                        "next_action": "Import this Postmark sender domain.",
                    }
                ],
                "total_discovered": 1,
                "importable_count": 1,
            }
        ),
    ):
        response = authed_client.get("/api/v1/domains/mail-services/import/postmark/preview")

    assert response.status_code == 200
    data = response.json()
    assert data["provider"] == "postmark"
    assert data["domains"][0]["domain"] == DOMAIN
    assert data["domains"][0]["required_dns_records"][0]["purpose"] == "dkim"


def test_mail_service_import_endpoint_returns_import_summary(authed_client: TestClient):
    with patch(
        "app.api.api_v1.endpoints.domains.import_mail_service_domains",
        new=AsyncMock(
            return_value={
                "provider": "postmark",
                "provider_name": "Postmark",
                "imported": [DOMAIN],
                "existing": [],
                "skipped": [],
                "total_discovered": 1,
            }
        ),
    ):
        response = authed_client.post(
            "/api/v1/domains/mail-services/import/postmark",
            json={"domains": [DOMAIN]},
        )

    assert response.status_code == 200
    assert response.json()["imported"] == [DOMAIN]


def test_mail_service_import_endpoint_maps_provider_errors(authed_client: TestClient):
    with patch(
        "app.api.api_v1.endpoints.domains.preview_mail_service_import",
        new=AsyncMock(side_effect=MailServiceImportError("Postmark discovery failed: timeout")),
    ):
        response = authed_client.get("/api/v1/domains/mail-services/import/postmark/preview")

    assert response.status_code == 502
    assert response.json()["detail"] == "Postmark discovery failed: timeout"


def test_mail_service_import_endpoint_maps_import_provider_errors(authed_client: TestClient):
    with patch(
        "app.api.api_v1.endpoints.domains.import_mail_service_domains",
        new=AsyncMock(side_effect=MailServiceImportError("Postmark discovery failed: timeout")),
    ):
        response = authed_client.post(
            "/api/v1/domains/mail-services/import/postmark",
            json={"domains": [DOMAIN]},
        )

    assert response.status_code == 502
    assert response.json()["detail"] == "Postmark discovery failed: timeout"


def test_mail_service_import_endpoint_rejects_unsupported_import_provider(
    authed_client: TestClient,
):
    with patch(
        "app.api.api_v1.endpoints.domains.import_mail_service_domains",
        new=AsyncMock(side_effect=LookupError("Unsupported mail service import: sendgrid")),
    ):
        response = authed_client.post(
            "/api/v1/domains/mail-services/import/sendgrid",
            json={"domains": [DOMAIN]},
        )

    assert response.status_code == 400
    assert response.json()["detail"] == "Unsupported mail service import: sendgrid"


def test_mail_service_import_endpoint_maps_plan_limits(authed_client: TestClient):
    error = OrganizationPlanLimitError(
        metric="monitored_domains",
        current=1,
        limit=1,
        attempted=1,
        unit="domains",
        entitlement_key="limits.monitored_domains",
    )
    with patch(
        "app.api.api_v1.endpoints.domains.import_mail_service_domains",
        new=AsyncMock(side_effect=error),
    ):
        response = authed_client.post(
            "/api/v1/domains/mail-services/import/postmark",
            json={"domains": [DOMAIN]},
        )

    assert response.status_code == 402
    assert response.json()["detail"]["code"] == "plan_limit_exceeded"


def test_domain_response_includes_mail_service_context(
    authed_client: TestClient,
    db_session,
):
    db_session.add(
        Domain(
            name=DOMAIN,
            description=(
                "Mail-service sender domain imported from Postmark (verified). "
                "DNS records are still linted and repaired in DMARQ."
            ),
            active=True,
            verified=True,
        )
    )
    db_session.commit()

    response = authed_client.get(f"/api/v1/domains/domains/{DOMAIN}")

    assert response.status_code == 200
    context = response.json()["mail_service_context"]
    assert context[0]["provider_name"] == "Postmark"
    assert context[0]["verification_state"] == "verified"


def test_postmark_account_token_is_redacted(authed_client: TestClient, db_session):
    db_session.add(
        Setting(
            key="postmark.account_token",
            value="raw-token",
            category="postmark",
        )
    )
    db_session.commit()

    response = authed_client.get("/api/v1/settings?category=postmark")

    assert response.status_code == 200
    assert response.json()[0]["value"] == "**redacted**"
