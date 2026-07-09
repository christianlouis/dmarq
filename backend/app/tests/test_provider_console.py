"""Product-backed provider console and support-session integration tests."""

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.health_score_snapshot import HealthScoreSnapshot
from app.models.mail_source import MailSource
from app.models.organization import Plan, Subscription
from app.models.report import DMARCReport
from app.models.user import User
from app.models.workspace import Workspace
from app.models.workspace_access import WorkspaceAuditLog, WorkspaceMembership
from app.services.demo_provider_seed import seed_demo_provider_database
from app.services.provider_access import require_provider_operator_access
from app.services.provider_console import build_provider_console
from app.services.provider_plans import ensure_default_provider_plans
from app.services.support_sessions import SUPPORT_SESSION_COOKIE, create_support_session_token


def _seeded_lawfirm(db: Session) -> tuple[Workspace, User, WorkspaceMembership, Subscription]:
    seed_demo_provider_database(db)
    workspace = db.query(Workspace).filter(Workspace.slug == "lawfirm-example").one()
    user = db.query(User).filter(User.email == "admin@lawfirm.example").one()
    membership = (
        db.query(WorkspaceMembership)
        .filter(
            WorkspaceMembership.workspace_id == workspace.id,
            WorkspaceMembership.user_id == user.id,
        )
        .one()
    )
    subscription = (
        db.query(Subscription)
        .filter(Subscription.organization_id == workspace.organization_id)
        .one()
    )
    return workspace, user, membership, subscription


def test_provider_demo_seed_is_idempotent_and_builds_console(db_session: Session):
    first = seed_demo_provider_database(db_session)
    second = seed_demo_provider_database(db_session)

    assert (
        first
        == second
        == {
            "accounts": 6,
            "plans": 3,
            "domains": 9,
            "users": 17,
            "reports": 27,
        }
    )
    assert db_session.query(DMARCReport).count() == 27
    assert db_session.query(HealthScoreSnapshot).count() == 9 * 14
    assert db_session.query(MailSource).count() == 6

    console = build_provider_console(db_session, demo_mode=True)
    assert console["source"] == "provider_accounts_db_v1"
    assert console["summary"]["accounts"] == 6
    assert console["summary"]["domains"] == 9
    assert console["support_access_demo"]["mode"] == "audited_workspace_session"

    lawfirm = next(
        account for account in console["accounts"] if account["slug"] == "lawfirm-example"
    )
    assert lawfirm["plan_label"] == "DMARQ Protect Plus"
    assert lawfirm["usage"]["messages_30d"] == sum(
        domain["messages_30d"] for domain in lawfirm["domains"]
    )
    assert {domain["name"]: domain["policy"] for domain in lawfirm["domains"]} == {
        "lawfirm.example": "quarantine",
        "secure.lawfirm.example": "none",
    }
    assert len(lawfirm["users"]) == 3


def test_provider_operator_access_uses_explicit_email_allowlist(
    db_session: Session,
    monkeypatch,
):
    operator = User(
        email="operator@cklnet.com",
        full_name="CKLNet Site Manager",
        is_active=True,
        is_superuser=False,
    )
    outsider = User(
        email="owner@customer.example",
        full_name="Customer Owner",
        is_active=True,
        is_superuser=True,
    )
    db_session.add_all([operator, outsider])
    db_session.commit()
    settings = get_settings()
    monkeypatch.setattr(settings, "DEMO_MODE", False)
    monkeypatch.setattr(settings, "PROVIDER_DEMO_ENABLED", False)
    monkeypatch.setattr(settings, "PROVIDER_OPERATOR_EMAILS", "operator@cklnet.com")

    require_provider_operator_access(
        db_session,
        {"auth_type": "session", "user_id": operator.id},
    )
    with pytest.raises(HTTPException) as exc_info:
        require_provider_operator_access(
            db_session,
            {"auth_type": "session", "user_id": outsider.id},
        )
    assert exc_info.value.status_code == 403


def test_default_provider_plan_bootstrap_is_additive_and_idempotent(db_session: Session):
    custom = Plan(
        code="monitor",
        name="CKLNet Custom Monitor",
        billing_mode="provider_resale",
        active=True,
        monthly_price_cents=2300,
    )
    db_session.add(custom)
    db_session.commit()

    first = ensure_default_provider_plans(db_session)
    second = ensure_default_provider_plans(db_session)

    assert first == {"created": 2, "available": 3}
    assert second == {"created": 0, "available": 3}
    assert (
        db_session.query(Plan).filter(Plan.code.in_(["monitor", "protect", "protect_plus"])).count()
        == 3
    )
    db_session.refresh(custom)
    assert custom.name == "CKLNet Custom Monitor"
    assert custom.monthly_price_cents == 2300


def test_read_only_support_session_scopes_normal_customer_apis(
    client: TestClient,
    db_session: Session,
):
    workspace, user, membership, subscription = _seeded_lawfirm(db_session)
    other_workspace = db_session.query(Workspace).filter(Workspace.slug == "bakery-example").one()
    token, _ = create_support_session_token(
        workspace_id=workspace.id,
        organization_id=workspace.organization_id,
        target_user_id=user.id,
        target_user_email=user.email,
        target_user_role=membership.role,
        operator={"id": "provider-operator", "name": "Provider Operator"},
        reason="Review the customer's DKIM incident",
        account_name=workspace.organization.name,
        customer_number="NS-10087",
        plan_code=subscription.plan.code,
        plan_label=subscription.plan.name,
        read_only=True,
    )
    client.cookies.set(SUPPORT_SESSION_COOKIE, token)

    me = client.get("/api/v1/auth/me")
    assert me.status_code == 200
    assert me.json()["email"] == "admin@lawfirm.example"
    assert me.json()["support_session"] is True

    workspaces = client.get("/api/v1/workspaces")
    assert workspaces.status_code == 200
    assert [row["slug"] for row in workspaces.json()["workspaces"]] == ["lawfirm-example"]

    domains = client.get(
        "/api/v1/domains/summary",
        headers={"X-DMARQ-Workspace-ID": str(other_workspace.id)},
    )
    assert domains.status_code == 200
    assert {row["domain_name"] for row in domains.json()["domains"]} == {
        "lawfirm.example",
        "secure.lawfirm.example",
    }

    members = client.get(f"/api/v1/memberships/workspaces/{workspace.id}?include_inactive=true")
    assert members.status_code == 200
    assert len(members.json()["memberships"]) == 4

    mutation = client.post(
        f"/api/v1/memberships/workspaces/{workspace.id}/invites",
        json={"email": "blocked@lawfirm.example", "role": "analyst"},
    )
    assert mutation.status_code == 403
    assert mutation.json()["detail"] == "This support session is read-only"

    forensic = client.get("/api/v1/forensics")
    tls = client.get("/api/v1/tls-reports")
    mail_sources = client.get("/api/v1/mail-sources")
    assert forensic.status_code == 200 and forensic.json()["total"] == 0
    assert tls.status_code == 200 and tls.json()["total"] == 0
    assert mail_sources.status_code == 200
    assert [row["name"] for row in mail_sources.json()] == ["Provider report inbox"]


def test_operator_can_start_and_end_audited_role_scoped_session(
    authed_client: TestClient,
    db_session: Session,
):
    workspace, user, _, _ = _seeded_lawfirm(db_session)

    started = authed_client.post(
        "/api/v1/operator/support-session",
        json={
            "workspace_id": workspace.id,
            "target_user_id": user.id,
            "reason": "Investigate a customer authentication incident",
            "access_mode": "role_scoped",
        },
    )

    assert started.status_code == 200
    assert started.json()["session"]["read_only"] is False
    assert SUPPORT_SESSION_COOKIE in started.cookies
    assert (
        db_session.query(WorkspaceAuditLog)
        .filter(WorkspaceAuditLog.action == "support_session.started")
        .count()
        == 1
    )

    current = authed_client.get("/api/v1/operator/support-session")
    assert current.status_code == 200
    assert current.json()["active"] is True

    ended = authed_client.delete("/api/v1/operator/support-session")
    assert ended.status_code == 200
    assert ended.json()["active"] is False
    assert (
        db_session.query(WorkspaceAuditLog)
        .filter(WorkspaceAuditLog.action == "support_session.ended")
        .count()
        == 1
    )
