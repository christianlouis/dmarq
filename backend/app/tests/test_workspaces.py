from contextlib import contextmanager

from fastapi.testclient import TestClient
from sqlalchemy import event
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import require_admin_auth
from app.models.domain import Domain
from app.models.mail_source import MailSource
from app.models.user import User
from app.models.workspace import Workspace
from app.models.workspace_access import WorkspaceMembership
from app.services.workspace_access import ROLE_ANALYST
from app.services.workspaces import (
    DEFAULT_WORKSPACE_SLUG,
    assign_default_workspace_to_unscoped_rows,
    get_or_create_default_workspace,
    normalize_workspace_slug,
    resolve_workspace,
    workspace_domain_query,
    workspace_mail_source_query,
    workspace_user_query,
)


@contextmanager
def _client_as_user(test_app, db_session: Session, user: User):
    async def mock_admin_auth():
        return {"auth_type": "session", "user_id": user.id}

    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    original_overrides = dict(test_app.dependency_overrides)
    test_app.dependency_overrides[get_db] = override_get_db
    test_app.dependency_overrides[require_admin_auth] = mock_admin_auth
    try:
        with TestClient(test_app) as client:
            yield client
    finally:
        test_app.dependency_overrides = original_overrides


def test_default_workspace_claims_legacy_rows(db_session: Session):
    """Existing single-tenant rows are attached to the default workspace."""
    domain = Domain(name="legacy.example", active=True)
    source = MailSource(name="Legacy inbox", method="IMAP", enabled=True)
    user = User(email="operator@example.com")
    db_session.add_all([domain, source, user])
    db_session.commit()

    workspace = assign_default_workspace_to_unscoped_rows(db_session)

    db_session.refresh(domain)
    db_session.refresh(source)
    db_session.refresh(user)
    assert workspace.slug == DEFAULT_WORKSPACE_SLUG
    assert domain.workspace_id == workspace.id
    assert source.workspace_id == workspace.id
    assert user.workspace_id == workspace.id


def test_default_workspace_assignment_is_read_only_without_legacy_rows(db_session: Session):
    """Normal workspace resolution must not contend with an active SQLite writer."""
    workspace = get_or_create_default_workspace(db_session)
    db_session.add_all(
        [
            Domain(name="scoped.example", workspace_id=workspace.id, active=True),
            MailSource(name="Scoped inbox", method="IMAP", workspace_id=workspace.id),
            User(email="scoped@example.com", workspace_id=workspace.id),
        ]
    )
    db_session.commit()
    statements = []

    def _record_statement(*args):
        statements.append(args[2])

    event.listen(db_session.bind, "before_cursor_execute", _record_statement)
    try:
        resolved = assign_default_workspace_to_unscoped_rows(db_session)
    finally:
        event.remove(db_session.bind, "before_cursor_execute", _record_statement)

    assert resolved.id == workspace.id
    assert not any(statement.lstrip().upper().startswith("UPDATE") for statement in statements)


def test_workspace_scoped_queries_exclude_other_tenants(db_session: Session):
    """Default scoped queries only return rows owned by that workspace."""
    default = get_or_create_default_workspace(db_session)
    other = Workspace(slug="client-two", name="Client Two", active=True)
    db_session.add(other)
    db_session.flush()
    db_session.add_all(
        [
            Domain(name="default.example", workspace_id=default.id, active=True),
            Domain(name="client-two.example", workspace_id=other.id, active=True),
            MailSource(name="default inbox", method="IMAP", workspace_id=default.id),
            MailSource(name="client two inbox", method="IMAP", workspace_id=other.id),
            User(email="default@example.com", workspace_id=default.id),
            User(email="client-two@example.com", workspace_id=other.id),
        ]
    )
    db_session.commit()

    assert [row.name for row in workspace_domain_query(db_session, default).all()] == [
        "default.example"
    ]
    assert [row.name for row in workspace_mail_source_query(db_session, default).all()] == [
        "default inbox"
    ]
    assert [row.email for row in workspace_user_query(db_session, default).all()] == [
        "default@example.com"
    ]


def test_workspace_resolution_and_slug_validation(db_session: Session):
    """Workspace lookup supports default, id, and normalized slug paths."""
    default = resolve_workspace(db_session)
    other = Workspace(slug="client-two", name="Client Two", active=True)
    db_session.add(other)
    db_session.commit()
    db_session.refresh(other)

    assert normalize_workspace_slug(" Client Two!! ") == "client-two"
    assert resolve_workspace(db_session).id == default.id
    assert resolve_workspace(db_session, workspace_id=other.id).id == other.id
    assert resolve_workspace(db_session, slug="Client Two").id == other.id


def test_domain_api_defaults_to_default_workspace(
    authed_client: TestClient,
    db_session: Session,
):
    """Domain API creates and lists rows inside the default workspace boundary."""
    other = Workspace(slug="client-two", name="Client Two", active=True)
    db_session.add(other)
    db_session.flush()
    db_session.add(Domain(name="other.example", workspace_id=other.id, active=True))
    db_session.commit()

    created = authed_client.post(
        "/api/v1/domains/domains",
        json={"name": "Default.Example", "description": "Default tenant"},
    )
    assert created.status_code == 201

    workspace = get_or_create_default_workspace(db_session)
    domain = db_session.query(Domain).filter(Domain.name == "default.example").first()
    assert domain.workspace_id == workspace.id

    listed = authed_client.get("/api/v1/domains/domains")
    assert listed.status_code == 200
    names = {item["name"] for item in listed.json()}
    assert "default.example" in names
    assert "other.example" not in names


def test_domain_api_listing_respects_selected_workspace_header(
    authed_client: TestClient,
    db_session: Session,
):
    """Domain listing follows the UI-selected workspace instead of the default."""
    default = get_or_create_default_workspace(db_session)
    other = Workspace(slug="selected-client", name="Selected Client", active=True)
    db_session.add(other)
    db_session.flush()
    db_session.add_all(
        [
            Domain(name="default-list.example", workspace_id=default.id, active=True),
            Domain(name="selected-list.example", workspace_id=other.id, active=True),
        ]
    )
    db_session.commit()

    listed = authed_client.get(
        "/api/v1/domains/domains",
        headers={"X-DMARQ-Workspace-ID": str(other.id)},
    )

    assert listed.status_code == 200
    names = {item["name"] for item in listed.json()}
    assert names == {"selected-list.example"}


def test_domain_read_routes_enforce_workspace_membership(
    test_app,
    client: TestClient,
    db_session: Session,
):
    """Read-only domain surfaces allow analysts but reject unauthenticated callers."""
    workspace = get_or_create_default_workspace(db_session)
    domain = Domain(name="analyst.example", workspace_id=workspace.id, active=True)
    analyst = User(email="domain-analyst@example.com", is_active=True, is_verified=True)
    db_session.add_all([domain, analyst])
    db_session.flush()
    db_session.add(
        WorkspaceMembership(
            workspace_id=workspace.id,
            user_id=analyst.id,
            role=ROLE_ANALYST,
            active=True,
        )
    )
    db_session.commit()

    assert client.get("/api/v1/domains/domains").status_code == 401

    with _client_as_user(test_app, db_session, analyst) as user_client:
        listed = user_client.get("/api/v1/domains/domains")
        assert listed.status_code == 200
        assert {item["name"] for item in listed.json()} == {"analyst.example"}

        deleted = user_client.delete("/api/v1/domains/analyst.example")
        assert deleted.status_code == 403
