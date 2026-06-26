"""Workspace/tenant helpers for MSP mode foundations."""

from __future__ import annotations

from typing import Optional

from sqlalchemy.orm import Query, Session

from app.models.domain import Domain
from app.models.mail_source import MailSource
from app.models.user import User
from app.models.workspace import Workspace

DEFAULT_WORKSPACE_SLUG = "default"
DEFAULT_WORKSPACE_NAME = "Default Workspace"


def normalize_workspace_slug(value: str) -> str:
    """Normalize a workspace slug for stable lookups."""
    slug = (value or "").strip().lower()
    cleaned = []
    previous_dash = False
    for char in slug:
        if char.isalnum():
            cleaned.append(char)
            previous_dash = False
        elif not previous_dash:
            cleaned.append("-")
            previous_dash = True
    return "".join(cleaned).strip("-")


def get_or_create_default_workspace(db: Session, *, commit: bool = True) -> Workspace:
    """Return the single-tenant default workspace, creating it when needed."""
    workspace = db.query(Workspace).filter(Workspace.slug == DEFAULT_WORKSPACE_SLUG).first()
    if workspace:
        return workspace

    workspace = Workspace(
        slug=DEFAULT_WORKSPACE_SLUG,
        name=DEFAULT_WORKSPACE_NAME,
        description="Automatically created for existing single-tenant installs.",
        active=True,
    )
    db.add(workspace)
    if commit:
        db.commit()
        db.refresh(workspace)
    else:
        db.flush()
    return workspace


def get_default_workspace(db: Session) -> Optional[Workspace]:
    """Return the default workspace without creating or migrating data."""
    return (
        db.query(Workspace)
        .filter(Workspace.slug == DEFAULT_WORKSPACE_SLUG, Workspace.active.is_(True))
        .first()
    )


def assign_default_workspace_to_unscoped_rows(
    db: Session,
    *,
    commit: bool = True,
) -> Workspace:
    """Attach legacy unscoped rows to the default workspace."""
    workspace = get_or_create_default_workspace(db, commit=commit)
    for model in (Domain, MailSource, User):
        db.query(model).filter(model.workspace_id.is_(None)).update(
            {model.workspace_id: workspace.id},
            synchronize_session=False,
        )
    if commit:
        db.commit()
    else:
        db.flush()
    return workspace


def resolve_workspace(
    db: Session,
    *,
    workspace_id: Optional[int] = None,
    slug: Optional[str] = None,
) -> Workspace:
    """Resolve a workspace, defaulting to the single-tenant workspace."""
    if workspace_id is not None:
        workspace = (
            db.query(Workspace)
            .filter(Workspace.id == workspace_id, Workspace.active.is_(True))
            .first()
        )
        if workspace:
            return workspace
        raise ValueError("Workspace not found")

    if slug:
        normalized = normalize_workspace_slug(slug)
        workspace = (
            db.query(Workspace)
            .filter(Workspace.slug == normalized, Workspace.active.is_(True))
            .first()
        )
        if workspace:
            return workspace
        raise ValueError("Workspace not found")

    return assign_default_workspace_to_unscoped_rows(db)


def workspace_domain_query(db: Session, workspace: Workspace) -> Query:
    """Return the default scoped domain query for a workspace."""
    return db.query(Domain).filter(Domain.workspace_id == workspace.id)


def workspace_mail_source_query(db: Session, workspace: Workspace) -> Query:
    """Return the default scoped mail-source query for a workspace."""
    return db.query(MailSource).filter(MailSource.workspace_id == workspace.id)


def workspace_user_query(db: Session, workspace: Workspace) -> Query:
    """Return the default scoped user query for a workspace."""
    return db.query(User).filter(User.workspace_id == workspace.id)
