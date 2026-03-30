import os
from typing import AsyncGenerator, Generator
from urllib.parse import urlparse, urlunparse

from sqlalchemy import create_engine
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from app.core.config import get_settings

_ASYNC_TO_SYNC_SCHEMES = {
    "postgresql+asyncpg": "postgresql+psycopg2",
}


def _make_sync_db_url(url: str) -> str:
    """Return the synchronous-driver equivalent of *url*.

    Kubernetes and docker-compose deployments sometimes configure DATABASE_URL
    with an async driver scheme (e.g. ``postgresql+asyncpg://``).  Alembic and
    the synchronous SQLAlchemy engine used here require a sync driver, so we
    map known async schemes to their psycopg2 equivalents.

    Only the scheme component of the URL is rewritten; all other parts
    (credentials, host, path, query) are left untouched.
    """
    parsed = urlparse(url)
    sync_scheme = _ASYNC_TO_SYNC_SCHEMES.get(parsed.scheme)
    if sync_scheme is None:
        return url
    return urlunparse(parsed._replace(scheme=sync_scheme))


def _ensure_sqlite_dir(url: str) -> None:
    """Create the parent directory for a SQLite database file if needed.

    For SQLite URLs (``sqlite:///relative/path`` or ``sqlite:////absolute/path``),
    the parent directory must exist before SQLAlchemy tries to open (or create)
    the file.  This is a no-op for in-memory databases (``sqlite://``) and for
    non-SQLite URLs.
    """
    sa_url = make_url(url)
    if not sa_url.drivername.startswith("sqlite"):
        return
    db_path = sa_url.database
    if not db_path or db_path == ":memory:":
        return  # in-memory – nothing to create
    parent = os.path.dirname(db_path)
    if parent:
        os.makedirs(parent, exist_ok=True)


settings = get_settings()

_sync_url = _make_sync_db_url(settings.DATABASE_URL)

# Ensure the parent directory exists before SQLAlchemy tries to open the file
_ensure_sqlite_dir(_sync_url)

# Configure SQLAlchemy (normalise async driver schemes to their sync equivalents)
engine = create_engine(_sync_url, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create base class for SQLAlchemy models
Base = declarative_base()


def get_db() -> Generator:
    """
    Dependency for getting DB sessions
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
