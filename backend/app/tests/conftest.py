# Import all models so Base.metadata knows every table
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.models.domain  # noqa: F401  # pylint: disable=unused-import
import app.models.mail_source as _mail_source_model  # noqa: F401  # pylint: disable=unused-import
import app.models.report  # noqa: F401  # pylint: disable=unused-import
import app.models.setting  # noqa: F401  # pylint: disable=unused-import
import app.models.user  # noqa: F401  # pylint: disable=unused-import
from app.core.database import Base, get_db
from app.core.security import require_admin_auth
from app.main import create_app
from app.services.report_store import ReportStore


@pytest.fixture()
def test_app() -> FastAPI:
    """Create a fresh FastAPI application instance for testing."""
    application = create_app()
    return application


@pytest.fixture()
def db_session():
    """Create a fresh in-memory SQLite database session per test.

    ``StaticPool`` ensures every SQLAlchemy operation reuses the same
    underlying DBAPI connection so the in-memory database (and its tables)
    persist for the full duration of the test, even across commits.
    """
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(engine)
        engine.dispose()


@pytest.fixture()
def client(test_app: FastAPI, db_session):  # pylint: disable=redefined-outer-name
    """Create a TestClient with a DB override for the test app."""

    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    test_app.dependency_overrides[get_db] = override_get_db
    with TestClient(test_app) as test_client:
        yield test_client
    test_app.dependency_overrides.clear()


@pytest.fixture(autouse=True)
def _reset_report_store():
    """Reset the ReportStore singleton between tests to avoid state leakage."""
    store = ReportStore.get_instance()
    store.clear()
    yield
    store.clear()


@pytest.fixture()
def authed_client(test_app: FastAPI, db_session):  # pylint: disable=redefined-outer-name
    """
    TestClient with both DB and admin-auth dependency overrides.

    Bypasses ``require_admin_auth`` so tests can call admin-only endpoints
    without needing a real API key or JWT token.
    """

    async def mock_admin_auth():
        return {"auth_type": "api_key", "api_key": "test-key"}

    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    test_app.dependency_overrides[get_db] = override_get_db
    test_app.dependency_overrides[require_admin_auth] = mock_admin_auth
    with TestClient(test_app) as test_client:
        yield test_client
    test_app.dependency_overrides.clear()
