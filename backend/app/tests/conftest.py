# Import all models so Base.metadata knows every table
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.models.domain  # noqa: F401  # pylint: disable=unused-import
import app.models.report  # noqa: F401  # pylint: disable=unused-import
import app.models.user  # noqa: F401  # pylint: disable=unused-import
from app.core.database import Base, get_db
from app.main import create_app
from app.services.report_store import ReportStore


@pytest.fixture()
def test_app() -> FastAPI:
    """Create a fresh FastAPI application instance for testing."""
    application = create_app()
    return application


@pytest.fixture()
def db_session():
    """Create a fresh in-memory SQLite database session per test."""
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False})
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
