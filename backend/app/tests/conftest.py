import asyncio

import pytest
import pytest_asyncio
from app.core.database import Base, get_db
from app.core.security import get_password_hash
from app.models.user import User
from fastapi import FastAPI
from fastapi.testclient import TestClient
from httpx import AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Use in-memory SQLite database for tests
TEST_DATABASE_URL = "sqlite:///./test.db"


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for each test case."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
def test_app() -> FastAPI:
    # Avoid circular import
    from app.main import create_app

    app = create_app()
    return app


@pytest.fixture(scope="function")
def db_session():
    # Create the SQLite database engine
    engine = create_engine(TEST_DATABASE_URL)

    # Create all tables
    Base.metadata.create_all(engine)

    # Create a new session
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = TestingSessionLocal()

    try:
        yield db
    finally:
        db.close()
        # Drop all tables after the test
        Base.metadata.drop_all(engine)


@pytest.fixture(scope="function")
def client(test_app: FastAPI, db_session):
    # Override the get_db dependency to use the test database
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    test_app.dependency_overrides[get_db] = override_get_db

    # Use the FastAPI TestClient
    with TestClient(test_app) as test_client:
        yield test_client


@pytest_asyncio.fixture(scope="function")
async def async_client(test_app: FastAPI, db_session):
    # Override the get_db dependency to use the test database
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    test_app.dependency_overrides[get_db] = override_get_db

    async with AsyncClient(app=test_app, base_url="http://testserver") as ac:
        yield ac


@pytest.fixture(scope="function")
def test_user(db_session):
    """Create a test user in the database."""
    user = User(
        email="test@example.com",
        hashed_password=get_password_hash("password"),
        is_active=True,
        is_superuser=False,
        is_verified=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user
