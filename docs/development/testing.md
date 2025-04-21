# Testing

This guide covers the testing methodology for DMARQ, including unit tests, integration tests, and end-to-end testing.

## Testing Philosophy

DMARQ follows a comprehensive testing approach to ensure reliability:

- **Unit Tests**: Test individual functions and classes in isolation
- **Integration Tests**: Test components working together
- **End-to-End Tests**: Test the complete application flow
- **Performance Tests**: Ensure the system can handle expected load

## Test Structure

The test directory structure follows the application structure:

```
backend/app/tests/
├── conftest.py              # Pytest fixtures and configuration
├── test_api.py              # API endpoint tests
├── test_dmarc_parser.py     # DMARC parser tests
├── test_models.py           # Database model tests
├── test_reports_api.py      # Reports API tests
├── unit/                    # Unit tests
│   ├── test_domain_validator.py
│   ├── test_utils.py
│   └── ...
├── integration/             # Integration tests
│   ├── test_database.py
│   ├── test_imap.py
│   └── ...
└── e2e/                     # End-to-end tests
    ├── test_report_flow.py
    └── ...
```

## Setting Up the Test Environment

### Prerequisites

- Python 3.9+
- pytest and required plugins

### Installation

```bash
cd backend
pip install -r requirements-dev.txt
```

This will install:
- pytest
- pytest-cov (for coverage reports)
- pytest-mock (for mocking)
- pytest-asyncio (for async tests)

## Running Tests

### All Tests

To run all tests:

```bash
cd backend
pytest
```

### Specific Tests

To run specific test files:

```bash
pytest tests/test_dmarc_parser.py
```

To run tests matching a pattern:

```bash
pytest -k "parser"  # Runs tests with "parser" in the name
```

### Test Coverage

To generate a coverage report:

```bash
pytest --cov=app
```

For an HTML coverage report:

```bash
pytest --cov=app --cov-report=html
```

Then open `htmlcov/index.html` to view the report.

## Writing Tests

### Fixtures

We use pytest fixtures for test setup and teardown. Common fixtures are defined in `conftest.py`:

```python
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.models.base import Base
from app.core.database import get_db

@pytest.fixture
def db_engine():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return engine

@pytest.fixture
def db_session(db_engine):
    Session = sessionmaker(bind=db_engine)
    session = Session()
    yield session
    session.close()

@pytest.fixture
def test_app(db_session):
    from app.main import app
    app.dependency_overrides[get_db] = lambda: db_session
    return app
```

### Unit Tests

Unit tests should focus on testing a single function or class in isolation, using mocks for dependencies:

```python
from app.utils.domain_validator import is_valid_domain
import pytest

def test_is_valid_domain():
    # Valid domains
    assert is_valid_domain("example.com") is True
    assert is_valid_domain("sub.example.com") is True
    
    # Invalid domains
    assert is_valid_domain("invalid..com") is False
    assert is_valid_domain("a" * 300 + ".com") is False
```

### API Tests

API tests use the FastAPI TestClient:

```python
from fastapi.testclient import TestClient

def test_get_domains(test_app, db_session):
    # Add test data to db_session
    # ...
    
    client = TestClient(test_app)
    response = client.get("/api/v1/domains")
    assert response.status_code == 200
    data = response.json()
    assert len(data["domains"]) == 2  # Assuming 2 domains were added
```

### Mocking

We use pytest-mock for mocking:

```python
def test_imap_client(mocker):
    # Mock the imaplib.IMAP4_SSL class
    mock_imap = mocker.patch("imaplib.IMAP4_SSL")
    mock_imap.return_value.login.return_value = ("OK", [])
    mock_imap.return_value.select.return_value = ("OK", [b"10"])
    
    from app.services.imap_client import IMAPClient
    client = IMAPClient("imap.example.com", "user", "pass")
    result = client.connect()
    
    assert result is True
    mock_imap.return_value.login.assert_called_once()
```

### Testing Async Code

For async functions, use pytest-asyncio:

```python
import pytest

@pytest.mark.asyncio
async def test_async_function():
    from app.services.report_processor import process_report_async
    result = await process_report_async("test_data")
    assert result is not None
```

## Testing Database Models

When testing database models, use an in-memory SQLite database:

```python
def test_domain_model(db_session):
    from app.models.domain import Domain
    
    domain = Domain(name="example.com")
    db_session.add(domain)
    db_session.commit()
    
    fetched = db_session.query(Domain).filter_by(name="example.com").first()
    assert fetched is not None
    assert fetched.name == "example.com"
```

## Test Data

### Sample Files

Sample DMARC report files for testing are stored in:
```
backend/app/tests/data/
```

These include:
- Sample XML reports
- Compressed reports (ZIP, GZ)
- Invalid reports for error testing

### Factories

For generating test data, we use factory_boy:

```python
import factory
from app.models.domain import Domain
from app.models.report import Report

class DomainFactory(factory.Factory):
    class Meta:
        model = Domain
    
    name = factory.Sequence(lambda n: f"domain-{n}.com")
    active = True

class ReportFactory(factory.Factory):
    class Meta:
        model = Report
    
    domain = factory.SubFactory(DomainFactory)
    report_id = factory.Sequence(lambda n: f"report-{n}")
    begin_date = factory.LazyFunction(lambda: datetime.now() - timedelta(days=1))
    end_date = factory.LazyFunction(lambda: datetime.now())
    org_name = "test-org"
```

## Continuous Integration

Tests are automatically run on every pull request using GitHub Actions.

The CI workflow:
1. Sets up the test environment
2. Runs linting checks
3. Runs the test suite
4. Generates coverage reports
5. Reports test results

## Performance Testing

For performance testing, we use Locust:

```bash
cd backend/performance_tests
locust -f locustfile.py
```

This starts a web interface at http://localhost:8089 to configure and run performance tests.

## Debugging Tests

When tests fail, you can use pytest's verbose mode for more details:

```bash
pytest -vv
```

For even more information, add the `-s` flag to show print statements:

```bash
pytest -vvs
```

## Writing Testable Code

To make testing easier:

1. **Dependency Injection**: Pass dependencies rather than creating them inside functions
2. **Single Responsibility**: Keep functions focused on a single task
3. **Pure Functions**: When possible, write pure functions that don't modify state
4. **Testable Units**: Structure code in small, testable units
5. **Configuration**: Make configuration injectable for tests

## Code Coverage Goals

Our coverage goals are:
- Overall coverage: 80%+
- Core modules: 90%+
- API endpoints: 100%

## Reporting Bugs

If you find a bug:
1. Write a failing test that reproduces the issue
2. File an issue describing the bug
3. Link the failing test in the issue
4. If possible, submit a PR with a fix