# Testing

This guide covers the testing methodology for DMARQ, including unit tests, integration tests, and how to run them.

## Testing Philosophy

DMARQ follows a practical testing approach:

- **Unit Tests**: Test individual functions and classes in isolation
- **Integration Tests**: Test API endpoints with the full FastAPI stack
- **Security Tests**: Verify security controls (input validation, XXE protection, API keys)

## Test Structure

```
backend/app/tests/
├── conftest.py              # Pytest fixtures (DB session, TestClient, ReportStore reset)
├── test_api.py              # API endpoint tests (health, domains, upload validation)
├── test_dmarc_parser.py     # DMARC XML/ZIP parser tests
├── test_models.py           # SQLAlchemy ORM model tests
├── test_report_store.py     # In-memory ReportStore tests
├── test_reports_api.py      # Reports upload and retrieval API tests
└── test_security.py         # Security: API keys, domain validation, XML security
```

## Setting Up the Test Environment

### Prerequisites

- Python 3.13+
- Dependencies from `backend/requirements.txt`

### Installation

```bash
cd backend
pip install -r requirements.txt
```

## Running Tests

### All Tests

```bash
cd backend
pytest
```

### With Coverage

```bash
pytest --cov=app --cov-report=term-missing
```

### Specific Test File

```bash
pytest app/tests/test_dmarc_parser.py
```

### Tests Matching a Pattern

```bash
pytest -k "parser"
```

### HTML Coverage Report

```bash
pytest --cov=app --cov-report=html
# Open htmlcov/index.html
```

## Key Fixtures (conftest.py)

| Fixture | Scope | Description |
|---------|-------|-------------|
| `test_app` | function | Fresh FastAPI application instance |
| `db_session` | function | In-memory SQLite session, tables created/dropped per test |
| `client` | function | `TestClient` wired to test DB |
| `_reset_report_store` | function (autouse) | Clears the `ReportStore` singleton between tests |

The `db_session` fixture uses `sqlite://` (true in-memory) so each test gets a clean database. All ORM models are imported in `conftest.py` to ensure `Base.metadata.create_all()` knows every table.

## Writing Tests

### Unit Tests (no fixtures needed)

```python
from app.utils.domain_validator import validate_domain

def test_valid_domain():
    is_valid, error, _ = validate_domain("example.com", check_dns=False)
    assert is_valid
```

### Model Tests (use `db_session`)

```python
from app.models.domain import Domain

def test_create_domain(db_session):
    domain = Domain(name="example.com", active=True)
    db_session.add(domain)
    db_session.commit()
    assert domain.id is not None
```

### API Tests (use `client`)

```python
def test_health_check(client):
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
```

## Linting Before Committing

Always run linting before committing:

```bash
black --check backend/app
isort --check-only backend/app
flake8 backend/app --max-line-length=100 --extend-ignore=E203,W503
```

Auto-fix formatting:

```bash
black backend/app
isort backend/app
```

## Code Coverage Goals

- Overall coverage: **80%+**
- Core modules: **90%+**
- New code should have **100%** branch coverage

## Continuous Integration

Tests run automatically on every push and PR via GitHub Actions
(`.github/workflows/ci.yml`).  See [CI/CD Pipeline](ci-cd.md) for a full
description of every stage.

The pipeline runs in four stages:

1. **Lint** (blocking gate) — Black, isort, Flake8, Pylint
2. **Parallel quality gates** — Test (pytest + Codecov), Security (Bandit + pip-audit),
   CodeQL analysis, and Dependency Review (PRs only)
3. **Docker** — builds and pushes to `ghcr.io` (main branch only)
4. **GitOps** — updates the preprod Kubernetes manifest (main branch only)