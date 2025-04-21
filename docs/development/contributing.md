# Contributing to DMARQ

Thank you for your interest in contributing to DMARQ! This guide will help you get started with the development process.

## Code of Conduct

Please read and follow our [Code of Conduct](https://github.com/yourusername/dmarq/blob/main/CODE_OF_CONDUCT.md) to keep our community approachable and respectable.

## How to Contribute

There are many ways to contribute to DMARQ:

- **Reporting bugs**: Submit detailed bug reports to help us improve
- **Suggesting features**: Propose new features or improvements
- **Writing code**: Contribute code changes or new features
- **Improving docs**: Help make our documentation more comprehensive
- **Translation**: Help translate the interface into other languages

## Development Environment Setup

### Prerequisites

- Python 3.9+
- Node.js 16+ (for frontend assets)
- Docker and Docker Compose (recommended)
- Git

### Setting Up the Project

1. **Fork the repository**

   Start by forking the [DMARQ repository](https://github.com/yourusername/dmarq) on GitHub.

2. **Clone your fork**

   ```bash
   git clone https://github.com/YOUR-USERNAME/dmarq.git
   cd dmarq
   ```

3. **Set up the development environment**

   Using Docker (recommended):

   ```bash
   docker-compose -f docker-compose.dev.yml up
   ```

   Or manually:

   ```bash
   # Create a virtual environment
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate

   # Install dependencies
   cd backend
   pip install -r requirements.txt
   pip install -r requirements-dev.txt

   # Set up the database
   cd app
   python -m alembic upgrade head

   # Start the development server
   uvicorn main:app --reload --host 0.0.0.0 --port 8000
   ```

4. **Frontend Assets (if modifying)**

   If you're modifying frontend assets:

   ```bash
   cd backend/app/static
   npm install
   npm run dev
   ```

## Making Changes

### Branching Strategy

We follow a simple branching strategy:

- `main` branch is the stable release branch
- `develop` branch is for development work
- Feature branches should be created from `develop`

### Creating a Branch

Create a new branch for your changes:

```bash
git checkout develop
git pull origin develop
git checkout -b feature/your-feature-name
```

Use prefixes like:
- `feature/` for new features
- `bugfix/` for bug fixes
- `docs/` for documentation changes
- `test/` for test improvements

### Coding Standards

We follow these standards:

- **Python**: [PEP 8](https://www.python.org/dev/peps/pep-0008/) style guide
- **JavaScript**: ESLint with Airbnb style
- **HTML/CSS**: Follow the project's existing patterns

We use pre-commit hooks to enforce coding standards:

```bash
pip install pre-commit
pre-commit install
```

### Testing

All code changes should include tests:

```bash
# Run the test suite
cd backend
pytest

# With coverage
pytest --cov=app
```

## Submitting a Pull Request

1. **Update your branch**

   ```bash
   git fetch origin
   git rebase origin/develop
   ```

2. **Run tests**

   Ensure all tests pass before submitting:

   ```bash
   pytest
   ```

3. **Commit your changes**

   Follow the [Conventional Commits](https://www.conventionalcommits.org/) standard:

   ```bash
   git commit -m "feat: add user authentication"
   ```

4. **Push to your fork**

   ```bash
   git push origin feature/your-feature-name
   ```

5. **Submit a pull request**

   Go to the [DMARQ repository](https://github.com/yourusername/dmarq) and create a pull request from your branch to the `develop` branch.

   Include in your PR description:
   - What changes you've made
   - Why you've made these changes
   - Any relevant issue numbers (e.g., "Fixes #123")
   - Screenshots if applicable

6. **Code review**

   Maintainers will review your code. You might need to make additional changes based on feedback.

## Pull Request Review Process

Pull requests are reviewed by maintainers who will check:

1. Code quality and style
2. Test coverage
3. Documentation
4. Overall fit with the project goals

## Release Process

We use semantic versioning (MAJOR.MINOR.PATCH):

- MAJOR version for incompatible API changes
- MINOR version for new functionality in a backwards compatible manner
- PATCH version for backwards compatible bug fixes

## Documentation

Please update documentation alongside code changes:

- Update relevant parts of this documentation site
- Add or update docstrings
- Update README.md if needed

To build and preview the documentation:

```bash
# Install mkdocs and requirements
pip install -r docs/readthedocs/requirements.txt

# Serve documentation locally
mkdocs serve
```

## Additional Resources

- [Project Architecture](../reference/architecture.md)
- [Database Schema](../reference/database.md)
- [API Reference](../reference/api.md)

## Getting Help

If you need help with your contribution, you can:

- Open an issue on GitHub
- Join our community channels
- Email the maintainers at maintainers@example.com

## Recognition

All contributors are recognized in our [CONTRIBUTORS.md](https://github.com/yourusername/dmarq/blob/main/CONTRIBUTORS.md) file. We appreciate your help in making DMARQ better!