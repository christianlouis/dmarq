# Contributing to DMARQ

First off, thank you for considering contributing to DMARQ! It's people like you that make DMARQ such a great tool for DMARC monitoring and email security.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Testing](#testing)
- [Style Guidelines](#style-guidelines)
- [Commit Messages](#commit-messages)
- [Pull Request Process](#pull-request-process)
- [Security](#security)

## Code of Conduct

This project and everyone participating in it is governed by our Code of Conduct. By participating, you are expected to uphold this code. Please report unacceptable behavior to the project maintainers.

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check the existing issues list as you might find that you don't need to create one. When you are creating a bug report, please include as many details as possible:

- **Use a clear and descriptive title**
- **Describe the exact steps to reproduce the problem**
- **Provide specific examples** to demonstrate the steps
- **Describe the behavior you observed** and what you expected
- **Include screenshots** if relevant
- **Include your environment details** (OS, Python version, Docker version)

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion:

- **Use a clear and descriptive title**
- **Provide a detailed description** of the proposed feature
- **Explain why this enhancement would be useful**
- **List some examples** of how it would be used
- **Consider the scope** - does it fit DMARQ's mission?

### Your First Code Contribution

Unsure where to begin? You can start by looking through issues tagged with:

- `good first issue` - should only require a few lines of code
- `help wanted` - more involved but not requiring deep knowledge of the codebase
- `documentation` - improvements or additions to documentation

### Pull Requests

- Fill in the required template
- Follow the [style guidelines](#style-guidelines)
- Include tests when adding features
- Update documentation as needed
- End all files with a newline

## Development Setup

### Prerequisites

- Python 3.10 or higher
- Docker and Docker Compose (for full stack testing)
- Git

### Local Development Setup

1. **Fork and clone the repository**

```bash
git clone https://github.com/YOUR_USERNAME/dmarq.git
cd dmarq
```

2. **Set up Python virtual environment**

```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
pip install -r requirements-dev.txt  # Development dependencies
```

3. **Set up environment variables**

```bash
cp .env.example .env
# Edit .env with your local configuration
```

4. **Run the development server**

```bash
cd backend
uvicorn app.main:app --reload --port 8080
```

5. **Access the application**

Open your browser to http://localhost:8080

### Docker Development

For a full stack with database:

```bash
docker compose up --build
```

## Making Changes

### Branch Naming Convention

Use descriptive branch names:

- `feature/add-new-chart-type`
- `fix/imap-connection-error`
- `docs/update-api-documentation`
- `security/fix-xss-vulnerability`

### Development Workflow

1. **Create a new branch**

```bash
git checkout -b feature/your-feature-name
```

2. **Make your changes**
   - Write clear, concise code
   - Follow the style guidelines
   - Add tests for new functionality
   - Update documentation

3. **Test your changes**

```bash
# Run unit tests
pytest

# Run with coverage
pytest --cov=app --cov-report=html

# Run linting
pylint app/
flake8 app/
black --check app/

# Run security checks
bandit -r app/
safety check
```

4. **Commit your changes**

```bash
git add .
git commit -m "feat: add new feature"
```

5. **Push to your fork**

```bash
git push origin feature/your-feature-name
```

6. **Create a Pull Request**

## Testing

### Running Tests

```bash
# Run all tests
pytest

# Run specific test file
pytest backend/app/tests/test_dmarc_parser.py

# Run with verbose output
pytest -v

# Run with coverage report
pytest --cov=app --cov-report=term-missing
```

### Writing Tests

- Place tests in `backend/app/tests/`
- Name test files with `test_` prefix
- Name test functions with `test_` prefix
- Use descriptive test names that explain what is being tested

Example:

```python
def test_dmarc_parser_handles_valid_xml():
    """Test that the parser correctly processes valid DMARC XML"""
    parser = DMARCParser()
    result = parser.parse_xml(valid_xml_content)
    assert result is not None
    assert result['domain'] == 'example.com'
```

### Test Coverage Goals

- Aim for at least 80% code coverage
- Critical security features should have 100% coverage
- All new features must include tests

## Style Guidelines

### Python Style Guide

We follow PEP 8 with some modifications:

- **Line length**: Maximum 100 characters (not 79)
- **Imports**: Organize as stdlib, third-party, local
- **Docstrings**: Use Google-style docstrings
- **Type hints**: Use type hints for function signatures

Example:

```python
from typing import Optional, List
from datetime import datetime

def process_dmarc_report(
    domain: str, 
    report_xml: str, 
    timestamp: Optional[datetime] = None
) -> List[dict]:
    """
    Process a DMARC aggregate report.
    
    Args:
        domain: The domain name being reported on
        report_xml: Raw XML content of the DMARC report
        timestamp: Optional timestamp for the report
        
    Returns:
        List of processed report records
        
    Raises:
        ValueError: If the XML is malformed
    """
    # Implementation here
    pass
```

### Code Formatting

We use automated code formatters:

```bash
# Format code with black
black backend/app/

# Sort imports with isort
isort backend/app/

# Type checking with mypy (coming soon)
mypy backend/app/
```

### Documentation Style

- Use clear, concise language
- Include code examples where helpful
- Keep documentation up-to-date with code changes
- Use proper Markdown formatting

## Commit Messages

Follow the Conventional Commits specification:

### Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types

- `feat`: A new feature
- `fix`: A bug fix
- `docs`: Documentation only changes
- `style`: Code style changes (formatting, missing semicolons, etc.)
- `refactor`: Code change that neither fixes a bug nor adds a feature
- `perf`: Performance improvements
- `test`: Adding missing tests or correcting existing tests
- `chore`: Changes to build process or auxiliary tools
- `security`: Security improvements or fixes

### Examples

```
feat(parser): add support for forensic DMARC reports

Added parsing logic for DMARC forensic (failure) reports (RUF).
This allows users to see detailed information about individual
email authentication failures.

Closes #123
```

```
fix(imap): handle connection timeout gracefully

The IMAP client now properly handles timeout exceptions and
retries with exponential backoff. This prevents the application
from crashing when the mail server is temporarily unavailable.

Fixes #456
```

```
security(api): add authentication to admin endpoints

Added authentication checks to /api/v1/admin/* endpoints to
prevent unauthorized access.

BREAKING CHANGE: Admin endpoints now require authentication token
```

## Pull Request Process

### Before Submitting

1. **Ensure your code follows the style guidelines**
2. **Run all tests and ensure they pass**
3. **Update documentation** as necessary
4. **Add or update tests** for your changes
5. **Run security scans** if touching sensitive code
6. **Verify the application works** with your changes

### PR Template

When you create a PR, fill out the template completely:

```markdown
## Description
Brief description of the changes

## Type of Change
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update

## Testing
Describe the tests you ran and how to reproduce them

## Checklist
- [ ] My code follows the style guidelines
- [ ] I have performed a self-review of my code
- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] I have made corresponding changes to the documentation
- [ ] My changes generate no new warnings
- [ ] I have added tests that prove my fix is effective or that my feature works
- [ ] New and existing unit tests pass locally with my changes
- [ ] Any dependent changes have been merged and published
```

### Review Process

1. **Automated checks** must pass (linting, tests, security scans)
2. **At least one maintainer review** is required
3. **Address review comments** promptly and professionally
4. **Keep the PR focused** - one feature/fix per PR
5. **Be patient** - maintainers review PRs as time allows

### After Approval

Once approved, a maintainer will merge your PR. The merge will trigger:

- Automated deployment (if applicable)
- Documentation updates
- Release notes generation

## Security

### Reporting Security Issues

**DO NOT** create public issues for security vulnerabilities. Instead:

1. Email the maintainers (see SECURITY.md for contact info)
2. Provide detailed information about the vulnerability
3. Allow time for the issue to be addressed before public disclosure

### Security Best Practices

When contributing code that touches security-sensitive areas:

- **Never commit secrets** (API keys, passwords, etc.)
- **Validate all inputs** from users or external systems
- **Use parameterized queries** (our ORM does this automatically)
- **Follow principle of least privilege**
- **Add security tests** for authentication/authorization changes
- **Document security implications** in your PR

### Security Checklist for PRs

If your PR involves any of these, extra scrutiny is required:

- [ ] Authentication or authorization
- [ ] Data validation or sanitization
- [ ] Database queries
- [ ] File uploads or downloads
- [ ] External API calls
- [ ] Cryptography or password handling
- [ ] Configuration or environment variables

## Working with AI Assistants (Agentic Coding)

DMARQ is designed to be "agentic coding friendly" - meaning it works well with AI coding assistants like GitHub Copilot, Cursor, and similar tools.

### Tips for AI-Assisted Development

1. **Clear Context**: Ensure your AI assistant has context about DMARQ's architecture
2. **Security First**: Always review AI-generated code for security implications
3. **Test Coverage**: AI-generated code still needs tests
4. **Code Review**: Human review is essential for AI-generated contributions
5. **Documentation**: Update docs even for AI-assisted changes

### Prompts that Work Well

When using AI assistants, these patterns work well:

```
"Add a new API endpoint to [do something], following DMARQ's existing patterns in the api/ directory"

"Write tests for [functionality] using the existing test structure in tests/"

"Refactor [module] to improve [aspect] while maintaining backward compatibility"

"Add input validation for [endpoint] following DMARQ's security guidelines"
```

## Questions?

If you have questions about contributing:

- Check the [documentation](https://dmarq.readthedocs.io/)
- Search [existing issues](https://github.com/christianlouis/dmarq/issues)
- Join our community [discussions](https://github.com/christianlouis/dmarq/discussions)
- Ask in your PR - maintainers are happy to help!

## Recognition

Contributors are recognized in:

- The project README
- Release notes
- The contributors page (coming soon)

Thank you for making DMARQ better! 🎉
