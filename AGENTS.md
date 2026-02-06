# Agentic Coding Guidelines for DMARQ

This document provides guidelines for using AI-powered coding assistants (agents) when contributing to DMARQ. Whether you're using GitHub Copilot, Cursor, Claude Code, or other AI coding tools, these guidelines will help you use them effectively and safely.

## Table of Contents

- [What is Agentic Coding?](#what-is-agentic-coding)
- [Why DMARQ is Agent-Friendly](#why-dmarq-is-agent-friendly)
- [Getting Started with AI Assistants](#getting-started-with-ai-assistants)
- [Best Practices](#best-practices)
- [Security Considerations](#security-considerations)
- [Effective Prompts](#effective-prompts)
- [Review and Validation](#review-and-validation)
- [Common Pitfalls](#common-pitfalls)

## What is Agentic Coding?

Agentic coding refers to software development where AI assistants (agents) help generate, modify, and review code. These tools can:

- Generate boilerplate code
- Suggest implementations based on comments
- Write tests automatically
- Refactor existing code
- Find and fix bugs
- Generate documentation

## Why DMARQ is Agent-Friendly

DMARQ is designed with characteristics that make it work well with AI coding assistants:

### 1. Clear Architecture
- Modular structure with separation of concerns
- Consistent patterns across the codebase
- Well-defined layers (API, Services, Models)

### 2. Comprehensive Documentation
- Inline code comments
- API documentation
- Architecture documentation (see `/docs`)
- Clear README with examples

### 3. Type Hints
```python
def process_report(domain: str, xml_content: str) -> List[Dict[str, Any]]:
    """Process a DMARC report with type-safe parameters"""
    pass
```

### 4. Test Infrastructure
- Existing test patterns to follow
- Clear test organization
- Example tests for reference

### 5. Consistent Coding Style
- PEP 8 compliance
- Automated formatting with Black
- Clear naming conventions

## Getting Started with AI Assistants

### Setting Up Context

Give your AI assistant context about DMARQ:

```markdown
DMARQ is a self-hosted DMARC monitoring platform built with:
- Backend: FastAPI (Python 3.10+)
- Database: SQLAlchemy ORM (PostgreSQL/SQLite)
- Templates: Jinja2 with Tailwind CSS
- Architecture: RESTful API with server-side rendering

Key directories:
- /backend/app/api - API endpoints
- /backend/app/services - Business logic
- /backend/app/models - Database models
- /backend/app/tests - Test files
- /docs - Documentation
```

### Provide Examples

Show the AI assistant examples from the codebase:

```python
# Example: "Create a new endpoint following this pattern"
@router.get("/domains", response_model=List[DomainResponse])
async def list_domains():
    """List all monitored domains"""
    store = ReportStore.get_instance()
    domains = store.get_domains()
    return domains
```

## Best Practices

### 1. Start Small

Begin with small, well-defined tasks:

✅ **Good**: "Add input validation for the domain parameter"
❌ **Too Broad**: "Rewrite the entire API layer"

### 2. Iterative Development

Work in iterations:

```
1. Generate initial implementation
2. Review and test
3. Refine based on results
4. Repeat until complete
```

### 3. Use AI for Appropriate Tasks

| Good Use Cases | Proceed with Caution |
|----------------|---------------------|
| Boilerplate code | Security-critical code |
| Test generation | Authentication logic |
| Data models | Cryptography |
| Documentation | Complex algorithms |
| Refactoring | Database migrations |
| Bug fixes | Configuration changes |

### 4. Provide Clear Specifications

Be specific in your prompts:

```markdown
# Good Prompt
Create a new API endpoint `/api/v1/reports/{report_id}` that:
- Returns a single DMARC report by ID
- Uses the existing ReportStore service
- Includes error handling for not-found cases
- Follows the existing endpoint patterns
- Returns a 404 if report doesn't exist
```

### 5. Review Generated Code

**Always** review AI-generated code for:

- Correctness
- Security vulnerabilities
- Performance implications
- Adherence to project standards
- Test coverage

## Security Considerations

### Critical: Security Review Required

When AI generates code involving:

- **Authentication/Authorization**: Review thoroughly
- **Input Validation**: Verify all edge cases
- **Database Queries**: Check for SQL injection risks
- **File Operations**: Validate paths and permissions
- **External APIs**: Review credential handling
- **Cryptography**: Verify algorithm choices

### Security Checklist for AI-Generated Code

```markdown
- [ ] No hardcoded secrets or credentials
- [ ] All user inputs are validated
- [ ] SQL queries use ORM (no raw SQL)
- [ ] Files are handled securely
- [ ] Error messages don't leak sensitive data
- [ ] Authentication is properly implemented
- [ ] Authorization checks are present
- [ ] HTTPS is enforced where applicable
- [ ] Dependencies are secure versions
```

### Example: Reviewing AI-Generated Auth Code

```python
# ❌ AI might generate this - INSECURE
@router.post("/admin/action")
async def admin_action():
    # Missing authentication check!
    return perform_admin_action()

# ✅ Fixed by human review
@router.post("/admin/action")
async def admin_action(
    current_user: User = Depends(get_current_active_user)
):
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")
    return perform_admin_action()
```

## Effective Prompts

### Prompt Templates

#### 1. Creating New Features

```
Create a new [feature] that:
- Purpose: [description]
- Location: [file/directory]
- Dependencies: [services, models]
- Follow patterns from: [example file]
- Include: [tests, docs, validation]
- Error handling: [specific requirements]
```

#### 2. Fixing Bugs

```
Fix the bug in [file] where [description]:
- Current behavior: [what happens now]
- Expected behavior: [what should happen]
- Error message: [if any]
- Reproduce: [steps]
- Maintain: [backward compatibility]
```

#### 3. Refactoring

```
Refactor [module/function] to [goal]:
- Current issues: [problems]
- Keep: [what must stay the same]
- Improve: [specific aspects]
- Don't break: [tests, APIs]
- Performance: [requirements]
```

#### 4. Adding Tests

```
Write tests for [function/module]:
- Test file: [location]
- Follow pattern: [existing test]
- Cover cases: [list scenarios]
- Use fixtures: [if applicable]
- Mock: [external dependencies]
```

### Real Examples for DMARQ

```markdown
# Example 1: New Endpoint
Create a GET endpoint /api/v1/domains/{domain}/stats that returns
DMARC statistics for a specific domain. Use the existing DomainResponse 
model and ReportStore.get_domain_summary() method. Include error 
handling for invalid domain names.

# Example 2: Input Validation
Add input validation to the domain parameter in the reports upload
endpoint. Domain should match pattern: ^[a-z0-9.-]+$ and be max 
255 characters. Return 400 error with clear message if invalid.

# Example 3: Test Creation
Write pytest tests for the DMARC parser handling compressed files.
Test cases: valid .zip, valid .gz, corrupted archive, empty archive,
archive with multiple files. Place in test_dmarc_parser.py.

# Example 4: Documentation
Generate API documentation for all endpoints in 
/api/v1/endpoints/domains.py following OpenAPI/Swagger format.
Include request/response examples and error codes.
```

## Review and Validation

### Human Review Process

1. **Read the Code**: Don't just trust, understand it
2. **Test Locally**: Run the code in your environment
3. **Check Tests**: Verify tests are meaningful
4. **Security Scan**: Run security tools (bandit, safety)
5. **Performance**: Consider efficiency implications
6. **Documentation**: Ensure docs are updated

### Testing AI-Generated Code

```bash
# Run unit tests
pytest backend/app/tests/

# Check code coverage
pytest --cov=app --cov-report=html

# Lint the code
pylint backend/app/
black --check backend/app/

# Security scan
bandit -r backend/app/
safety check

# Type checking
mypy backend/app/
```

### Code Review Questions

Ask yourself:

1. **Does it work?** Test thoroughly
2. **Is it secure?** Check for vulnerabilities
3. **Is it maintainable?** Can others understand it?
4. **Does it fit?** Follows project patterns?
5. **Is it tested?** Has adequate test coverage?
6. **Is it documented?** Clear comments and docs?

## Common Pitfalls

### Pitfall 1: Over-Trusting AI

❌ **Don't**: Accept AI code without review
✅ **Do**: Treat AI suggestions as drafts requiring validation

### Pitfall 2: Insufficient Context

❌ **Don't**: Give vague prompts
✅ **Do**: Provide specific requirements and examples

### Pitfall 3: Ignoring Project Standards

❌ **Don't**: Let AI deviate from project conventions
✅ **Do**: Explicitly mention standards in prompts

### Pitfall 4: Security Blind Spots

❌ **Don't**: Assume AI handles security correctly
✅ **Do**: Always perform security review

### Pitfall 5: Missing Tests

❌ **Don't**: Ship AI code without tests
✅ **Do**: Generate tests for all new code

### Pitfall 6: Documentation Lag

❌ **Don't**: Forget to update documentation
✅ **Do**: Update docs alongside code changes

## Advanced Techniques

### 1. Multi-Step Prompting

Break complex tasks into steps:

```markdown
Step 1: "Create the data model for forensic reports"
Step 2: "Add database migration for the new model"
Step 3: "Create service methods to process forensic reports"
Step 4: "Add API endpoint to retrieve forensic reports"
Step 5: "Write tests for the entire flow"
```

### 2. Using Examples

Provide examples to guide the AI:

```python
# "Create a similar endpoint for forensic reports"
# Example to follow:
@router.get("/aggregate-reports/{report_id}")
async def get_aggregate_report(report_id: str):
    store = ReportStore.get_instance()
    report = store.get_report(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report
```

### 3. Constraint-Based Generation

Set clear boundaries:

```markdown
Create a caching layer for domain statistics:
- Must not cache for more than 5 minutes
- Must handle cache invalidation on new reports
- Must be thread-safe
- Must use Redis if available, fallback to in-memory
- Must include cache hit/miss metrics
```

### 4. Validation Prompts

Ask AI to review its own work:

```markdown
Review the above code for:
1. Security vulnerabilities
2. Performance bottlenecks
3. Error handling completeness
4. Test coverage gaps
5. Documentation clarity
```

## Integration with Development Workflow

### Git Workflow

```bash
# 1. Create branch
git checkout -b feature/ai-assisted-forensic-reports

# 2. Use AI to generate code
# ... work with AI assistant ...

# 3. Review and test
pytest
bandit -r backend/app/

# 4. Commit with clear message
git commit -m "feat: add forensic report support

Generated initial implementation with AI assistance.
Manually reviewed for security and correctness.
Added additional test cases and error handling."

# 5. Create PR with context
# Mention AI assistance in PR description
```

### PR Description Template

```markdown
## Description
[What was changed]

## AI Assistance
- Tool used: GitHub Copilot / Cursor / Claude
- Tasks assisted: [code generation, tests, docs]
- Human review: [what you validated]

## Testing
[How you tested the AI-generated code]

## Security Review
- [ ] No hardcoded secrets
- [ ] Input validation present
- [ ] Authentication/authorization correct
- [ ] No SQL injection risks
- [ ] Error handling appropriate
```

## Resources

### AI Coding Tools

- **GitHub Copilot**: https://github.com/features/copilot
- **Cursor**: https://cursor.sh/
- **Tabnine**: https://www.tabnine.com/
- **Amazon CodeWhisperer**: https://aws.amazon.com/codewhisperer/

### Security Tools

```bash
# Install security scanning tools
pip install bandit safety detect-secrets

# Run scans
bandit -r backend/app/
safety check
detect-secrets scan
```

### Learning Resources

- [GitHub Copilot Best Practices](https://github.blog/2023-06-20-how-to-write-better-prompts-for-github-copilot/)
- [AI-Assisted Coding Security Guide](https://owasp.org/www-project-ai-security-and-privacy-guide/)
- [DMARQ Contributing Guide](CONTRIBUTING.md)
- [DMARQ Security Policy](SECURITY.md)

## Questions and Support

If you have questions about using AI assistants with DMARQ:

1. Check this guide first
2. Review existing AI-assisted PRs for examples
3. Ask in GitHub Discussions
4. Mention in your PR if you need guidance

## Conclusion

AI coding assistants are powerful tools that can accelerate development when used properly. The key principles:

1. **AI assists, humans decide**: You're responsible for the code
2. **Security first**: Always review for vulnerabilities
3. **Test everything**: Don't trust, verify
4. **Document clearly**: Note when AI was used
5. **Follow standards**: Maintain project consistency

Happy coding with your AI assistant! 🤖✨

---

**Document Version**: 1.0  
**Last Updated**: 2026-02-06
