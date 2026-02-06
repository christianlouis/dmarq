# Security Policy

## Overview

DMARQ is a privacy-conscious, self-hosted DMARC monitoring and analysis platform. Security is paramount given that this tool processes sensitive email authentication data. This document outlines our security policy, how to report vulnerabilities, and security best practices for deployments.

## Supported Versions

We currently support security updates for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

We take all security vulnerabilities seriously. If you discover a security vulnerability in DMARQ, please follow these steps:

### How to Report

1. **DO NOT** create a public GitHub issue for security vulnerabilities
2. Email security reports to: [Maintainer Email - TODO: Add email address]
3. Include the following information:
   - Description of the vulnerability
   - Steps to reproduce the issue
   - Potential impact
   - Suggested fix (if any)

### What to Expect

- **Initial Response**: Within 48 hours of submission
- **Status Update**: Regular updates every 5-7 days
- **Resolution Timeline**: We aim to address critical vulnerabilities within 7 days
- **Credit**: Security researchers will be credited in our release notes (unless you prefer to remain anonymous)

## Known Security Considerations

### Critical Security Issues Identified (Status: Pending Remediation)

The following security issues have been identified and are documented for transparency:

#### 1. **Missing Authentication on Admin Endpoints** (CRITICAL)
- **Location**: `backend/app/main.py` lines 195-196, 224-225
- **Issue**: Admin endpoints `/api/v1/admin/trigger-poll` and `/api/v1/admin/poll-status` lack authentication
- **Impact**: Unauthorized users can trigger IMAP polling operations
- **Status**: ⚠️ Requires immediate remediation
- **Workaround**: Use network-level access controls to restrict access

#### 2. **Default SECRET_KEY in Configuration** (CRITICAL)
- **Location**: `backend/app/core/config.py` line 24
- **Issue**: Default SECRET_KEY value is not production-safe
- **Impact**: JWT tokens can be forged if default key is used
- **Status**: ⚠️ Must be changed before production deployment
- **Remediation**: Always set a unique `SECRET_KEY` in your `.env` file using a cryptographically secure random string

#### 3. **XML External Entity (XXE) Vulnerability** (HIGH)
- **Location**: `backend/app/services/dmarc_parser.py`
- **Issue**: Standard ElementTree parser used instead of defusedxml
- **Impact**: Potential XXE attacks through malicious DMARC reports
- **Status**: ⚠️ Requires code changes
- **Mitigation**: Use `defusedxml.ElementTree` instead of standard library

#### 4. **IMAP Credentials in URLs** (HIGH)
- **Location**: `backend/app/api/api_v1/endpoints/imap.py`
- **Issue**: IMAP credentials accepted as query parameters
- **Impact**: Credentials exposed in logs and browser history
- **Status**: ⚠️ Requires API redesign
- **Workaround**: Only use environment variables for IMAP configuration

#### 5. **Insufficient File Upload Validation** (HIGH)
- **Location**: `backend/app/api/api_v1/endpoints/reports.py`
- **Issue**: File type validation relies only on extensions
- **Impact**: Malicious files may bypass detection
- **Status**: ⚠️ Requires enhanced validation
- **Mitigation**: Implement MIME type checking and content validation

#### 6. **Missing Security Headers** (MEDIUM)
- **Location**: `backend/app/main.py`
- **Issue**: No security headers configured (CSP, X-Frame-Options, etc.)
- **Impact**: Increased XSS and clickjacking risks
- **Status**: 🔄 Enhancement needed

#### 7. **Overly Permissive CORS Configuration** (MEDIUM)
- **Location**: `backend/app/main.py` lines 75-82
- **Issue**: Wildcard methods and headers allowed
- **Impact**: Potential CSRF and security bypass issues
- **Status**: 🔄 Should be restricted

#### 8. **Exception Details Exposed to Clients** (MEDIUM)
- **Location**: Multiple endpoints
- **Issue**: Full exception messages returned in API responses
- **Impact**: Information disclosure to potential attackers
- **Status**: 🔄 Needs error handling improvements

## Security Best Practices for Deployment

### 1. Environment Configuration

**Always configure these security-critical settings:**

```bash
# Generate a secure secret key (use a tool like openssl)
SECRET_KEY=$(openssl rand -hex 32)

# Use strong database credentials
DATABASE_URL=postgresql://user:strong_password@localhost/dmarq

# Secure IMAP credentials
IMAP_PASSWORD=your_secure_password

# Configure proper CORS origins (no wildcards)
BACKEND_CORS_ORIGINS=https://your-domain.com
```

### 2. Network Security

- **Run behind a reverse proxy** (nginx, Traefik, Caddy) with TLS
- **Restrict network access** to the database and IMAP services
- **Use firewall rules** to limit access to trusted networks
- **Enable HTTPS only** - never expose the application over plain HTTP

### 3. Database Security

- Use PostgreSQL instead of SQLite for production
- Enable database encryption at rest
- Use strong, unique passwords
- Regular database backups with encryption
- Limit database user permissions (principle of least privilege)

### 4. File Upload Security

- Validate file extensions AND content types
- Implement file size limits (configured in your reverse proxy)
- Store uploaded files outside the webroot
- Scan uploaded files for malware (integrate with ClamAV or similar)

### 5. Docker Security

```yaml
# docker-compose.yml security best practices
services:
  app:
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp
    user: "1000:1000"  # Run as non-root user
```

### 6. Monitoring and Logging

- Enable application logging and monitor for suspicious activity
- Use log aggregation (ELK stack, Loki, etc.)
- Set up alerts for:
  - Failed authentication attempts
  - Unusual API access patterns
  - File upload errors
  - IMAP connection failures
- Regularly review logs for security incidents

### 7. Regular Updates

- Keep Docker images updated
- Update Python dependencies regularly
- Monitor security advisories for FastAPI and dependencies
- Apply security patches promptly

### 8. Access Control

- Implement role-based access control (RBAC) when multi-user support is added
- Use strong password policies (minimum length, complexity)
- Enable multi-factor authentication (MFA) when available
- Regular audit of user accounts and permissions

## Security Development Practices

### For Contributors

1. **Never commit secrets** to the repository
2. **Use `.env` files** for local development (never commit `.env`)
3. **Follow secure coding guidelines**:
   - Validate all user inputs
   - Use parameterized queries (SQLAlchemy ORM handles this)
   - Escape output in templates (Jinja2 auto-escapes by default)
   - Use HTTPS for all external API calls
4. **Add security tests** for new features
5. **Run security scans** before submitting PRs:
   ```bash
   # Check for hardcoded secrets
   pip install detect-secrets
   detect-secrets scan
   
   # Check for known vulnerabilities
   pip install safety
   safety check
   
   # Static analysis
   pip install bandit
   bandit -r backend/app
   ```

### Code Review Checklist

Before approving PRs, reviewers should verify:

- [ ] No hardcoded credentials or secrets
- [ ] Input validation on all user-supplied data
- [ ] Authentication/authorization checks on sensitive endpoints
- [ ] Proper error handling (no sensitive data in error messages)
- [ ] SQL injection prevention (using ORM properly)
- [ ] XSS prevention (output escaping)
- [ ] CSRF protection where applicable
- [ ] Secure file handling (if files are uploaded/downloaded)
- [ ] Dependencies are up-to-date and without known vulnerabilities

## Secure Configuration Template

Create a production-ready `.env` file using this template:

```bash
# Application Settings (REQUIRED)
PROJECT_NAME="DMARQ"
SECRET_KEY="GENERATE_UNIQUE_KEY_HERE_USE_OPENSSL_RAND_HEX_32"
ENVIRONMENT="production"

# Database (REQUIRED - Use PostgreSQL in production)
DATABASE_URL="postgresql://dmarq_user:STRONG_PASSWORD@db:5432/dmarq_db"

# IMAP Settings (REQUIRED for automated report fetching)
IMAP_SERVER="imap.example.com"
IMAP_PORT=993
IMAP_USERNAME="dmarc@example.com"
IMAP_PASSWORD="STRONG_IMAP_PASSWORD"

# CORS Origins (REQUIRED - Be specific, no wildcards)
BACKEND_CORS_ORIGINS="https://dmarq.yourdomain.com"

# Admin User (for initial setup)
FIRST_SUPERUSER="admin@example.com"
FIRST_SUPERUSER_PASSWORD="STRONG_ADMIN_PASSWORD_CHANGE_AFTER_FIRST_LOGIN"

# Optional: Cloudflare Integration
# CLOUDFLARE_API_TOKEN="your_cloudflare_api_token"
# CLOUDFLARE_ZONE_ID="your_cloudflare_zone_id"

# Security Settings (recommended)
# SESSION_TIMEOUT=1800  # 30 minutes
# MAX_UPLOAD_SIZE=10485760  # 10MB
# RATE_LIMIT_PER_MINUTE=60
```

## Security Roadmap

We are committed to improving DMARQ's security posture. Planned security enhancements:

### Short Term (Next Release)
- [ ] Fix critical authentication issues on admin endpoints
- [ ] Replace ElementTree with defusedxml
- [ ] Add security headers middleware
- [ ] Improve error handling to prevent information disclosure
- [ ] Add rate limiting on sensitive endpoints

### Medium Term (Next 3 months)
- [ ] Implement comprehensive input validation
- [ ] Add automated security scanning to CI/CD
- [ ] Enhance file upload security
- [ ] Add audit logging for security events
- [ ] Implement CSRF protection

### Long Term (Next 6 months)
- [ ] Security audit by external firm
- [ ] Penetration testing
- [ ] Implement role-based access control (RBAC)
- [ ] Add multi-factor authentication (MFA)
- [ ] Security hardening guide
- [ ] SOC 2 compliance documentation

## Security Resources

### Tools for Security Testing

```bash
# Install security testing tools
pip install bandit safety detect-secrets

# Run security scans
bandit -r backend/app -f json -o security-report.json
safety check --json
detect-secrets scan --baseline .secrets.baseline
```

### Recommended Reading

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [FastAPI Security Documentation](https://fastapi.tiangolo.com/tutorial/security/)
- [Docker Security Best Practices](https://docs.docker.com/engine/security/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

## Compliance and Standards

DMARQ aims to comply with:

- **GDPR**: Data privacy and protection (self-hosted approach helps with compliance)
- **SOC 2**: Security controls (roadmap item)
- **OWASP**: Top 10 and API Security guidelines
- **CWE**: Common Weakness Enumeration mitigation

## Contact

For security-related questions or concerns:
- Security Email: [TODO: Add security contact email]
- General Issues: [GitHub Issues](https://github.com/christianlouis/dmarq/issues) (non-security only)
- Documentation: [DMARQ Docs](https://dmarq.readthedocs.io/)

## Acknowledgments

We thank the security research community for helping keep DMARQ secure. Security researchers who responsibly disclose vulnerabilities will be acknowledged here (with their permission).

---

**Last Updated**: 2026-02-06
**Document Version**: 1.0
