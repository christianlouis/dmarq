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

### Security Remediation Status (Updated: 2026-02-09)

The following security issues have been identified and **REMEDIATED** in the latest version:

#### 1. **Missing Authentication on Admin Endpoints** (CRITICAL) - ✅ FIXED
- **Location**: `backend/app/main.py` and `backend/app/api/api_v1/endpoints/imap.py`
- **Issue**: Admin endpoints `/api/v1/admin/trigger-poll`, `/api/v1/admin/poll-status`, and IMAP endpoints lacked authentication
- **Impact**: Unauthorized users could trigger IMAP polling operations
- **Status**: ✅ **RESOLVED** - Authentication middleware implemented
- **Solution Implemented**:
  - Added API key authentication system with secure key generation
  - Implemented JWT token verification support
  - All admin endpoints now require either X-API-Key header or Bearer token
  - API key generated and logged on application startup
  - Added `require_admin_auth` dependency for protected endpoints

#### 2. **Default SECRET_KEY in Configuration** (CRITICAL) - ✅ FIXED
- **Location**: `backend/app/core/config.py`
- **Issue**: Default SECRET_KEY value was not production-safe
- **Impact**: JWT tokens could be forged if default key is used
- **Status**: ✅ **RESOLVED** - Automatic validation and generation
- **Solution Implemented**:
  - Removed hardcoded default SECRET_KEY
  - Added validation that generates secure random key if not provided
  - Warning logged if default/missing key detected
  - Minimum length validation (32 characters recommended)
  - Updated .env.example with clear security documentation

#### 3. **XML External Entity (XXE) Vulnerability** (HIGH) - ✅ FIXED
- **Location**: `backend/app/services/dmarc_parser.py`
- **Issue**: Standard ElementTree parser used instead of defusedxml
- **Impact**: Potential XXE attacks through malicious DMARC reports
- **Status**: ✅ **RESOLVED** - Using defusedxml
- **Solution Implemented**:
  - Replaced `xml.etree.ElementTree` with `defusedxml.ElementTree`
  - Added file size limits (10 MB max)
  - Implemented zip bomb protection (100 MB uncompressed max, 10 files max)
  - Added comprehensive validation for compressed archives
  - Security tests verify XXE protection

#### 4. **IMAP Credentials in URLs** (HIGH) - ✅ FIXED
- **Location**: `backend/app/api/api_v1/endpoints/imap.py`
- **Issue**: IMAP credentials accepted as query parameters
- **Impact**: Credentials exposed in logs and browser history
- **Status**: ✅ **RESOLVED** - Query parameter validation added
- **Solution Implemented**:
  - Added validation to reject credentials in query parameters
  - All IMAP endpoints now require authentication
  - Clear error messages guide users to use environment variables
  - Added parameter validation (days must be 1-365)

#### 5. **Insufficient File Upload Validation** (HIGH) - ✅ FIXED
- **Location**: `backend/app/api/api_v1/endpoints/reports.py`
- **Issue**: File type validation relied only on extensions
- **Impact**: Malicious files could bypass detection
- **Status**: ✅ **RESOLVED** - Multi-layer validation
- **Solution Implemented**:
  - Added file extension validation (whitelist: .xml, .zip, .gz)
  - Implemented MIME type validation when python-magic available
  - Added file size validation (10 MB max)
  - Sanitized error messages to prevent information disclosure
  - Domain validation for parsed reports
  - Comprehensive security tests for file upload scenarios

#### 6. **Missing Security Headers** (MEDIUM) - ✅ FIXED
- **Location**: `backend/app/main.py` and new `backend/app/middleware/security.py`
- **Issue**: No security headers configured (CSP, X-Frame-Options, etc.)
- **Impact**: Increased XSS and clickjacking risks
- **Status**: ✅ **RESOLVED** - Security headers middleware implemented
- **Solution Implemented**:
  - Created SecurityHeadersMiddleware
  - Added Content-Security-Policy (CSP)
  - Added X-Frame-Options: DENY
  - Added X-Content-Type-Options: nosniff
  - Added X-XSS-Protection: 1; mode=block
  - Added Referrer-Policy: strict-origin-when-cross-origin
  - Added Permissions-Policy to disable unnecessary features
  - Added Strict-Transport-Security (HSTS) for production
  - Cache-Control headers for sensitive API endpoints

#### 7. **Overly Permissive CORS Configuration** (MEDIUM) - ✅ FIXED
- **Location**: `backend/app/main.py`
- **Issue**: Wildcard methods and headers allowed
- **Impact**: Potential CSRF and security bypass issues
- **Status**: ✅ **RESOLVED** - Restricted CORS configuration
- **Solution Implemented**:
  - Restricted methods to: GET, POST, PUT, DELETE, OPTIONS only
  - Specified exact allowed headers (no wildcards)
  - Limited exposed headers
  - Added 10-minute cache for preflight requests
  - Documentation in .env.example for production configuration

#### 8. **Exception Details Exposed to Clients** (MEDIUM) - ✅ FIXED
- **Location**: Multiple endpoints, especially `backend/app/api/api_v1/endpoints/reports.py`
- **Issue**: Full exception messages returned in API responses
- **Impact**: Information disclosure to potential attackers
- **Status**: ✅ **RESOLVED** - Sanitized error handling
- **Solution Implemented**:
  - Implemented sanitized error responses
  - Generic error messages returned to clients
  - Detailed errors logged server-side only
  - Appropriate HTTP status codes (400, 413, 500)
  - No file paths, stack traces, or internal details exposed

### Testing Coverage

Comprehensive security test suite added (`backend/app/tests/test_security.py`):
- ✅ Authentication and API key tests
- ✅ Domain validation tests (format, malicious input, length limits)
- ✅ File upload security tests (size limits, zip bomb protection)
- ✅ XML parsing security tests (defusedxml verification, XXE protection)
- ✅ Error handling and information disclosure prevention

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

We are committed to improving DMARQ's security posture. Recent accomplishments and future plans:

### Recently Completed ✅ (February 2026)
- [x] Fix critical authentication issues on admin endpoints
- [x] Replace ElementTree with defusedxml
- [x] Add security headers middleware
- [x] Improve error handling to prevent information disclosure
- [x] Implement comprehensive input validation
- [x] Enhance file upload security with zip bomb protection
- [x] Add security-focused unit test suite
- [x] Restrict CORS configuration

### Short Term (Next 1-2 months)
- [ ] Add rate limiting with Redis backend (currently basic implementation)
- [ ] Add automated security scanning to CI/CD (bandit, safety)
- [ ] Implement CSRF protection for state-changing operations
- [ ] Add session management and timeout configuration
- [ ] Enhance audit logging for security events
- [ ] Add optional python-magic for enhanced MIME type detection

### Medium Term (Next 3-6 months)
- [ ] Implement role-based access control (RBAC)
- [ ] Add multi-factor authentication (MFA) support
- [ ] Database encryption at rest
- [ ] Advanced rate limiting per endpoint
- [ ] Security event monitoring and alerting
- [ ] Implement API request signing

### Long Term (Next 6-12 months)
- [ ] Security audit by external firm
- [ ] Penetration testing
- [ ] Security hardening guide
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
