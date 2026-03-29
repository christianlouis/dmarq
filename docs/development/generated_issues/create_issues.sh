#!/bin/bash
#
# Script to create GitHub issues from DMARQ roadmap
# Requires: GitHub CLI (gh) - https://cli.github.com/
#
# Usage: ./create_issues.sh
#

set -e

REPO="christianlouis/dmarq"

echo "Creating GitHub issues for DMARQ roadmap..."
echo "Repository: $REPO"
echo ""

# Check if gh is installed
if ! command -v gh &> /dev/null; then
    echo "Error: GitHub CLI (gh) is not installed."
    echo "Please install it from: https://cli.github.com/"
    exit 1
fi

# Check if authenticated
if ! gh auth status &> /dev/null; then
    echo "Error: Not authenticated with GitHub CLI."
    echo "Please run: gh auth login"
    exit 1
fi

ISSUE_COUNT=0

# Issue 1: [Security Sprint] Authentication & Authorization...
echo "Creating issue 1/54: [Security Sprint] Authentication & Authorization..."
gh issue create \
  --repo "$REPO" \
  --title "[Security Sprint] Authentication & Authorization" \
  --body "## Description

Part of the **Security Remediation Sprint** - Priority: **CRITICAL**

### Tasks

- [ ] Add authentication middleware to all admin endpoints
- [ ] Implement proper user authentication system
- [ ] Add authorization checks on sensitive operations
- [ ] Add rate limiting to prevent abuse

### Files to Update

- \`backend/app/main.py\`
- \`backend/app/api/api_v1/endpoints/imap.py\`
- \`backend/app/api/api_v1/endpoints/domains.py\`

### Related Documentation

- [SECURITY.md](../SECURITY.md)
- [Security Remediation Sprint](../ROADMAP.md#security-remediation-sprint-priority---in-progress)

---
*This issue was auto-generated from the DMARQ roadmap.*" \
  --label "security,priority: critical,security: critical" || echo "  Failed to create issue 1"

ISSUE_COUNT=$((ISSUE_COUNT + 1))
sleep 1  # Rate limiting

# Issue 2: [Security Sprint] Secret Management...
echo "Creating issue 2/54: [Security Sprint] Secret Management..."
gh issue create \
  --repo "$REPO" \
  --title "[Security Sprint] Secret Management" \
  --body "## Description

Part of the **Security Remediation Sprint** - Priority: **CRITICAL**

### Tasks

- [ ] Remove default SECRET_KEY value
- [ ] Add SECRET_KEY validation on startup
- [ ] Document secret generation in deployment guide
- [ ] Add warning if default secret is detected

### Files to Update

- \`backend/app/core/config.py\`

### Related Documentation

- [SECURITY.md](../SECURITY.md)
- [Security Remediation Sprint](../ROADMAP.md#security-remediation-sprint-priority---in-progress)

---
*This issue was auto-generated from the DMARQ roadmap.*" \
  --label "security,priority: critical,security: critical" || echo "  Failed to create issue 2"

ISSUE_COUNT=$((ISSUE_COUNT + 1))
sleep 1  # Rate limiting

# Issue 3: [Security Sprint] XML Parsing Security...
echo "Creating issue 3/54: [Security Sprint] XML Parsing Security..."
gh issue create \
  --repo "$REPO" \
  --title "[Security Sprint] XML Parsing Security" \
  --body "## Description

Part of the **Security Remediation Sprint** - Priority: **HIGH**

### Tasks

- [ ] Replace ElementTree with defusedxml
- [ ] Add file size limits for uploads
- [ ] Implement zip bomb protection
- [ ] Add malware scanning hooks (optional)

### Files to Update

- \`backend/app/services/dmarc_parser.py\`

### Related Documentation

- [SECURITY.md](../SECURITY.md)
- [Security Remediation Sprint](../ROADMAP.md#security-remediation-sprint-priority---in-progress)

---
*This issue was auto-generated from the DMARQ roadmap.*" \
  --label "security,priority: high,security: high" || echo "  Failed to create issue 3"

ISSUE_COUNT=$((ISSUE_COUNT + 1))
sleep 1  # Rate limiting

# Issue 4: [Security Sprint] Input Validation...
echo "Creating issue 4/54: [Security Sprint] Input Validation..."
gh issue create \
  --repo "$REPO" \
  --title "[Security Sprint] Input Validation" \
  --body "## Description

Part of the **Security Remediation Sprint** - Priority: **HIGH**

### Tasks

- [ ] Add domain name validation regex
- [ ] Implement file type validation (MIME + extension)
- [ ] Add parameter validation on all endpoints
- [ ] Sanitize error messages

### Files to Update

- \`backend/app/api/api_v1/endpoints/domains.py\`
- \`backend/app/api/api_v1/endpoints/reports.py\`
- \`backend/app/utils/domain_validator.py\`

### Related Documentation

- [SECURITY.md](../SECURITY.md)
- [Security Remediation Sprint](../ROADMAP.md#security-remediation-sprint-priority---in-progress)

---
*This issue was auto-generated from the DMARQ roadmap.*" \
  --label "security,priority: high,security: high" || echo "  Failed to create issue 4"

ISSUE_COUNT=$((ISSUE_COUNT + 1))
sleep 1  # Rate limiting

# Issue 5: [Security Sprint] Security Headers...
echo "Creating issue 5/54: [Security Sprint] Security Headers..."
gh issue create \
  --repo "$REPO" \
  --title "[Security Sprint] Security Headers" \
  --body "## Description

Part of the **Security Remediation Sprint** - Priority: **MEDIUM**

### Tasks

- [ ] Add security headers middleware
- [ ] Implement CSP (Content Security Policy)
- [ ] Add X-Frame-Options, X-Content-Type-Options
- [ ] Configure HSTS for production

### Related Documentation

- [SECURITY.md](../SECURITY.md)
- [Security Remediation Sprint](../ROADMAP.md#security-remediation-sprint-priority---in-progress)

---
*This issue was auto-generated from the DMARQ roadmap.*" \
  --label "security,priority: medium" || echo "  Failed to create issue 5"

ISSUE_COUNT=$((ISSUE_COUNT + 1))
sleep 1  # Rate limiting

# Issue 6: [Security Sprint] CORS Configuration...
echo "Creating issue 6/54: [Security Sprint] CORS Configuration..."
gh issue create \
  --repo "$REPO" \
  --title "[Security Sprint] CORS Configuration" \
  --body "## Description

Part of the **Security Remediation Sprint** - Priority: **MEDIUM**

### Tasks

- [ ] Restrict CORS methods and headers
- [ ] Remove wildcard configurations
- [ ] Document CORS setup for deployments

### Files to Update

- \`backend/app/main.py\`

### Related Documentation

- [SECURITY.md](../SECURITY.md)
- [Security Remediation Sprint](../ROADMAP.md#security-remediation-sprint-priority---in-progress)

---
*This issue was auto-generated from the DMARQ roadmap.*" \
  --label "security,priority: medium" || echo "  Failed to create issue 6"

ISSUE_COUNT=$((ISSUE_COUNT + 1))
sleep 1  # Rate limiting

# Issue 7: [Security Sprint] Error Handling...
echo "Creating issue 7/54: [Security Sprint] Error Handling..."
gh issue create \
  --repo "$REPO" \
  --title "[Security Sprint] Error Handling" \
  --body "## Description

Part of the **Security Remediation Sprint** - Priority: **MEDIUM**

### Tasks

- [ ] Implement centralized error handling
- [ ] Remove sensitive data from error responses
- [ ] Add error logging with request context
- [ ] Create user-friendly error messages

### Related Documentation

- [SECURITY.md](../SECURITY.md)
- [Security Remediation Sprint](../ROADMAP.md#security-remediation-sprint-priority---in-progress)

---
*This issue was auto-generated from the DMARQ roadmap.*" \
  --label "security,priority: medium" || echo "  Failed to create issue 7"

ISSUE_COUNT=$((ISSUE_COUNT + 1))
sleep 1  # Rate limiting

# Issue 8: [M4] Historical trend charts (Chart.js integration...
echo "Creating issue 8/54: [M4] Historical trend charts (Chart.js integration..."
gh issue create \
  --repo "$REPO" \
  --title "[M4] Historical trend charts (Chart.js integration)" \
  --body "## Description

Feature for **Milestone 4: Enhanced Dashboard & Visualization**

**Timeline**: Next - 4-6 weeks

### Feature
Historical trend charts (Chart.js integration)

### Related Documentation

- [Milestone 4](../ROADMAP.md#milestone-4-enhanced-dashboard--visualization)

---
*This issue was auto-generated from the DMARQ roadmap.*" \
  --label "enhancement,milestone-4,priority: high" || echo "  Failed to create issue 8"

ISSUE_COUNT=$((ISSUE_COUNT + 1))
sleep 1  # Rate limiting

# Issue 9: [M4] Compliance rate visualizations...
echo "Creating issue 9/54: [M4] Compliance rate visualizations..."
gh issue create \
  --repo "$REPO" \
  --title "[M4] Compliance rate visualizations" \
  --body "## Description

Feature for **Milestone 4: Enhanced Dashboard & Visualization**

**Timeline**: Next - 4-6 weeks

### Feature
Compliance rate visualizations

### Related Documentation

- [Milestone 4](../ROADMAP.md#milestone-4-enhanced-dashboard--visualization)

---
*This issue was auto-generated from the DMARQ roadmap.*" \
  --label "enhancement,milestone-4,priority: high" || echo "  Failed to create issue 9"

ISSUE_COUNT=$((ISSUE_COUNT + 1))
sleep 1  # Rate limiting

# Issue 10: [M4] Volume and sender analytics...
echo "Creating issue 10/54: [M4] Volume and sender analytics..."
gh issue create \
  --repo "$REPO" \
  --title "[M4] Volume and sender analytics" \
  --body "## Description

Feature for **Milestone 4: Enhanced Dashboard & Visualization**

**Timeline**: Next - 4-6 weeks

### Feature
Volume and sender analytics

### Related Documentation

- [Milestone 4](../ROADMAP.md#milestone-4-enhanced-dashboard--visualization)

---
*This issue was auto-generated from the DMARQ roadmap.*" \
  --label "enhancement,milestone-4,priority: high" || echo "  Failed to create issue 10"

ISSUE_COUNT=$((ISSUE_COUNT + 1))
sleep 1  # Rate limiting

# Issue 11: [M4] Time-series data displays...
echo "Creating issue 11/54: [M4] Time-series data displays..."
gh issue create \
  --repo "$REPO" \
  --title "[M4] Time-series data displays" \
  --body "## Description

Feature for **Milestone 4: Enhanced Dashboard & Visualization**

**Timeline**: Next - 4-6 weeks

### Feature
Time-series data displays

### Related Documentation

- [Milestone 4](../ROADMAP.md#milestone-4-enhanced-dashboard--visualization)

---
*This issue was auto-generated from the DMARQ roadmap.*" \
  --label "enhancement,milestone-4,priority: high" || echo "  Failed to create issue 11"

ISSUE_COUNT=$((ISSUE_COUNT + 1))
sleep 1  # Rate limiting

# Issue 12: [M4] Domain comparison views...
echo "Creating issue 12/54: [M4] Domain comparison views..."
gh issue create \
  --repo "$REPO" \
  --title "[M4] Domain comparison views" \
  --body "## Description

Feature for **Milestone 4: Enhanced Dashboard & Visualization**

**Timeline**: Next - 4-6 weeks

### Feature
Domain comparison views

### Related Documentation

- [Milestone 4](../ROADMAP.md#milestone-4-enhanced-dashboard--visualization)

---
*This issue was auto-generated from the DMARQ roadmap.*" \
  --label "enhancement,milestone-4,priority: high" || echo "  Failed to create issue 12"

ISSUE_COUNT=$((ISSUE_COUNT + 1))
sleep 1  # Rate limiting

# Issue 13: [M5] FastAPI Users integration...
echo "Creating issue 13/54: [M5] FastAPI Users integration..."
gh issue create \
  --repo "$REPO" \
  --title "[M5] FastAPI Users integration" \
  --body "## Description

Feature for **Milestone 5: User Authentication & Multi-User Support**

**Timeline**: 8-10 weeks

### Feature
FastAPI Users integration

### Related Documentation

- [Milestone 5](../ROADMAP.md#milestone-5-user-authentication--multi-user-support)

---
*This issue was auto-generated from the DMARQ roadmap.*" \
  --label "enhancement,milestone-5,priority: high" || echo "  Failed to create issue 13"

ISSUE_COUNT=$((ISSUE_COUNT + 1))
sleep 1  # Rate limiting

# Issue 14: [M5] User registration and management...
echo "Creating issue 14/54: [M5] User registration and management..."
gh issue create \
  --repo "$REPO" \
  --title "[M5] User registration and management" \
  --body "## Description

Feature for **Milestone 5: User Authentication & Multi-User Support**

**Timeline**: 8-10 weeks

### Feature
User registration and management

### Related Documentation

- [Milestone 5](../ROADMAP.md#milestone-5-user-authentication--multi-user-support)

---
*This issue was auto-generated from the DMARQ roadmap.*" \
  --label "enhancement,milestone-5,priority: high" || echo "  Failed to create issue 14"

ISSUE_COUNT=$((ISSUE_COUNT + 1))
sleep 1  # Rate limiting

# Issue 15: [M5] JWT-based authentication...
echo "Creating issue 15/54: [M5] JWT-based authentication..."
gh issue create \
  --repo "$REPO" \
  --title "[M5] JWT-based authentication" \
  --body "## Description

Feature for **Milestone 5: User Authentication & Multi-User Support**

**Timeline**: 8-10 weeks

### Feature
JWT-based authentication

### Related Documentation

- [Milestone 5](../ROADMAP.md#milestone-5-user-authentication--multi-user-support)

---
*This issue was auto-generated from the DMARQ roadmap.*" \
  --label "enhancement,milestone-5,priority: high" || echo "  Failed to create issue 15"

ISSUE_COUNT=$((ISSUE_COUNT + 1))
sleep 1  # Rate limiting

# Issue 16: [M5] Role-based access control (RBAC)...
echo "Creating issue 16/54: [M5] Role-based access control (RBAC)..."
gh issue create \
  --repo "$REPO" \
  --title "[M5] Role-based access control (RBAC)" \
  --body "## Description

Feature for **Milestone 5: User Authentication & Multi-User Support**

**Timeline**: 8-10 weeks

### Feature
Role-based access control (RBAC)

### Related Documentation

- [Milestone 5](../ROADMAP.md#milestone-5-user-authentication--multi-user-support)

---
*This issue was auto-generated from the DMARQ roadmap.*" \
  --label "enhancement,milestone-5,priority: high" || echo "  Failed to create issue 16"

ISSUE_COUNT=$((ISSUE_COUNT + 1))
sleep 1  # Rate limiting

# Issue 17: [M5] Password reset functionality...
echo "Creating issue 17/54: [M5] Password reset functionality..."
gh issue create \
  --repo "$REPO" \
  --title "[M5] Password reset functionality" \
  --body "## Description

Feature for **Milestone 5: User Authentication & Multi-User Support**

**Timeline**: 8-10 weeks

### Feature
Password reset functionality

### Related Documentation

- [Milestone 5](../ROADMAP.md#milestone-5-user-authentication--multi-user-support)

---
*This issue was auto-generated from the DMARQ roadmap.*" \
  --label "enhancement,milestone-5,priority: high" || echo "  Failed to create issue 17"

ISSUE_COUNT=$((ISSUE_COUNT + 1))
sleep 1  # Rate limiting

# Issue 18: [M5] Email verification (optional)...
echo "Creating issue 18/54: [M5] Email verification (optional)..."
gh issue create \
  --repo "$REPO" \
  --title "[M5] Email verification (optional)" \
  --body "## Description

Feature for **Milestone 5: User Authentication & Multi-User Support**

**Timeline**: 8-10 weeks

### Feature
Email verification (optional)

### Related Documentation

- [Milestone 5](../ROADMAP.md#milestone-5-user-authentication--multi-user-support)

---
*This issue was auto-generated from the DMARQ roadmap.*" \
  --label "enhancement,milestone-5,priority: high" || echo "  Failed to create issue 18"

ISSUE_COUNT=$((ISSUE_COUNT + 1))
sleep 1  # Rate limiting

# Issue 19: [M6] Apprise integration...
echo "Creating issue 19/54: [M6] Apprise integration..."
gh issue create \
  --repo "$REPO" \
  --title "[M6] Apprise integration" \
  --body "## Description

Feature for **Milestone 6: Alerting & Notifications**

**Timeline**: 10-12 weeks

### Feature
Apprise integration

### Related Documentation

- [Milestone 6](../ROADMAP.md#milestone-6-alerting--notifications)

---
*This issue was auto-generated from the DMARQ roadmap.*" \
  --label "enhancement,milestone-6,priority: medium" || echo "  Failed to create issue 19"

ISSUE_COUNT=$((ISSUE_COUNT + 1))
sleep 1  # Rate limiting

# Issue 20: [M6] Customizable alert rules...
echo "Creating issue 20/54: [M6] Customizable alert rules..."
gh issue create \
  --repo "$REPO" \
  --title "[M6] Customizable alert rules" \
  --body "## Description

Feature for **Milestone 6: Alerting & Notifications**

**Timeline**: 10-12 weeks

### Feature
Customizable alert rules

### Related Documentation

- [Milestone 6](../ROADMAP.md#milestone-6-alerting--notifications)

---
*This issue was auto-generated from the DMARQ roadmap.*" \
  --label "enhancement,milestone-6,priority: medium" || echo "  Failed to create issue 20"

ISSUE_COUNT=$((ISSUE_COUNT + 1))
sleep 1  # Rate limiting

# Issue 21: [M6] Multi-channel notifications (Email, Slack, et...
echo "Creating issue 21/54: [M6] Multi-channel notifications (Email, Slack, et..."
gh issue create \
  --repo "$REPO" \
  --title "[M6] Multi-channel notifications (Email, Slack, etc.)" \
  --body "## Description

Feature for **Milestone 6: Alerting & Notifications**

**Timeline**: 10-12 weeks

### Feature
Multi-channel notifications (Email, Slack, etc.)

### Related Documentation

- [Milestone 6](../ROADMAP.md#milestone-6-alerting--notifications)

---
*This issue was auto-generated from the DMARQ roadmap.*" \
  --label "enhancement,milestone-6,priority: medium" || echo "  Failed to create issue 21"

ISSUE_COUNT=$((ISSUE_COUNT + 1))
sleep 1  # Rate limiting

# Issue 22: [M6] Alert history and management...
echo "Creating issue 22/54: [M6] Alert history and management..."
gh issue create \
  --repo "$REPO" \
  --title "[M6] Alert history and management" \
  --body "## Description

Feature for **Milestone 6: Alerting & Notifications**

**Timeline**: 10-12 weeks

### Feature
Alert history and management

### Related Documentation

- [Milestone 6](../ROADMAP.md#milestone-6-alerting--notifications)

---
*This issue was auto-generated from the DMARQ roadmap.*" \
  --label "enhancement,milestone-6,priority: medium" || echo "  Failed to create issue 22"

ISSUE_COUNT=$((ISSUE_COUNT + 1))
sleep 1  # Rate limiting

# Issue 23: [M6] Notification preferences per user...
echo "Creating issue 23/54: [M6] Notification preferences per user..."
gh issue create \
  --repo "$REPO" \
  --title "[M6] Notification preferences per user" \
  --body "## Description

Feature for **Milestone 6: Alerting & Notifications**

**Timeline**: 10-12 weeks

### Feature
Notification preferences per user

### Related Documentation

- [Milestone 6](../ROADMAP.md#milestone-6-alerting--notifications)

---
*This issue was auto-generated from the DMARQ roadmap.*" \
  --label "enhancement,milestone-6,priority: medium" || echo "  Failed to create issue 23"

ISSUE_COUNT=$((ISSUE_COUNT + 1))
sleep 1  # Rate limiting

# Issue 24: [M7] Custom alert conditions...
echo "Creating issue 24/54: [M7] Custom alert conditions..."
gh issue create \
  --repo "$REPO" \
  --title "[M7] Custom alert conditions" \
  --body "## Description

Feature for **Milestone 7: Advanced Rule Engine**

**Timeline**: 14-16 weeks

### Feature
Custom alert conditions

### Related Documentation

- [Milestone 7](../ROADMAP.md#milestone-7-advanced-rule-engine)

---
*This issue was auto-generated from the DMARQ roadmap.*" \
  --label "enhancement,milestone-7,priority: medium" || echo "  Failed to create issue 24"

ISSUE_COUNT=$((ISSUE_COUNT + 1))
sleep 1  # Rate limiting

# Issue 25: [M7] Threshold-based triggers...
echo "Creating issue 25/54: [M7] Threshold-based triggers..."
gh issue create \
  --repo "$REPO" \
  --title "[M7] Threshold-based triggers" \
  --body "## Description

Feature for **Milestone 7: Advanced Rule Engine**

**Timeline**: 14-16 weeks

### Feature
Threshold-based triggers

### Related Documentation

- [Milestone 7](../ROADMAP.md#milestone-7-advanced-rule-engine)

---
*This issue was auto-generated from the DMARQ roadmap.*" \
  --label "enhancement,milestone-7,priority: medium" || echo "  Failed to create issue 25"

ISSUE_COUNT=$((ISSUE_COUNT + 1))
sleep 1  # Rate limiting

# Issue 26: [M7] New sender detection...
echo "Creating issue 26/54: [M7] New sender detection..."
gh issue create \
  --repo "$REPO" \
  --title "[M7] New sender detection" \
  --body "## Description

Feature for **Milestone 7: Advanced Rule Engine**

**Timeline**: 14-16 weeks

### Feature
New sender detection

### Related Documentation

- [Milestone 7](../ROADMAP.md#milestone-7-advanced-rule-engine)

---
*This issue was auto-generated from the DMARQ roadmap.*" \
  --label "enhancement,milestone-7,priority: medium" || echo "  Failed to create issue 26"

ISSUE_COUNT=$((ISSUE_COUNT + 1))
sleep 1  # Rate limiting

# Issue 27: [M7] Anomaly detection...
echo "Creating issue 27/54: [M7] Anomaly detection..."
gh issue create \
  --repo "$REPO" \
  --title "[M7] Anomaly detection" \
  --body "## Description

Feature for **Milestone 7: Advanced Rule Engine**

**Timeline**: 14-16 weeks

### Feature
Anomaly detection

### Related Documentation

- [Milestone 7](../ROADMAP.md#milestone-7-advanced-rule-engine)

---
*This issue was auto-generated from the DMARQ roadmap.*" \
  --label "enhancement,milestone-7,priority: medium" || echo "  Failed to create issue 27"

ISSUE_COUNT=$((ISSUE_COUNT + 1))
sleep 1  # Rate limiting

# Issue 28: [M7] Scheduled report summaries...
echo "Creating issue 28/54: [M7] Scheduled report summaries..."
gh issue create \
  --repo "$REPO" \
  --title "[M7] Scheduled report summaries" \
  --body "## Description

Feature for **Milestone 7: Advanced Rule Engine**

**Timeline**: 14-16 weeks

### Feature
Scheduled report summaries

### Related Documentation

- [Milestone 7](../ROADMAP.md#milestone-7-advanced-rule-engine)

---
*This issue was auto-generated from the DMARQ roadmap.*" \
  --label "enhancement,milestone-7,priority: medium" || echo "  Failed to create issue 28"

ISSUE_COUNT=$((ISSUE_COUNT + 1))
sleep 1  # Rate limiting

# Issue 29: [M8] DNS record health checks...
echo "Creating issue 29/54: [M8] DNS record health checks..."
gh issue create \
  --repo "$REPO" \
  --title "[M8] DNS record health checks" \
  --body "## Description

Feature for **Milestone 8: DNS Health & Cloudflare Integration**

**Timeline**: 16-18 weeks

### Feature
DNS record health checks

### Related Documentation

- [Milestone 8](../ROADMAP.md#milestone-8-dns-health--cloudflare-integration)

---
*This issue was auto-generated from the DMARQ roadmap.*" \
  --label "enhancement,milestone-8,priority: medium" || echo "  Failed to create issue 29"

ISSUE_COUNT=$((ISSUE_COUNT + 1))
sleep 1  # Rate limiting

# Issue 30: [M8] SPF/DKIM/DMARC validation...
echo "Creating issue 30/54: [M8] SPF/DKIM/DMARC validation..."
gh issue create \
  --repo "$REPO" \
  --title "[M8] SPF/DKIM/DMARC validation" \
  --body "## Description

Feature for **Milestone 8: DNS Health & Cloudflare Integration**

**Timeline**: 16-18 weeks

### Feature
SPF/DKIM/DMARC validation

### Related Documentation

- [Milestone 8](../ROADMAP.md#milestone-8-dns-health--cloudflare-integration)

---
*This issue was auto-generated from the DMARQ roadmap.*" \
  --label "enhancement,milestone-8,priority: medium" || echo "  Failed to create issue 30"

ISSUE_COUNT=$((ISSUE_COUNT + 1))
sleep 1  # Rate limiting

# Issue 31: [M8] Cloudflare API integration...
echo "Creating issue 31/54: [M8] Cloudflare API integration..."
gh issue create \
  --repo "$REPO" \
  --title "[M8] Cloudflare API integration" \
  --body "## Description

Feature for **Milestone 8: DNS Health & Cloudflare Integration**

**Timeline**: 16-18 weeks

### Feature
Cloudflare API integration

### Related Documentation

- [Milestone 8](../ROADMAP.md#milestone-8-dns-health--cloudflare-integration)

---
*This issue was auto-generated from the DMARQ roadmap.*" \
  --label "enhancement,milestone-8,priority: medium" || echo "  Failed to create issue 31"

ISSUE_COUNT=$((ISSUE_COUNT + 1))
sleep 1  # Rate limiting

# Issue 32: [M8] Configuration recommendations...
echo "Creating issue 32/54: [M8] Configuration recommendations..."
gh issue create \
  --repo "$REPO" \
  --title "[M8] Configuration recommendations" \
  --body "## Description

Feature for **Milestone 8: DNS Health & Cloudflare Integration**

**Timeline**: 16-18 weeks

### Feature
Configuration recommendations

### Related Documentation

- [Milestone 8](../ROADMAP.md#milestone-8-dns-health--cloudflare-integration)

---
*This issue was auto-generated from the DMARQ roadmap.*" \
  --label "enhancement,milestone-8,priority: medium" || echo "  Failed to create issue 32"

ISSUE_COUNT=$((ISSUE_COUNT + 1))
sleep 1  # Rate limiting

# Issue 33: [M8] DNS change tracking...
echo "Creating issue 33/54: [M8] DNS change tracking..."
gh issue create \
  --repo "$REPO" \
  --title "[M8] DNS change tracking" \
  --body "## Description

Feature for **Milestone 8: DNS Health & Cloudflare Integration**

**Timeline**: 16-18 weeks

### Feature
DNS change tracking

### Related Documentation

- [Milestone 8](../ROADMAP.md#milestone-8-dns-health--cloudflare-integration)

---
*This issue was auto-generated from the DMARQ roadmap.*" \
  --label "enhancement,milestone-8,priority: medium" || echo "  Failed to create issue 33"

ISSUE_COUNT=$((ISSUE_COUNT + 1))
sleep 1  # Rate limiting

# Issue 34: [M9] Forensic report parsing...
echo "Creating issue 34/54: [M9] Forensic report parsing..."
gh issue create \
  --repo "$REPO" \
  --title "[M9] Forensic report parsing" \
  --body "## Description

Feature for **Milestone 9: Forensic Reports**

**Timeline**: RUF) Support (20-22 weeks

### Feature
Forensic report parsing

### Related Documentation

- [Milestone 9](../ROADMAP.md#milestone-9-forensic-reports)

---
*This issue was auto-generated from the DMARQ roadmap.*" \
  --label "enhancement,milestone-9,priority: low" || echo "  Failed to create issue 34"

ISSUE_COUNT=$((ISSUE_COUNT + 1))
sleep 1  # Rate limiting

# Issue 35: [M9] Failure sample analysis...
echo "Creating issue 35/54: [M9] Failure sample analysis..."
gh issue create \
  --repo "$REPO" \
  --title "[M9] Failure sample analysis" \
  --body "## Description

Feature for **Milestone 9: Forensic Reports**

**Timeline**: RUF) Support (20-22 weeks

### Feature
Failure sample analysis

### Related Documentation

- [Milestone 9](../ROADMAP.md#milestone-9-forensic-reports)

---
*This issue was auto-generated from the DMARQ roadmap.*" \
  --label "enhancement,milestone-9,priority: low" || echo "  Failed to create issue 35"

ISSUE_COUNT=$((ISSUE_COUNT + 1))
sleep 1  # Rate limiting

# Issue 36: [M9] PII redaction options...
echo "Creating issue 36/54: [M9] PII redaction options..."
gh issue create \
  --repo "$REPO" \
  --title "[M9] PII redaction options" \
  --body "## Description

Feature for **Milestone 9: Forensic Reports**

**Timeline**: RUF) Support (20-22 weeks

### Feature
PII redaction options

### Related Documentation

- [Milestone 9](../ROADMAP.md#milestone-9-forensic-reports)

---
*This issue was auto-generated from the DMARQ roadmap.*" \
  --label "enhancement,milestone-9,priority: low" || echo "  Failed to create issue 36"

ISSUE_COUNT=$((ISSUE_COUNT + 1))
sleep 1  # Rate limiting

# Issue 37: [M9] Detailed authentication failure views...
echo "Creating issue 37/54: [M9] Detailed authentication failure views..."
gh issue create \
  --repo "$REPO" \
  --title "[M9] Detailed authentication failure views" \
  --body "## Description

Feature for **Milestone 9: Forensic Reports**

**Timeline**: RUF) Support (20-22 weeks

### Feature
Detailed authentication failure views

### Related Documentation

- [Milestone 9](../ROADMAP.md#milestone-9-forensic-reports)

---
*This issue was auto-generated from the DMARQ roadmap.*" \
  --label "enhancement,milestone-9,priority: low" || echo "  Failed to create issue 37"

ISSUE_COUNT=$((ISSUE_COUNT + 1))
sleep 1  # Rate limiting

# Issue 38: [M9] Sample download/export...
echo "Creating issue 38/54: [M9] Sample download/export..."
gh issue create \
  --repo "$REPO" \
  --title "[M9] Sample download/export" \
  --body "## Description

Feature for **Milestone 9: Forensic Reports**

**Timeline**: RUF) Support (20-22 weeks

### Feature
Sample download/export

### Related Documentation

- [Milestone 9](../ROADMAP.md#milestone-9-forensic-reports)

---
*This issue was auto-generated from the DMARQ roadmap.*" \
  --label "enhancement,milestone-9,priority: low" || echo "  Failed to create issue 38"

ISSUE_COUNT=$((ISSUE_COUNT + 1))
sleep 1  # Rate limiting

# Issue 39: [M10] Historical trend analysis...
echo "Creating issue 39/54: [M10] Historical trend analysis..."
gh issue create \
  --repo "$REPO" \
  --title "[M10] Historical trend analysis" \
  --body "## Description

Feature for **Milestone 10: Advanced Analytics & Reporting**

**Timeline**: 24-26 weeks

### Feature
Historical trend analysis

### Related Documentation

- [Milestone 10](../ROADMAP.md#milestone-10-advanced-analytics--reporting)

---
*This issue was auto-generated from the DMARQ roadmap.*" \
  --label "enhancement,milestone-10,priority: low" || echo "  Failed to create issue 39"

ISSUE_COUNT=$((ISSUE_COUNT + 1))
sleep 1  # Rate limiting

# Issue 40: [M10] Comparative reporting...
echo "Creating issue 40/54: [M10] Comparative reporting..."
gh issue create \
  --repo "$REPO" \
  --title "[M10] Comparative reporting" \
  --body "## Description

Feature for **Milestone 10: Advanced Analytics & Reporting**

**Timeline**: 24-26 weeks

### Feature
Comparative reporting

### Related Documentation

- [Milestone 10](../ROADMAP.md#milestone-10-advanced-analytics--reporting)

---
*This issue was auto-generated from the DMARQ roadmap.*" \
  --label "enhancement,milestone-10,priority: low" || echo "  Failed to create issue 40"

ISSUE_COUNT=$((ISSUE_COUNT + 1))
sleep 1  # Rate limiting

# Issue 41: [M10] Export capabilities (PDF, CSV)...
echo "Creating issue 41/54: [M10] Export capabilities (PDF, CSV)..."
gh issue create \
  --repo "$REPO" \
  --title "[M10] Export capabilities (PDF, CSV)" \
  --body "## Description

Feature for **Milestone 10: Advanced Analytics & Reporting**

**Timeline**: 24-26 weeks

### Feature
Export capabilities (PDF, CSV)

### Related Documentation

- [Milestone 10](../ROADMAP.md#milestone-10-advanced-analytics--reporting)

---
*This issue was auto-generated from the DMARQ roadmap.*" \
  --label "enhancement,milestone-10,priority: low" || echo "  Failed to create issue 41"

ISSUE_COUNT=$((ISSUE_COUNT + 1))
sleep 1  # Rate limiting

# Issue 42: [M10] Scheduled reports...
echo "Creating issue 42/54: [M10] Scheduled reports..."
gh issue create \
  --repo "$REPO" \
  --title "[M10] Scheduled reports" \
  --body "## Description

Feature for **Milestone 10: Advanced Analytics & Reporting**

**Timeline**: 24-26 weeks

### Feature
Scheduled reports

### Related Documentation

- [Milestone 10](../ROADMAP.md#milestone-10-advanced-analytics--reporting)

---
*This issue was auto-generated from the DMARQ roadmap.*" \
  --label "enhancement,milestone-10,priority: low" || echo "  Failed to create issue 42"

ISSUE_COUNT=$((ISSUE_COUNT + 1))
sleep 1  # Rate limiting

# Issue 43: [M10] Custom dashboards...
echo "Creating issue 43/54: [M10] Custom dashboards..."
gh issue create \
  --repo "$REPO" \
  --title "[M10] Custom dashboards" \
  --body "## Description

Feature for **Milestone 10: Advanced Analytics & Reporting**

**Timeline**: 24-26 weeks

### Feature
Custom dashboards

### Related Documentation

- [Milestone 10](../ROADMAP.md#milestone-10-advanced-analytics--reporting)

---
*This issue was auto-generated from the DMARQ roadmap.*" \
  --label "enhancement,milestone-10,priority: low" || echo "  Failed to create issue 43"

ISSUE_COUNT=$((ISSUE_COUNT + 1))
sleep 1  # Rate limiting

# Issue 44: [M11] Multi-tenant architecture...
echo "Creating issue 44/54: [M11] Multi-tenant architecture..."
gh issue create \
  --repo "$REPO" \
  --title "[M11] Multi-tenant architecture" \
  --body "## Description

Feature for **Milestone 11: Enterprise Features**

**Timeline**: 28-30+ weeks

### Feature
Multi-tenant architecture

### Related Documentation

- [Milestone 11](../ROADMAP.md#milestone-11-enterprise-features)

---
*This issue was auto-generated from the DMARQ roadmap.*" \
  --label "enhancement,milestone-11,priority: low" || echo "  Failed to create issue 44"

ISSUE_COUNT=$((ISSUE_COUNT + 1))
sleep 1  # Rate limiting

# Issue 45: [M11] API rate limiting...
echo "Creating issue 45/54: [M11] API rate limiting..."
gh issue create \
  --repo "$REPO" \
  --title "[M11] API rate limiting" \
  --body "## Description

Feature for **Milestone 11: Enterprise Features**

**Timeline**: 28-30+ weeks

### Feature
API rate limiting

### Related Documentation

- [Milestone 11](../ROADMAP.md#milestone-11-enterprise-features)

---
*This issue was auto-generated from the DMARQ roadmap.*" \
  --label "enhancement,milestone-11,priority: low" || echo "  Failed to create issue 45"

ISSUE_COUNT=$((ISSUE_COUNT + 1))
sleep 1  # Rate limiting

# Issue 46: [M11] Advanced RBAC...
echo "Creating issue 46/54: [M11] Advanced RBAC..."
gh issue create \
  --repo "$REPO" \
  --title "[M11] Advanced RBAC" \
  --body "## Description

Feature for **Milestone 11: Enterprise Features**

**Timeline**: 28-30+ weeks

### Feature
Advanced RBAC

### Related Documentation

- [Milestone 11](../ROADMAP.md#milestone-11-enterprise-features)

---
*This issue was auto-generated from the DMARQ roadmap.*" \
  --label "enhancement,milestone-11,priority: low" || echo "  Failed to create issue 46"

ISSUE_COUNT=$((ISSUE_COUNT + 1))
sleep 1  # Rate limiting

# Issue 47: [M11] SSO integration (SAML, OAuth)...
echo "Creating issue 47/54: [M11] SSO integration (SAML, OAuth)..."
gh issue create \
  --repo "$REPO" \
  --title "[M11] SSO integration (SAML, OAuth)" \
  --body "## Description

Feature for **Milestone 11: Enterprise Features**

**Timeline**: 28-30+ weeks

### Feature
SSO integration (SAML, OAuth)

### Related Documentation

- [Milestone 11](../ROADMAP.md#milestone-11-enterprise-features)

---
*This issue was auto-generated from the DMARQ roadmap.*" \
  --label "enhancement,milestone-11,priority: low" || echo "  Failed to create issue 47"

ISSUE_COUNT=$((ISSUE_COUNT + 1))
sleep 1  # Rate limiting

# Issue 48: [M11] Compliance reporting (SOC 2, GDPR)...
echo "Creating issue 48/54: [M11] Compliance reporting (SOC 2, GDPR)..."
gh issue create \
  --repo "$REPO" \
  --title "[M11] Compliance reporting (SOC 2, GDPR)" \
  --body "## Description

Feature for **Milestone 11: Enterprise Features**

**Timeline**: 28-30+ weeks

### Feature
Compliance reporting (SOC 2, GDPR)

### Related Documentation

- [Milestone 11](../ROADMAP.md#milestone-11-enterprise-features)

---
*This issue was auto-generated from the DMARQ roadmap.*" \
  --label "enhancement,milestone-11,priority: low" || echo "  Failed to create issue 48"

ISSUE_COUNT=$((ISSUE_COUNT + 1))
sleep 1  # Rate limiting

# Issue 49: [M11] High availability setup...
echo "Creating issue 49/54: [M11] High availability setup..."
gh issue create \
  --repo "$REPO" \
  --title "[M11] High availability setup" \
  --body "## Description

Feature for **Milestone 11: Enterprise Features**

**Timeline**: 28-30+ weeks

### Feature
High availability setup

### Related Documentation

- [Milestone 11](../ROADMAP.md#milestone-11-enterprise-features)

---
*This issue was auto-generated from the DMARQ roadmap.*" \
  --label "enhancement,milestone-11,priority: low" || echo "  Failed to create issue 49"

ISSUE_COUNT=$((ISSUE_COUNT + 1))
sleep 1  # Rate limiting

# Issue 50: [M11] Backup and disaster recovery...
echo "Creating issue 50/54: [M11] Backup and disaster recovery..."
gh issue create \
  --repo "$REPO" \
  --title "[M11] Backup and disaster recovery" \
  --body "## Description

Feature for **Milestone 11: Enterprise Features**

**Timeline**: 28-30+ weeks

### Feature
Backup and disaster recovery

### Related Documentation

- [Milestone 11](../ROADMAP.md#milestone-11-enterprise-features)

---
*This issue was auto-generated from the DMARQ roadmap.*" \
  --label "enhancement,milestone-11,priority: low" || echo "  Failed to create issue 50"

ISSUE_COUNT=$((ISSUE_COUNT + 1))
sleep 1  # Rate limiting

# Issue 51: [Continuous] Code Quality Improvements...
echo "Creating issue 51/54: [Continuous] Code Quality Improvements..."
gh issue create \
  --repo "$REPO" \
  --title "[Continuous] Code Quality Improvements" \
  --body "## Description

Ongoing code quality tasks to maintain and improve DMARQ.

### Tasks

- [ ] Maintain >80% test coverage
- [ ] Regular dependency updates
- [ ] Code review for all changes
- [ ] Performance optimization
- [ ] Technical debt reduction

### Related Documentation

- [Continuous Improvements](../ROADMAP.md#continuous-improvements-ongoing)

---
*This issue was auto-generated from the DMARQ roadmap.*" \
  --label "maintenance,continuous-improvement,code-quality" || echo "  Failed to create issue 51"

ISSUE_COUNT=$((ISSUE_COUNT + 1))
sleep 1  # Rate limiting

# Issue 52: [Continuous] Security Improvements...
echo "Creating issue 52/54: [Continuous] Security Improvements..."
gh issue create \
  --repo "$REPO" \
  --title "[Continuous] Security Improvements" \
  --body "## Description

Ongoing security tasks to maintain and improve DMARQ.

### Tasks

- [ ] Monthly security audits
- [ ] Automated vulnerability scanning (GitHub Actions)
- [ ] Dependency security monitoring
- [ ] Regular penetration testing
- [ ] Security training for contributors

### Related Documentation

- [Continuous Improvements](../ROADMAP.md#continuous-improvements-ongoing)

---
*This issue was auto-generated from the DMARQ roadmap.*" \
  --label "maintenance,continuous-improvement,security" || echo "  Failed to create issue 52"

ISSUE_COUNT=$((ISSUE_COUNT + 1))
sleep 1  # Rate limiting

# Issue 53: [Continuous] Documentation Improvements...
echo "Creating issue 53/54: [Continuous] Documentation Improvements..."
gh issue create \
  --repo "$REPO" \
  --title "[Continuous] Documentation Improvements" \
  --body "## Description

Ongoing documentation tasks to maintain and improve DMARQ.

### Tasks

- [ ] Keep documentation current
- [ ] API documentation completeness
- [ ] Security best practices guide
- [ ] Deployment playbooks
- [ ] Troubleshooting guides

### Related Documentation

- [Continuous Improvements](../ROADMAP.md#continuous-improvements-ongoing)

---
*This issue was auto-generated from the DMARQ roadmap.*" \
  --label "maintenance,continuous-improvement,documentation" || echo "  Failed to create issue 53"

ISSUE_COUNT=$((ISSUE_COUNT + 1))
sleep 1  # Rate limiting

# Issue 54: [Continuous] Community Improvements...
echo "Creating issue 54/54: [Continuous] Community Improvements..."
gh issue create \
  --repo "$REPO" \
  --title "[Continuous] Community Improvements" \
  --body "## Description

Ongoing community tasks to maintain and improve DMARQ.

### Tasks

- [ ] Issue triage and response
- [ ] PR review and merging
- [ ] Community engagement
- [ ] Feature request evaluation
- [ ] Bug fix prioritization

### Related Documentation

- [Continuous Improvements](../ROADMAP.md#continuous-improvements-ongoing)

---
*This issue was auto-generated from the DMARQ roadmap.*" \
  --label "maintenance,continuous-improvement" || echo "  Failed to create issue 54"

ISSUE_COUNT=$((ISSUE_COUNT + 1))
sleep 1  # Rate limiting

echo ""
echo "Done! Created $ISSUE_COUNT issues."
echo ""
echo "Next steps:"
echo "1. Review the created issues at: https://github.com/$REPO/issues"
echo "2. Create milestones if needed"
echo "3. Assign issues to milestones and team members"
echo "4. Start working on the Security Remediation Sprint first!"