# DMARQ Roadmap Issues

This directory contains auto-generated GitHub issues parsed from the DMARQ roadmap documents.

## 📊 Summary

**Total Issues Generated**: 54

### Breakdown by Category

- **Security Remediation Sprint**: 7 issues (CRITICAL/HIGH priority)
- **Milestone Features**: 43 issues (distributed across milestones 4-11)
- **Continuous Improvements**: 4 issues (ongoing maintenance)

## 📁 Files

### 1. `issues.json`
JSON-formatted issue data suitable for programmatic import or custom processing.

**Structure**:
```json
[
  {
    "title": "Issue title",
    "body": "Issue description in markdown",
    "labels": ["label1", "label2"],
    "milestone": "Milestone name",
    "assignees": []
  }
]
```

### 2. `issues_preview.md`
Human-readable preview of all issues, organized by milestone. Review this file to see what issues will be created.

### 3. `create_issues.sh`
Executable bash script that uses GitHub CLI to create all issues automatically.

## 🚀 How to Create Issues

### Option 1: Using GitHub CLI (Recommended)

**Prerequisites**:
- Install [GitHub CLI](https://cli.github.com/)
- Authenticate: `gh auth login`

**Steps**:
```bash
cd generated_issues
./create_issues.sh
```

The script will:
- Check if GitHub CLI is installed and authenticated
- Create all 54 issues in the `christianlouis/dmarq` repository
- Apply appropriate labels to each issue
- Add rate limiting (1 second between issues) to avoid API throttling

**Note**: The script does NOT create milestones automatically. See section below.

### Option 2: Manual Creation

Review `issues_preview.md` and manually create issues through the GitHub web interface.

### Option 3: Custom Import

Use `issues.json` with your own tooling or GitHub API integration.

## 🏷️ Milestones

The following milestones are referenced in the issues. You may want to create these in GitHub before running the import script:

1. **Security Remediation Sprint** (7 issues) - 🔴 PRIORITY
2. **Milestone 4: Enhanced Dashboard & Visualization** (6 issues)
3. **Milestone 5: User Authentication & Multi-User Support** (6 issues)
4. **Milestone 6: Alerting & Notifications** (5 issues)
5. **Milestone 7: Advanced Rule Engine** (5 issues)
6. **Milestone 8: DNS Health & Cloudflare Integration** (5 issues)
7. **Milestone 9: Forensic Reports (RUF) Support** (5 issues)
8. **Milestone 10: Advanced Analytics & Reporting** (5 issues)
9. **Milestone 11: Enterprise Features** (6 issues)
10. **Continuous Improvements** (4 issues)

**To create milestones using GitHub CLI**:
```bash
gh milestone create "Security Remediation Sprint" --repo christianlouis/dmarq
gh milestone create "Milestone 4: Enhanced Dashboard & Visualization" --repo christianlouis/dmarq
# ... etc
```

Or create them through the GitHub web interface: https://github.com/christianlouis/dmarq/milestones

## 🏷️ Labels

The issues use the following labels (you may need to create some):

### Priority Labels
- `priority: critical` - Must be addressed immediately
- `priority: high` - Important, should be addressed soon
- `priority: medium` - Normal priority
- `priority: low` - Can be deferred

### Type Labels
- `security` - Security-related issues
- `security: critical` - Critical security vulnerabilities
- `security: high` - High-severity security issues
- `enhancement` - New features or improvements
- `maintenance` - Ongoing maintenance tasks
- `continuous-improvement` - Part of continuous improvement process
- `documentation` - Documentation updates
- `code-quality` - Code quality improvements

### Milestone Labels
- `milestone-4` through `milestone-11` - Associate with specific milestones

## 📋 Issue Organization

### Security Sprint (Start Here!)
The Security Remediation Sprint contains 7 critical security issues that should be addressed **first**:

1. Authentication & Authorization (CRITICAL)
2. Secret Management (CRITICAL)
3. XML Parsing Security (HIGH)
4. Input Validation (HIGH)
5. Security Headers (MEDIUM)
6. CORS Configuration (MEDIUM)
7. Error Handling (MEDIUM)

### Milestone Features
Features are organized by milestone (4-11), with Milestone 4 being the next to implement after security fixes.

### Continuous Improvements
Four ongoing improvement categories:
- Code Quality
- Security
- Documentation
- Community

## 🔄 Regenerating Issues

If you need to regenerate issues after modifying the roadmap:

```bash
cd /home/runner/work/dmarq/dmarq
python3 scripts/generate_issues.py
```

This will overwrite the files in this directory.

## ⚙️ Customization

### Modifying the Generator

Edit `/home/runner/work/dmarq/dmarq/scripts/generate_issues.py` to customize:
- Issue title formats
- Body templates
- Label assignments
- Milestone mappings

### Filtering Issues

To create only specific issues:

**Security issues only**:
```bash
jq '.[] | select(.labels[] | contains("security"))' issues.json
```

**Specific milestone**:
```bash
jq '.[] | select(.milestone == "Milestone 4: Enhanced Dashboard & Visualization")' issues.json
```

**High priority only**:
```bash
jq '.[] | select(.labels[] | contains("priority: high"))' issues.json
```

## 🎯 Recommended Workflow

1. **Review**: Read through `issues_preview.md` to understand all issues
2. **Create Milestones**: Set up milestones in GitHub
3. **Create Labels**: Ensure all required labels exist
4. **Import Security Issues First**: Consider importing just the Security Sprint issues first
5. **Import Remaining Issues**: Create the rest of the issues
6. **Organize**: Assign issues to milestones and team members
7. **Prioritize**: Adjust priorities based on your team's capacity

## 📞 Support

- **Source**: Generated from [ROADMAP.md](../ROADMAP.md)
- **Script**: [scripts/generate_issues.py](../scripts/generate_issues.py)
- **Questions**: Open an issue in the DMARQ repository

## 🔒 Important Notes

### Security Priority
The Security Remediation Sprint issues are marked as CRITICAL and HIGH priority. These should be addressed **before** implementing new features to ensure the application is secure.

### Milestone Dependencies
Some milestones depend on others:
- Milestone 5 (Authentication) is required before several later features
- Security Sprint should be completed before Milestone 4
- See the roadmap for detailed dependency information

### Rate Limiting
The import script includes rate limiting (1 second between API calls) to avoid GitHub API throttling. Creating all 54 issues will take approximately 1-2 minutes.

---

**Generated**: 2026-02-06  
**Script Version**: 1.0  
**Issues Count**: 54
