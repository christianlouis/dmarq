# CI/CD Pipeline

DMARQ uses GitHub Actions for all continuous integration and delivery tasks.
The pipeline is defined in two workflow files:

| File | Purpose | Triggers |
|------|---------|----------|
| `.github/workflows/ci.yml` | Lint → Test → Security → Docker → GitOps | Push to `main`/`develop`, pull requests, weekly schedule |
| `.github/workflows/release.yml` | Semantic versioning & changelog | Push to `main` |

Use the [Release Checklist](../deployment/release-checklist.md) before merging production changes and after the deployment updates.

---

## Pipeline Stages

### Stage 1 — Lint (blocking gate)

All subsequent jobs depend on this stage succeeding.

| Tool | What it checks |
|------|---------------|
| **Black** | Code formatting (line length 100, target Python 3.13) |
| **isort** | Import ordering (Black-compatible profile) |
| **Flake8** | Style and complexity (`max-complexity=10`, E203/W503/E501 ignored) |
| **Pylint** | Deeper static analysis (`continue-on-error` — advisory only) |

The lint job auto-formats with Black and isort before running the `--check`
step, so a failing lint job is usually caused by a Flake8 or Pylint issue.

### Stage 2 — Parallel quality gates

These jobs run in parallel once lint passes.

#### Test

```bash
cd backend
pytest --cov=app --cov-report=xml --cov-report=term-missing
```

Coverage results are uploaded to [Codecov](https://codecov.io).

#### Security Scan

- **Bandit** — Python security linter; the JSON report is uploaded as a
  workflow artifact (`bandit-security-report`) for every run.
- **pip-audit** — checks all packages in `backend/requirements.txt` against
  known CVE databases.

Both steps use `continue-on-error: true` so they are advisory; a finding will
not block the build but will appear in the workflow summary.

#### CodeQL Analysis

GitHub's semantic code analysis scans the Python source for known vulnerability
patterns (security and quality queries).  Runs on push and PR events only —
skipped on the weekly scheduled scan.

#### Dependency Review

Runs on pull requests only.  Fails if any new dependency introduces a
vulnerability of `moderate` severity or higher.

### Stage 3 — Docker Build & Publish

Runs only on pushes to `main` after both **Test** and **Security** pass.

- Builds from `./backend/Dockerfile`
- Builds the static Tailwind/DaisyUI CSS bundle from `backend/package.json`
  before the Python runtime image is assembled. Production pages must load
  `/static/css/app.css` and must not load the Tailwind browser compiler.
- Pushes to `ghcr.io/<owner>/dmarq` with three tags:
  - `latest` (default branch only)
  - branch name (e.g. `main`)
  - short commit SHA (e.g. `a1b2c3d`)
- Layer cache is stored via GitHub Actions cache (`type=gha`).
- Injects safe build metadata into the image:
  - `DMARQ_BUILD_SHA`
  - `DMARQ_BUILD_REF`
  - `DMARQ_BUILD_IMAGE`
  - `DMARQ_BUILD_DATE`

The running app exposes the same metadata in the release modal and at
`/api/v1/health/release`. Operators should use that endpoint, not assumptions
from GitHub alone, when deciding whether a fix is live.

### Stage 4 — GitOps (Update K8s Manifest)

Runs only on pushes to `main` after the Docker stage succeeds.

Updates the image tag in the GitOps manifests that Argo CD actually reconciles
for the self-hosted demo and preprod environments:

- `apps/dmarq/greenfield-demo/dmarq-stack.yaml` for `demo.dmarq.org`
- `apps/dmarq/greenfield-preprod/dmarq-stack.yaml` for `preprod.app.dmarq.org`

Production (`apps/dmarq/prod/dmarq-stack.yaml` for `app.dmarq.org`) is not
updated automatically by this stage. Promote the tested image to production with
an explicit GitOps change after reviewing the release.

### Rollout drift checks

After demo, preprod, or production is reconciled, check the live release endpoint
against the expected image or commit:

```bash
python3 scripts/check_release_rollout.py \
  --base-url https://demo.dmarq.org \
  --expected-environment demo \
  --expected-sha a1b2c3d
```

For `app.dmarq.org`, use the image tag promoted in
`apps/dmarq/prod/dmarq-stack.yaml`. For `demo.dmarq.org`, use the image tag
written to `apps/dmarq/greenfield-demo/dmarq-stack.yaml`, and use the
environment label configured for that deployment. A mismatch means the
browser-visible app is behind GitOps or serving a different image than expected.

!!! note "Optional"
    This stage requires a `GH_PAT` repository secret with write access to the
    k8s-cluster-state repo.  If the secret is absent or lacks access the step
    emits a warning and skips gracefully — it will never fail the pipeline.

---

## Release Workflow

`release.yml` uses
[python-semantic-release](https://python-semantic-release.readthedocs.io/)
to automate versioning from
[Conventional Commits](https://www.conventionalcommits.org/):

- Bumps `version` in `pyproject.toml`
- Generates/updates `CHANGELOG.md`
- Creates a Git tag and a GitHub Release

Commit prefixes that trigger a release:

| Prefix | Version bump |
|--------|-------------|
| `fix:` | Patch (0.0.**x**) |
| `feat:` | Minor (0.**x**.0) |
| `feat!:` / `BREAKING CHANGE` | Major (**x**.0.0) |

---

## Scheduled Security Scan

A cron job runs every Monday at 00:00 UTC and executes the **Lint**,
**Security Scan**, and **Test** stages against the latest `main` code.
CodeQL and Dependency Review are skipped on schedule events.

---

## Troubleshooting

### Lint failure

1. Pull the latest branch and run locally:
   ```bash
   black backend/app
   isort backend/app
   flake8 backend/app
   ```
2. Commit the formatted files and push.

Pylint failures are advisory (`continue-on-error: true`) and will not block
the pipeline, but should still be investigated.

### Test failure

1. Reproduce locally:
   ```bash
   cd backend
   pytest --cov=app --cov-report=term-missing -x
   ```
2. Check the test output in the **Test** job log for the failing assertion and
   stack trace.
3. The coverage XML is not uploaded as an artifact — run locally to inspect
   `htmlcov/index.html`.

### Security scan failure

- **Bandit**: Download the `bandit-security-report` artifact from the workflow
  run's *Artifacts* panel and review `bandit-report.json`.
- **pip-audit**: The finding is printed directly to the job log.  Update or pin
  the affected dependency in `backend/requirements.txt`.

### Docker build failure

Common causes:

| Symptom | Fix |
|---------|-----|
| `pip install` error | Check `backend/requirements.txt` for unpinned or incompatible versions |
| `COPY` file not found | Ensure the file exists and is not listed in `.dockerignore` |
| Registry auth failure | Verify the workflow has `packages: write` permission |

### Dependency Review failure (PR only)

The PR introduced a dependency with a known vulnerability.  Either:

- Remove the dependency, or
- Upgrade to a patched version, or
- If the finding is a false positive, discuss with a maintainer — the severity
  threshold (`moderate`) can be adjusted in the workflow.

### Release workflow not triggering

Ensure your merge commit message follows Conventional Commits.  The release
workflow only creates a new version when `python-semantic-release` detects a
`fix:`, `feat:`, or breaking-change commit since the last tag.
