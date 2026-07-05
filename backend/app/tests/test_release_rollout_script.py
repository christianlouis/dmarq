import importlib.util
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]


def _load_script_module():
    script_path = REPO_ROOT / "scripts" / "check_release_rollout.py"
    spec = importlib.util.spec_from_file_location("check_release_rollout", script_path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def test_release_rollout_compare_accepts_matching_prefixes():
    module = _load_script_module()

    failures = module._compare(  # pylint: disable=protected-access
        {
            "version": "1.2.3",
            "environment": "demo",
            "build": {
                "sha": "abcdef1234567890",
                "short_sha": "abcdef123456",
                "image": "ghcr.io/christianlouis/dmarq:abcdef1",
            },
        },
        expected_version="1.2.3",
        expected_sha="abcdef1",
        expected_image="ghcr.io/christianlouis/dmarq:abcdef1",
        expected_environment="demo",
    )

    assert failures == []


def test_release_rollout_compare_reports_drift():
    module = _load_script_module()

    failures = module._compare(  # pylint: disable=protected-access
        {
            "version": "1.2.3",
            "environment": "production",
            "build": {
                "short_sha": "abcdef123456",
                "image": "ghcr.io/christianlouis/dmarq:abcdef1",
            },
        },
        expected_version="1.2.4",
        expected_sha="deadbee",
        expected_image="ghcr.io/christianlouis/dmarq:deadbee",
        expected_environment="demo",
    )

    assert any("version expected 1.2.4" in failure for failure in failures)
    assert any("environment expected demo" in failure for failure in failures)
    assert any("build SHA expected prefix deadbee" in failure for failure in failures)
    assert any(
        "image expected ghcr.io/christianlouis/dmarq:deadbee" in failure for failure in failures
    )


def test_release_workflow_build_metadata_uses_checked_out_ref():
    """Docker build metadata must describe the commit used to build the image."""
    workflow = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    assert "FULL_SHA=$(git rev-parse HEAD)" in workflow
    assert "DMARQ_BUILD_SHA=${{ steps.release_ref.outputs.full_sha }}" in workflow
    assert "DMARQ_BUILD_REF=${{ steps.release_ref.outputs.build_ref }}" in workflow
    assert "DMARQ_BUILD_DATE=${{ steps.release_ref.outputs.build_date }}" in workflow
    build_args = workflow.split("build-args: |", maxsplit=1)[1].split("cache-from:", maxsplit=1)[0]
    assert "github.sha" not in build_args
    assert "github.ref_name" not in build_args
    assert "github.event.head_commit.timestamp" not in build_args


def test_release_workflow_skips_gitops_for_stale_main_runs():
    """Older main CI runs must not roll GitOps manifests back after main advances."""
    workflow = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    assert workflow.count("Confirm source ref is still current") == 2
    assert workflow.count("https://api.github.com/repos/${{ github.repository }}/commits/main") == 2
    assert workflow.count("Skipping GitOps update because main advanced") == 2
    assert (
        workflow.count("Skipping GitOps update because the current main SHA could not be resolved")
        == 2
    )
    assert workflow.count("steps.source-ref.outputs.current == 'true'") == 6
    assert (
        'if [ "${{ github.event_name }}" != "push" ] || '
        '[ "${{ github.ref }}" != "refs/heads/main" ]; then'
    ) in workflow


def test_release_workflow_dispatches_gitops_deploy_after_release():
    """Semantic-release commits must trigger the deploy workflow explicitly."""
    workflow = (REPO_ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")

    assert "actions: write" in workflow
    assert "id: semantic" in workflow
    assert "steps.semantic.outputs.released == 'true'" in workflow
    assert "gh workflow run ci.yml" in workflow
    assert 'release_ref="${RELEASE_TAG}"' in workflow
    assert 'release_tag="${RELEASE_TAG}"' in workflow
    assert "-f deploy_gitops=true" in workflow
