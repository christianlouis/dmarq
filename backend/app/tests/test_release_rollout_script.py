import importlib.util
from pathlib import Path


def _load_script_module():
    script_path = Path(__file__).resolve().parents[3] / "scripts" / "check_release_rollout.py"
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
    assert any("image expected ghcr.io/christianlouis/dmarq:deadbee" in failure for failure in failures)
