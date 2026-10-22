from __future__ import annotations

import importlib.util
import os
import subprocess
from pathlib import Path

import pytest

_VALIDATOR = Path(__file__).parents[1] / "validate-requirements-lock.py"
_spec = importlib.util.spec_from_file_location("validate_requirements_lock", _VALIDATOR)
assert _spec and _spec.loader
validate_requirements_lock = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(validate_requirements_lock)


def test_validator_accepts_exact_satisfying_pin(tmp_path, monkeypatch):
    req = tmp_path / "requirements.txt"
    lock = tmp_path / "requirements.lock"
    req.write_text("Demo>=1.0\n")
    lock.write_text("Demo==1.2\n")
    monkeypatch.setattr("sys.argv", ["validate", str(req), str(lock)])
    assert validate_requirements_lock.main() == 0


@pytest.mark.parametrize(
    "lock, expected",
    [
        ("Other==1.2\n", "missing lock entry"),
        ("Demo==0.9\n", "does not satisfy"),
        ("Demo>=1.2\n", "exact == pin"),
        ("Demo==1.2.*\n", "exact == pin"),
        ("Demo==1.2\nOther>=2.0\n", "exact == pin"),
        ("Demo==1.2\nDemo==1.3\n", "duplicate lock entry"),
    ],
)
def test_validator_rejects_invalid_lock(tmp_path, monkeypatch, lock, expected):
    req = tmp_path / "requirements.txt"
    locked = tmp_path / "requirements.lock"
    req.write_text("Demo>=1.0\n")
    locked.write_text(lock)
    monkeypatch.setattr("sys.argv", ["validate", str(req), str(locked)])
    with pytest.raises(SystemExit, match=expected):
        validate_requirements_lock.main()


def test_generator_failure_preserves_existing_lock(tmp_path):
    root = tmp_path / "repo"
    (root / "backend").mkdir(parents=True)
    (root / "scripts").mkdir()
    script = Path(__file__).parents[1] / "lock-requirements.sh"
    target = root / "scripts" / "lock-requirements.sh"
    target.write_bytes(script.read_bytes())
    target.chmod(0o755)
    (root / "backend" / "requirements.txt").write_text("Demo>=1.0\n")
    lock = root / "backend" / "requirements.lock"
    lock.write_text("sentinel\n")
    docker = root / "docker"
    docker.write_text("#!/bin/sh\nexit 42\n")
    docker.chmod(0o755)
    env = os.environ | {"PATH": f"{root}:{os.environ['PATH']}"}
    result = subprocess.run([str(target)], env=env, text=True, capture_output=True)
    assert result.returncode == 42
    assert lock.read_text() == "sentinel\n"


def test_generator_inspect_failure_preserves_existing_lock(tmp_path):
    root = tmp_path / "repo"
    (root / "backend").mkdir(parents=True)
    (root / "scripts").mkdir()
    script = Path(__file__).parents[1] / "lock-requirements.sh"
    target = root / "scripts" / "lock-requirements.sh"
    target.write_bytes(script.read_bytes())
    target.chmod(0o755)
    (root / "backend" / "requirements.txt").write_text("Demo>=1.0\n")
    lock = root / "backend" / "requirements.lock"
    lock.write_text("sentinel\n")
    docker = root / "docker"
    docker.write_text(
        "#!/bin/sh\n"
        'case "$1" in\n'
        "  run) printf 'Demo==1.2\\n' ;;\n"
        "  image) exit 42 ;;\n"
        "esac\n"
    )
    docker.chmod(0o755)
    env = os.environ | {"PATH": f"{root}:{os.environ['PATH']}"}
    result = subprocess.run([str(target)], env=env, text=True, capture_output=True)
    assert result.returncode == 42
    assert lock.read_text() == "sentinel\n"
