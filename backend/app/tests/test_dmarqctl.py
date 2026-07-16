import json
import shutil
import sys
from pathlib import Path
from types import SimpleNamespace

ROOT_DIR = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT_DIR))

from scripts import dmarqctl  # noqa: E402

EXAMPLE_CONFIG = ROOT_DIR / "docs/deployment/examples/agent-install.compose.json"
KUBERNETES_CONFIG = ROOT_DIR / "docs/deployment/examples/agent-install.kubernetes.json"
SCHEMA = ROOT_DIR / "docs/deployment/schemas/install-v1.schema.json"


def _config():
    return json.loads(EXAMPLE_CONFIG.read_text(encoding="utf-8"))


def _kubernetes_config():
    return json.loads(KUBERNETES_CONFIG.read_text(encoding="utf-8"))


def _environment_values(path):
    values = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            key, value = stripped.split("=", 1)
            values[key] = value.strip().strip('"').strip("'")
    return values


def test_install_contract_schema_and_example_are_versioned():
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    config = _config()

    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["properties"]["schemaVersion"]["const"] == "1"
    assert config["schemaVersion"] == "1"
    assert dmarqctl.validate_config(config) == []
    assert dmarqctl.validate_config(_kubernetes_config()) == []


def test_validate_config_rejects_unknown_and_incomplete_inputs():
    errors = dmarqctl.validate_config(
        {
            "schemaVersion": "2",
            "deployment": {"mode": "shell", "publicBaseUrl": "localhost"},
            "product": {"profile": "unknown", "ownerEmail": "invalid"},
            "unexpected": True,
        }
    )

    assert {error["code"] for error in errors} >= {
        "unknown_field",
        "unsupported_version",
        "invalid_choice",
        "invalid_url",
        "invalid_email",
    }


def test_bootstrap_is_idempotent_and_does_not_return_secrets(tmp_path):
    shutil.copy(ROOT_DIR / ".env.example", tmp_path / ".env.example")
    config = _config()

    first = dmarqctl.bootstrap(config, tmp_path, start=False)
    env_path = tmp_path / ".env"
    first_contents = env_path.read_text(encoding="utf-8")
    second = dmarqctl.bootstrap(config, tmp_path, start=False)
    second_contents = env_path.read_text(encoding="utf-8")
    values = _environment_values(env_path)

    assert first["status"] == "configured"
    assert first["environmentUnchanged"] is False
    assert second["environmentUnchanged"] is True
    assert first_contents == second_contents
    assert env_path.stat().st_mode & 0o777 == 0o600
    assert len(values["SECRET_KEY"]) == 64
    assert len(values["ADMIN_API_KEY"]) == 64
    assert len(values["POSTGRES_PASSWORD"]) == 64
    serialized = json.dumps(first) + json.dumps(second)
    assert values["SECRET_KEY"] not in serialized
    assert values["ADMIN_API_KEY"] not in serialized
    assert values["POSTGRES_PASSWORD"] not in serialized


def test_bootstrap_reads_secret_reference_without_echoing_it(tmp_path, monkeypatch):
    shutil.copy(ROOT_DIR / ".env.example", tmp_path / ".env.example")
    config = _config()
    config["secrets"]["secretKey"] = {"env": "DMARQ_TEST_SECRET"}
    monkeypatch.setenv("DMARQ_TEST_SECRET", "a" * 64)

    result = dmarqctl.bootstrap(config, tmp_path, start=False)
    values = _environment_values(tmp_path / ".env")

    assert values["SECRET_KEY"] == "a" * 64
    assert "a" * 64 not in json.dumps(result)


def test_bootstrap_supports_custom_env_file_and_url_encodes_database_secret(
    tmp_path,
    monkeypatch,
):
    shutil.copy(ROOT_DIR / ".env.example", tmp_path / ".env.example")
    config = _config()
    config["deployment"]["envFile"] = "config/dmarq.env"
    config["secrets"]["databasePassword"] = {"env": "DMARQ_TEST_DATABASE_PASSWORD"}
    monkeypatch.setenv("DMARQ_TEST_DATABASE_PASSWORD", "space and@colon:")

    result = dmarqctl.bootstrap(config, tmp_path, start=False)
    env_path = tmp_path / "config/dmarq.env"
    values = _environment_values(env_path)

    assert result["environmentFile"] == str(env_path)
    assert values["DMARQ_ENV_FILE"] == "config/dmarq.env"
    assert values["POSTGRES_PASSWORD"] == "space and@colon:"
    assert "space%20and%40colon%3A" in values["DATABASE_URL"]


def test_bootstrap_rejects_env_file_outside_project(tmp_path):
    shutil.copy(ROOT_DIR / ".env.example", tmp_path / ".env.example")
    config = _config()
    config["deployment"]["envFile"] = "../outside.env"

    try:
        dmarqctl.bootstrap(config, tmp_path, start=False)
    except dmarqctl.ControlError as exc:
        assert exc.code == "environment_path_outside_project"
        assert exc.exit_code == dmarqctl.EXIT_INVALID_CONFIG
    else:
        raise AssertionError("Expected environment path traversal to be rejected")


def test_bootstrap_rejects_multiline_environment_secret(tmp_path, monkeypatch):
    shutil.copy(ROOT_DIR / ".env.example", tmp_path / ".env.example")
    config = _config()
    config["secrets"]["secretKey"] = {"env": "DMARQ_TEST_SECRET"}
    monkeypatch.setenv("DMARQ_TEST_SECRET", "line-one\nline-two")

    try:
        dmarqctl.bootstrap(config, tmp_path, start=False)
    except dmarqctl.ControlError as exc:
        assert exc.code == "environment_value_not_env_safe"
        assert exc.exit_code == dmarqctl.EXIT_INVALID_CONFIG
    else:
        raise AssertionError("Expected multiline environment secret to be rejected")


def test_bootstrap_preserves_dollar_sign_in_referenced_secret(tmp_path, monkeypatch):
    shutil.copy(ROOT_DIR / ".env.example", tmp_path / ".env.example")
    config = _config()
    config["secrets"]["secretKey"] = {"env": "DMARQ_TEST_SECRET"}
    monkeypatch.setenv("DMARQ_TEST_SECRET", "literal$dollar$value")

    dmarqctl.bootstrap(config, tmp_path, start=False)
    first = (tmp_path / ".env").read_text(encoding="utf-8")
    result = dmarqctl.bootstrap(config, tmp_path, start=False)

    assert result["environmentUnchanged"] is True
    assert (tmp_path / ".env").read_text(encoding="utf-8") == first
    assert _environment_values(tmp_path / ".env")["SECRET_KEY"] == "literal$dollar$value"


def test_preflight_returns_structured_checks(tmp_path, monkeypatch):
    monkeypatch.setattr(dmarqctl, "_compose_available", lambda: True)
    monkeypatch.setattr(dmarqctl, "_port_available", lambda _address, _port: True)
    monkeypatch.setattr(dmarqctl.platform, "machine", lambda: "arm64")

    result = dmarqctl.preflight(_config(), tmp_path)

    assert result["status"] == "ready"
    assert [check["code"] for check in result["checks"]] == [
        "architecture_supported",
        "docker_compose_available",
        "listen_port_available",
        "project_directory_writable",
    ]
    assert all(check["status"] == "pass" for check in result["checks"])


def test_kubernetes_preflight_checks_tools_context_chart_and_secret(monkeypatch):
    def command_result(command, **_kwargs):
        if command[:3] == ["kubectl", "config", "current-context"]:
            return SimpleNamespace(returncode=0, stdout="kind-dmarq\n", stderr="")
        return SimpleNamespace(returncode=0, stdout="ok\n", stderr="")

    monkeypatch.setattr(dmarqctl, "_command_result", command_result)
    monkeypatch.setattr(dmarqctl.platform, "machine", lambda: "arm64")

    result = dmarqctl.preflight(_kubernetes_config(), ROOT_DIR)

    assert result["status"] == "ready"
    assert [check["code"] for check in result["checks"]] == [
        "architecture_supported",
        "helm_available",
        "kubernetes_context_available",
        "helm_chart_available",
        "kubernetes_secret_available",
        "project_directory_writable",
    ]
    assert "kind-dmarq" in result["checks"][2]["message"]


def test_kubernetes_bootstrap_uses_non_secret_temporary_values(monkeypatch):
    captured = {}

    def command_result(command, **_kwargs):
        values_path = Path(command[command.index("--values") + 1])
        captured["command"] = command
        captured["valuesPath"] = values_path
        captured["values"] = json.loads(values_path.read_text(encoding="utf-8"))
        return SimpleNamespace(returncode=0, stdout="deployed\n", stderr="")

    monkeypatch.setattr(dmarqctl, "_command_result", command_result)

    result = dmarqctl.bootstrap(_kubernetes_config(), ROOT_DIR, start=True)

    assert result["status"] == "ready"
    assert result["deploymentMode"] == "kubernetes"
    assert captured["command"][:3] == ["helm", "upgrade", "--install"]
    assert captured["values"]["existingSecret"] == "dmarq"
    assert captured["values"]["bootstrap"]["ownerEmail"] == "owner@example.com"
    assert "secretKey" not in json.dumps(captured["values"])
    assert not captured["valuesPath"].exists()


def test_compose_command_falls_back_to_standalone_binary(monkeypatch):
    monkeypatch.setattr(
        dmarqctl.shutil,
        "which",
        lambda command: f"/usr/bin/{command}" if command in {"docker", "docker-compose"} else None,
    )

    def fake_run(command, **_kwargs):
        return SimpleNamespace(returncode=0 if command[0] == "docker-compose" else 1)

    monkeypatch.setattr(dmarqctl.subprocess, "run", fake_run)

    assert dmarqctl._compose_command() == ["docker-compose"]


def test_bootstrap_can_start_and_complete_setup_without_browser(tmp_path, monkeypatch):
    shutil.copy(ROOT_DIR / ".env.example", tmp_path / ".env.example")
    calls = []
    monkeypatch.setattr(dmarqctl, "_compose_available", lambda: True)
    monkeypatch.setattr(
        dmarqctl,
        "_start_compose",
        lambda root, env_path: calls.append((root, env_path)),
    )
    monkeypatch.setattr(dmarqctl, "_complete_setup", lambda _config: True)

    result = dmarqctl.bootstrap(_config(), tmp_path, start=True)

    assert result["status"] == "ready"
    assert result["started"] is True
    assert result["setupCompletedNow"] is True
    assert calls[0] == (tmp_path, tmp_path / ".env")


def test_bootstrap_can_configure_an_already_running_instance(tmp_path, monkeypatch):
    shutil.copy(ROOT_DIR / ".env.example", tmp_path / ".env.example")
    monkeypatch.setattr(dmarqctl, "_complete_setup", lambda _config: True)

    result = dmarqctl.bootstrap(
        _config(),
        tmp_path,
        start=False,
        setup_existing=True,
    )

    assert result["status"] == "ready"
    assert result["started"] is False
    assert result["configuredExistingInstance"] is True
    assert result["setupCompletedNow"] is True


def test_status_returns_machine_readable_release_and_intake_state(monkeypatch):
    responses = {
        "/healthz": {"status": "healthy"},
        "/api/v1/setup/status": {
            "is_setup_complete": True,
            "total_domains": 2,
            "total_mail_sources": 1,
            "enabled_mail_sources": 1,
        },
        "/api/v1/health/release": {
            "version": "1.2.3",
            "image": "ghcr.io/christianlouis/dmarq:sha-test",
            "git_ref": "abc123",
        },
    }
    monkeypatch.setattr(
        dmarqctl,
        "_request_json",
        lambda _base_url, path, **_kwargs: responses[path],
    )

    result = dmarqctl.status(_config())

    assert result == {
        "command": "status",
        "status": "ready",
        "publicBaseUrl": "http://127.0.0.1:8080",
        "health": "healthy",
        "setupComplete": True,
        "domains": 2,
        "mailSources": 1,
        "enabledMailSources": 1,
        "release": {
            "version": "1.2.3",
            "image": "ghcr.io/christianlouis/dmarq:sha-test",
            "gitRef": "abc123",
        },
        "errors": [],
    }


def test_main_uses_stable_exit_code_for_invalid_config(tmp_path, capsys):
    config_path = tmp_path / "invalid.json"
    config_path.write_text("{}", encoding="utf-8")

    exit_code = dmarqctl.main(["--config", str(config_path), "--json", "preflight"])
    output = json.loads(capsys.readouterr().out)

    assert exit_code == dmarqctl.EXIT_INVALID_CONFIG
    assert output["status"] == "invalid"
    assert output["command"] == "preflight"
