#!/usr/bin/env python3
"""Non-interactive DMARQ installation and readiness control surface."""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, Iterable, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen

EXIT_OK = 0
EXIT_INVALID_CONFIG = 2
EXIT_PREFLIGHT_FAILED = 3
EXIT_NOT_READY = 4
EXIT_OPERATION_FAILED = 5

ROOT_DIR = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = ROOT_DIR / "docs/deployment/examples/agent-install.compose.json"
DEFAULT_IMAGE = "ghcr.io/christianlouis/dmarq:docker-stable"
PLACEHOLDERS = {
    "SECRET_KEY": "CHANGE_THIS_TO_A_RANDOM_SECRET_IN_PRODUCTION",
    "ADMIN_API_KEY": "CHANGE_THIS_TO_A_RANDOM_ADMIN_API_KEY",
    "POSTGRES_PASSWORD": "CHANGE_THIS_DOCKER_POSTGRES_PASSWORD",
}
SUPPORTED_ARCHITECTURES = {"x86_64", "amd64", "aarch64", "arm64"}


class ControlError(RuntimeError):
    """Structured operator error with a stable code and process exit status."""

    def __init__(self, code: str, message: str, exit_code: int) -> None:
        super().__init__(message)
        self.code = code
        self.exit_code = exit_code


def _emit(payload: Dict[str, Any], *, as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
        return
    status = str(payload.get("status", "unknown")).upper()
    print(f"DMARQ {payload.get('command', 'operation')}: {status}")
    for check in payload.get("checks", []):
        print(f"- {check['status']}: {check['code']} - {check['message']}")
    if payload.get("message"):
        print(payload["message"])


def _load_config(path: str) -> Dict[str, Any]:
    try:
        if path == "-":
            payload = json.load(sys.stdin)
        else:
            with Path(path).open(encoding="utf-8") as handle:
                payload = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise ControlError(
            "config_read_failed",
            f"Installation configuration could not be read: {type(exc).__name__}.",
            EXIT_INVALID_CONFIG,
        ) from exc
    if not isinstance(payload, dict):
        raise ControlError(
            "config_not_object",
            "Installation configuration must be a JSON object.",
            EXIT_INVALID_CONFIG,
        )
    return payload


def _validation_error(path: str, code: str, message: str) -> Dict[str, str]:
    return {"path": path, "code": code, "message": message}


def validate_config(config: Dict[str, Any]) -> list[Dict[str, str]]:  # noqa: C901
    """Validate the v1 contract without requiring third-party Python packages."""
    errors: list[Dict[str, str]] = []
    allowed_root = {"schemaVersion", "deployment", "product", "database", "secrets"}
    for key in sorted(set(config) - allowed_root):
        errors.append(_validation_error(key, "unknown_field", "Unknown top-level field."))
    if config.get("schemaVersion") != "1":
        errors.append(
            _validation_error("schemaVersion", "unsupported_version", "Expected schemaVersion 1.")
        )

    deployment = config.get("deployment")
    if not isinstance(deployment, dict):
        errors.append(_validation_error("deployment", "required_object", "Object is required."))
        deployment = {}
    mode = deployment.get("mode")
    if mode not in {"compose", "kubernetes"}:
        errors.append(
            _validation_error(
                "deployment.mode", "invalid_choice", "Expected compose or kubernetes."
            )
        )
    if mode == "kubernetes" and not deployment.get("existingSecret"):
        errors.append(
            _validation_error(
                "deployment.existingSecret",
                "required_for_kubernetes",
                "Kubernetes mode requires an existing Secret name.",
            )
        )
    public_base_url = deployment.get("publicBaseUrl")
    parsed_url = urlparse(str(public_base_url or ""))
    if parsed_url.scheme not in {"http", "https"} or not parsed_url.netloc:
        errors.append(
            _validation_error(
                "deployment.publicBaseUrl",
                "invalid_url",
                "An absolute HTTP or HTTPS URL is required.",
            )
        )
    port = deployment.get("port", 8080)
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        errors.append(
            _validation_error("deployment.port", "invalid_port", "Expected an integer 1-65535.")
        )

    product = config.get("product")
    if not isinstance(product, dict):
        errors.append(_validation_error("product", "required_object", "Object is required."))
        product = {}
    if product.get("profile") not in {"single-user", "multi-workspace", "provider"}:
        errors.append(
            _validation_error(
                "product.profile", "invalid_choice", "Unknown product installation profile."
            )
        )
    owner_email = product.get("ownerEmail")
    if not isinstance(owner_email, str) or "@" not in owner_email or owner_email.startswith("@"):
        errors.append(
            _validation_error(
                "product.ownerEmail", "invalid_email", "A valid owner email is required."
            )
        )
    authentication = product.get("authentication", {})
    if not isinstance(authentication, dict) or authentication.get("mode", "disabled") not in {
        "disabled",
        "logto",
        "oidc",
        "authentik",
        "trusted_proxy",
    }:
        errors.append(
            _validation_error(
                "product.authentication.mode", "invalid_choice", "Unknown authentication mode."
            )
        )

    database = config.get("database", {})
    if not isinstance(database, dict):
        errors.append(_validation_error("database", "invalid_object", "Expected an object."))
        database = {}
    database_mode = database.get("mode", "bundled")
    if database_mode not in {"bundled", "external"}:
        errors.append(
            _validation_error("database.mode", "invalid_choice", "Expected bundled or external.")
        )
    if database_mode == "external" and not database.get("urlEnv"):
        errors.append(
            _validation_error(
                "database.urlEnv",
                "required_for_external_database",
                "External database mode requires the environment variable name containing its URL.",
            )
        )

    secrets_config = config.get("secrets", {})
    if not isinstance(secrets_config, dict):
        errors.append(_validation_error("secrets", "invalid_object", "Expected an object."))
        secrets_config = {}
    for name in ("secretKey", "adminApiKey", "databasePassword"):
        source = secrets_config.get(name, {"generate": True})
        if not isinstance(source, dict) or not (
            source == {"generate": True}
            or (
                set(source) == {"env"}
                and isinstance(source.get("env"), str)
                and re.fullmatch(r"[A-Z_][A-Z0-9_]*", source["env"])
            )
        ):
            errors.append(
                _validation_error(
                    f"secrets.{name}",
                    "invalid_secret_source",
                    'Use either {"generate":true} or {"env":"VARIABLE_NAME"}.',
                )
            )
    return errors


def _check(code: str, status: str, message: str) -> Dict[str, str]:
    return {"code": code, "status": status, "message": message}


def _compose_command() -> Optional[list[str]]:
    candidates: list[list[str]] = []
    if shutil.which("docker"):
        candidates.append(["docker", "compose"])
    if shutil.which("docker-compose"):
        candidates.append(["docker-compose"])
    for candidate in candidates:
        try:
            completed = subprocess.run(
                [*candidate, "version"],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if completed.returncode == 0:
            return candidate
    return None


def _compose_available() -> bool:
    return _compose_command() is not None


def _command_result(command: list[str], *, timeout: int = 15) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return subprocess.CompletedProcess(command, 1, "", type(exc).__name__)


def _port_available(address: str, port: int) -> bool:
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as candidate:
            candidate.bind((address, port))
    except OSError:
        return False
    return True


def preflight(config: Dict[str, Any], root: Path) -> Dict[str, Any]:
    errors = validate_config(config)
    if errors:
        return {"command": "preflight", "status": "invalid", "errors": errors, "checks": []}

    deployment = config["deployment"]
    checks: list[Dict[str, str]] = []
    architecture = platform.machine().lower()
    checks.append(
        _check(
            "architecture_supported",
            "pass" if architecture in SUPPORTED_ARCHITECTURES else "fail",
            f"Host architecture is {architecture or 'unknown'}.",
        )
    )
    if deployment["mode"] == "compose":
        compose_available = _compose_available()
        checks.append(
            _check(
                "docker_compose_available",
                "pass" if compose_available else "fail",
                (
                    "Docker Compose is available."
                    if compose_available
                    else "Docker Compose is required."
                ),
            )
        )
        address = str(deployment.get("bindAddress", "127.0.0.1"))
        port = int(deployment.get("port", 8080))
        port_available = _port_available(address, port)
        checks.append(
            _check(
                "listen_port_available",
                "pass" if port_available else "fail",
                (
                    f"Listen address {address}:{port} is available."
                    if port_available
                    else f"Listen address {address}:{port} is already in use or unavailable."
                ),
            )
        )
    else:
        helm = _command_result(["helm", "version", "--short"])
        checks.append(
            _check(
                "helm_available",
                "pass" if helm.returncode == 0 else "fail",
                "Helm is available." if helm.returncode == 0 else "Helm is required.",
            )
        )
        context = _command_result(["kubectl", "config", "current-context"])
        context_name = context.stdout.strip()
        checks.append(
            _check(
                "kubernetes_context_available",
                "pass" if context.returncode == 0 and context_name else "fail",
                (
                    f"Kubernetes context is {context_name}."
                    if context.returncode == 0 and context_name
                    else "An active Kubernetes context is required."
                ),
            )
        )
        chart_path = (root / deployment.get("chartPath", "deploy/helm/dmarq")).resolve()
        chart_available = (chart_path / "Chart.yaml").is_file()
        checks.append(
            _check(
                "helm_chart_available",
                "pass" if chart_available else "fail",
                (
                    f"DMARQ Helm chart is available at {chart_path}."
                    if chart_available
                    else f"DMARQ Helm chart is missing at {chart_path}."
                ),
            )
        )
        namespace = str(deployment.get("namespace", "dmarq"))
        secret_name = str(deployment["existingSecret"])
        secret = _command_result(
            ["kubectl", "--namespace", namespace, "get", "secret", secret_name, "-o", "name"]
        )
        checks.append(
            _check(
                "kubernetes_secret_available",
                "pass" if secret.returncode == 0 else "fail",
                (
                    f"Kubernetes Secret {namespace}/{secret_name} is available."
                    if secret.returncode == 0
                    else f"Kubernetes Secret {namespace}/{secret_name} must exist before install."
                ),
            )
        )
    checks.append(
        _check(
            "project_directory_writable",
            "pass" if root.is_dir() and os.access(root, os.W_OK) else "fail",
            (
                f"Project directory {root} is writable."
                if root.is_dir() and os.access(root, os.W_OK)
                else f"Project directory {root} is missing or not writable."
            ),
        )
    )
    status = "ready" if all(item["status"] != "fail" for item in checks) else "blocked"
    return {"command": "preflight", "status": status, "checks": checks, "errors": []}


def _read_env_file(path: Path) -> tuple[list[str], Dict[str, str]]:
    if not path.exists():
        return [], {}
    lines = path.read_text(encoding="utf-8").splitlines()
    values: Dict[str, str] = {}
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        values[key] = value.strip().strip('"').strip("'")
    return lines, values


def _render_env(lines: Iterable[str], values: Dict[str, str]) -> str:
    remaining = dict(values)
    rendered: list[str] = []
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            key = stripped.split("=", 1)[0]
            if key in remaining:
                rendered.append(f"{key}={_quote_env_value(remaining.pop(key), key)}")
                continue
        rendered.append(line)
    if remaining:
        if rendered and rendered[-1]:
            rendered.append("")
        rendered.append("# Managed by scripts/dmarqctl.py")
        for key in sorted(remaining):
            rendered.append(f"{key}={_quote_env_value(remaining[key], key)}")
    return "\n".join(rendered).rstrip() + "\n"


def _quote_env_value(value: str, key: str) -> str:
    if any(character in value for character in ("\x00", "\n", "\r", "'")):
        raise ControlError(
            "environment_value_not_env_safe",
            f"Environment value for {key} contains characters that cannot be preserved safely.",
            EXIT_INVALID_CONFIG,
        )
    return f"'{value}'"


def _resolve_secret(
    config: Dict[str, Any],
    config_key: str,
    env_key: str,
    existing: Dict[str, str],
) -> str:
    current = existing.get(env_key, "")
    if current and current != PLACEHOLDERS[env_key]:
        return current
    source = config.get("secrets", {}).get(config_key, {"generate": True})
    source_env = source.get("env") if isinstance(source, dict) else None
    if source_env:
        value = os.environ.get(source_env, "")
        if not value:
            raise ControlError(
                "secret_environment_missing",
                f"Required secret environment variable {source_env} is not set.",
                EXIT_INVALID_CONFIG,
            )
        return value
    return secrets.token_hex(32)


def _write_environment(config: Dict[str, Any], root: Path) -> tuple[Path, bool]:
    deployment = config["deployment"]
    env_path = (root / str(deployment.get("envFile", ".env"))).resolve()
    if not env_path.is_relative_to(root):
        raise ControlError(
            "environment_path_outside_project",
            "The Compose environment file must stay inside the DMARQ project directory.",
            EXIT_INVALID_CONFIG,
        )
    example_path = root / ".env.example"
    if not env_path.exists() and not example_path.exists():
        raise ControlError(
            "environment_template_missing",
            f"Environment template was not found at {example_path}.",
            EXIT_OPERATION_FAILED,
        )
    source_path = env_path if env_path.exists() else example_path
    lines, existing = _read_env_file(source_path)
    product = config["product"]
    database = config.get("database", {})
    profile = product["profile"]
    auth_mode = product.get("authentication", {}).get("mode", "disabled")
    values = {
        "DMARQ_ENV_FILE": str(env_path.relative_to(root)),
        "DMARQ_BIND_ADDRESS": str(deployment.get("bindAddress", "127.0.0.1")),
        "DMARQ_PORT": str(deployment.get("port", 8080)),
        "DMARQ_IMAGE": str(deployment.get("image", DEFAULT_IMAGE)),
        "PUBLIC_BASE_URL": str(deployment["publicBaseUrl"]).rstrip("/"),
        "PROJECT_NAME": str(product.get("appName", "DMARQ")),
        "LANGUAGE": str(product.get("language", "en")),
        "AUTH_MODE": str(auth_mode),
        "AUTH_DISABLED": "true" if auth_mode == "disabled" else "false",
        "MULTI_WORKSPACE_UI_ENABLED": "true" if profile != "single-user" else "false",
        "PROVIDER_BOOTSTRAP_DEFAULT_PLANS": "true" if profile == "provider" else "false",
        "SECRET_KEY": _resolve_secret(config, "secretKey", "SECRET_KEY", existing),
        "ADMIN_API_KEY": _resolve_secret(config, "adminApiKey", "ADMIN_API_KEY", existing),
    }
    database_mode = database.get("mode", "bundled")
    if database_mode == "external":
        url_env = database["urlEnv"]
        database_url = os.environ.get(url_env, "")
        if not database_url:
            raise ControlError(
                "database_url_environment_missing",
                f"Required database URL environment variable {url_env} is not set.",
                EXIT_INVALID_CONFIG,
            )
        values["DATABASE_URL"] = database_url
    else:
        database_name = str(database.get("name", "dmarq"))
        database_user = str(database.get("user", "dmarq"))
        database_password = _resolve_secret(
            config, "databasePassword", "POSTGRES_PASSWORD", existing
        )
        values.update(
            {
                "POSTGRES_DB": database_name,
                "POSTGRES_USER": database_user,
                "POSTGRES_PASSWORD": database_password,
                "DATABASE_URL": (
                    "postgresql://"
                    f"{quote(database_user, safe='')}:{quote(database_password, safe='')}"
                    f"@db:5432/{quote(database_name, safe='')}"
                ),
            }
        )

    rendered = _render_env(lines, values)
    unchanged = env_path.exists() and env_path.read_text(encoding="utf-8") == rendered
    env_path.parent.mkdir(parents=True, exist_ok=True)
    env_path.write_text(rendered, encoding="utf-8")
    env_path.chmod(0o600)
    return env_path, unchanged


def _request_json(
    base_url: str,
    path: str,
    *,
    method: str = "GET",
    payload: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {"Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    request = Request(
        f"{base_url.rstrip('/')}{path}",
        data=body,
        headers=headers,
        method=method,
    )
    try:
        with urlopen(request, timeout=30) as response:  # noqa: S310 - operator URL.
            raw = response.read()
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:500]
        raise ControlError(
            "http_request_failed",
            f"{method} {path} returned HTTP {exc.code}: {detail}",
            EXIT_OPERATION_FAILED,
        ) from exc
    except (URLError, TimeoutError, OSError) as exc:
        raise ControlError(
            "instance_unreachable",
            f"DMARQ instance could not be reached for {path}: {type(exc).__name__}.",
            EXIT_NOT_READY,
        ) from exc
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ControlError(
            "invalid_json_response",
            f"DMARQ returned an invalid JSON response for {path}.",
            EXIT_OPERATION_FAILED,
        ) from exc
    return parsed if isinstance(parsed, dict) else {"value": parsed}


def _start_compose(root: Path, env_path: Path) -> None:
    env_arg = str(env_path.relative_to(root)) if env_path.is_relative_to(root) else str(env_path)
    compose_command = _compose_command()
    if not compose_command:
        raise ControlError(
            "docker_compose_unavailable",
            "Docker Compose is required to start DMARQ.",
            EXIT_PREFLIGHT_FAILED,
        )
    commands = (
        [*compose_command, "--env-file", env_arg, "pull"],
        [*compose_command, "--env-file", env_arg, "up", "-d", "--wait"],
    )
    for command in commands:
        completed = subprocess.run(command, cwd=root, check=False, capture_output=True, text=True)
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout).strip().splitlines()[-1:]
            raise ControlError(
                "compose_failed",
                f"Docker Compose failed: {detail[0] if detail else 'unknown error'}",
                EXIT_OPERATION_FAILED,
            )


def _install_kubernetes(config: Dict[str, Any], root: Path) -> None:
    deployment = config["deployment"]
    product = config["product"]
    image = str(deployment.get("image", DEFAULT_IMAGE))
    if ":" not in image:
        raise ControlError(
            "image_tag_required",
            "Kubernetes image must include an explicit tag.",
            EXIT_INVALID_CONFIG,
        )
    image_repository, image_tag = image.rsplit(":", 1)
    chart_path = (root / deployment.get("chartPath", "deploy/helm/dmarq")).resolve()
    if not (chart_path / "Chart.yaml").is_file():
        raise ControlError(
            "helm_chart_missing",
            f"DMARQ Helm chart was not found at {chart_path}.",
            EXIT_OPERATION_FAILED,
        )
    values = {
        "image": {"repository": image_repository, "tag": image_tag},
        "existingSecret": deployment["existingSecret"],
        "config": {
            "projectName": product.get("appName", "DMARQ"),
            "environment": "production",
            "publicBaseUrl": deployment["publicBaseUrl"],
            "language": product.get("language", "en"),
            "profile": product["profile"],
            "authMode": product.get("authentication", {}).get("mode", "disabled"),
        },
        "bootstrap": {"enabled": True, "ownerEmail": product["ownerEmail"]},
        "postgresql": {"enabled": config.get("database", {}).get("mode", "bundled") == "bundled"},
    }
    values_file: Optional[Path] = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            prefix="dmarq-values-",
            suffix=".json",
            dir=root,
            delete=False,
        ) as handle:
            json.dump(values, handle)
            values_file = Path(handle.name)
        values_file.chmod(0o600)
        command = [
            "helm",
            "upgrade",
            "--install",
            str(deployment.get("releaseName", "dmarq")),
            str(chart_path),
            "--namespace",
            str(deployment.get("namespace", "dmarq")),
            "--create-namespace",
            "--atomic",
            "--wait",
            "--wait-for-jobs",
            "--timeout",
            "15m",
            "--values",
            str(values_file),
        ]
        completed = _command_result(command, timeout=960)
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout).strip().splitlines()[-1:]
            raise ControlError(
                "helm_install_failed",
                f"Helm install failed: {detail[0] if detail else 'unknown error'}",
                EXIT_OPERATION_FAILED,
            )
    finally:
        if values_file is not None:
            values_file.unlink(missing_ok=True)


def _complete_setup(config: Dict[str, Any]) -> bool:
    base_url = str(config["deployment"]["publicBaseUrl"]).rstrip("/")
    status = _request_json(base_url, "/api/v1/setup/status")
    if status.get("is_setup_complete"):
        return False
    product = config["product"]
    _request_json(
        base_url,
        "/api/v1/setup/admin",
        method="POST",
        payload={"email": product["ownerEmail"]},
    )
    _request_json(
        base_url,
        "/api/v1/setup/system",
        method="POST",
        payload={
            "app_name": product.get("appName", "DMARQ"),
            "base_url": base_url,
            "cloudflare_enabled": False,
        },
    )
    return True


def bootstrap(
    config: Dict[str, Any],
    root: Path,
    *,
    start: bool,
    setup_existing: bool = False,
) -> Dict[str, Any]:
    errors = validate_config(config)
    if errors:
        return {"command": "bootstrap", "status": "invalid", "errors": errors}
    if config["deployment"]["mode"] == "kubernetes":
        if not start or setup_existing:
            raise ControlError(
                "kubernetes_bootstrap_mode_invalid",
                "Kubernetes bootstrap installs and configures the Helm release in one operation.",
                EXIT_INVALID_CONFIG,
            )
        _install_kubernetes(config, root)
        return {
            "command": "bootstrap",
            "status": "ready",
            "deploymentMode": "kubernetes",
            "releaseName": config["deployment"].get("releaseName", "dmarq"),
            "namespace": config["deployment"].get("namespace", "dmarq"),
            "image": config["deployment"].get("image", DEFAULT_IMAGE),
            "publicBaseUrl": config["deployment"]["publicBaseUrl"],
            "started": True,
            "setupCompletedNow": True,
            "errors": [],
        }
    env_path, unchanged = _write_environment(config, root)
    setup_completed = False
    if start:
        if not _compose_available():
            raise ControlError(
                "docker_compose_unavailable",
                "Docker Compose is required to start DMARQ.",
                EXIT_PREFLIGHT_FAILED,
            )
        _start_compose(root, env_path)
        setup_completed = _complete_setup(config)
    elif setup_existing:
        setup_completed = _complete_setup(config)
    return {
        "command": "bootstrap",
        "status": "ready" if start or setup_existing else "configured",
        "deploymentMode": "compose",
        "environmentFile": str(env_path),
        "environmentUnchanged": unchanged,
        "image": config["deployment"].get("image", DEFAULT_IMAGE),
        "publicBaseUrl": config["deployment"]["publicBaseUrl"],
        "started": start,
        "configuredExistingInstance": setup_existing,
        "setupCompletedNow": setup_completed,
        "errors": [],
    }


def status(config: Dict[str, Any]) -> Dict[str, Any]:
    errors = validate_config(config)
    if errors:
        return {"command": "status", "status": "invalid", "errors": errors}
    base_url = str(config["deployment"]["publicBaseUrl"]).rstrip("/")
    health = _request_json(base_url, "/healthz")
    setup = _request_json(base_url, "/api/v1/setup/status")
    release = _request_json(base_url, "/api/v1/health/release")
    ready = health.get("status") in {"ok", "healthy"} and bool(setup.get("is_setup_complete"))
    return {
        "command": "status",
        "status": "ready" if ready else "attention",
        "publicBaseUrl": base_url,
        "health": health.get("status"),
        "setupComplete": bool(setup.get("is_setup_complete")),
        "domains": int(setup.get("total_domains") or 0),
        "mailSources": int(setup.get("total_mail_sources") or 0),
        "enabledMailSources": int(setup.get("enabled_mail_sources") or 0),
        "release": {
            "version": release.get("version"),
            "image": release.get("image"),
            "gitRef": release.get("git_ref"),
        },
        "errors": [],
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dmarqctl")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG))
    parser.add_argument("--root", type=Path, default=ROOT_DIR)
    parser.add_argument("--json", action="store_true", dest="as_json")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("preflight")
    bootstrap_parser = subparsers.add_parser("bootstrap")
    bootstrap_mode = bootstrap_parser.add_mutually_exclusive_group()
    bootstrap_mode.add_argument("--no-start", action="store_true")
    bootstrap_mode.add_argument("--setup-existing", action="store_true")
    subparsers.add_parser("status")
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        config = _load_config(args.config)
        if args.command == "preflight":
            result = preflight(config, args.root.resolve())
            exit_code = EXIT_OK if result["status"] == "ready" else EXIT_PREFLIGHT_FAILED
            if result["status"] == "invalid":
                exit_code = EXIT_INVALID_CONFIG
        elif args.command == "bootstrap":
            result = bootstrap(
                config,
                args.root.resolve(),
                start=not args.no_start and not args.setup_existing,
                setup_existing=args.setup_existing,
            )
            exit_code = EXIT_OK if result["status"] != "invalid" else EXIT_INVALID_CONFIG
        else:
            result = status(config)
            exit_code = EXIT_OK if result["status"] == "ready" else EXIT_NOT_READY
            if result["status"] == "invalid":
                exit_code = EXIT_INVALID_CONFIG
    except ControlError as exc:
        result = {
            "command": args.command,
            "status": "error",
            "error": {"code": exc.code, "message": str(exc)},
        }
        exit_code = exc.exit_code
    _emit(result, as_json=args.as_json)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
