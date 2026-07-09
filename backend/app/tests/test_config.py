"""
Tests for application settings / config.py.

Covers BACKEND_CORS_ORIGINS parsing including the empty-string case that
previously caused a JSONDecodeError in pydantic_settings v2 before validators
could run (see: pydantic_settings sources/providers/env.py decode_complex_value).
"""

import pytest

from app.core.config import Settings
from app.core.database import _ensure_sqlite_dir, _make_sync_db_url


class TestBackendCorsOriginsValidator:
    """Tests for the assemble_cors_origins validator."""

    def test_comma_separated_string(self):
        """Comma-separated origins are split into a list."""
        settings = Settings(BACKEND_CORS_ORIGINS="http://localhost:3000,http://localhost:5173")
        assert settings.BACKEND_CORS_ORIGINS == [
            "http://localhost:3000",
            "http://localhost:5173",
        ]

    def test_single_origin_string(self):
        """A single origin as a string is wrapped in a list."""
        settings = Settings(BACKEND_CORS_ORIGINS="https://example.com")
        assert settings.BACKEND_CORS_ORIGINS == ["https://example.com"]

    def test_empty_string_returns_empty_list(self):
        """An empty string must not raise JSONDecodeError; returns an empty list."""
        settings = Settings(BACKEND_CORS_ORIGINS="")
        assert settings.BACKEND_CORS_ORIGINS == []

    def test_whitespace_only_string_returns_empty_list(self):
        """A whitespace-only string is treated the same as empty."""
        settings = Settings(BACKEND_CORS_ORIGINS="   ")
        assert settings.BACKEND_CORS_ORIGINS == []

    def test_list_passthrough(self):
        """A list value is passed through unchanged."""
        origins = ["https://a.example.com", "https://b.example.com"]
        settings = Settings(BACKEND_CORS_ORIGINS=origins)
        assert settings.BACKEND_CORS_ORIGINS == origins

    def test_default_when_not_provided(self):
        """Defaults are returned when BACKEND_CORS_ORIGINS is not set."""
        settings = Settings()
        assert "http://localhost:3000" in settings.BACKEND_CORS_ORIGINS
        assert "http://localhost:5173" in settings.BACKEND_CORS_ORIGINS

    def test_comma_separated_with_spaces(self):
        """Extra whitespace around origins is stripped."""
        settings = Settings(BACKEND_CORS_ORIGINS=" http://a.example.com , http://b.example.com ")
        assert settings.BACKEND_CORS_ORIGINS == [
            "http://a.example.com",
            "http://b.example.com",
        ]

    def test_json_array_string(self):
        """A JSON array string is parsed into a list."""
        settings = Settings(
            BACKEND_CORS_ORIGINS='["https://a.example.com", "https://b.example.com"]'
        )
        assert settings.BACKEND_CORS_ORIGINS == [
            "https://a.example.com",
            "https://b.example.com",
        ]


class TestWorkspaceUiMode:
    """Tests for self-hosted versus multi-workspace UI settings."""

    def test_multi_workspace_ui_defaults_to_disabled(self):
        settings = Settings()

        assert settings.MULTI_WORKSPACE_UI_ENABLED is False

    def test_multi_workspace_ui_can_be_enabled_explicitly(self):
        settings = Settings(MULTI_WORKSPACE_UI_ENABLED=True)

        assert settings.MULTI_WORKSPACE_UI_ENABLED is True

    def test_provider_operator_emails_are_normalized(self):
        settings = Settings(
            PROVIDER_OPERATOR_EMAILS=" Admin@Example.com, operator@example.com ,admin@example.com"
        )

        assert settings.provider_operator_emails == {
            "admin@example.com",
            "operator@example.com",
        }


class TestMakeSyncDbUrl:
    """Tests for the _make_sync_db_url() URL normalization helper."""

    def test_asyncpg_replaced_with_psycopg2(self):
        """asyncpg scheme is converted to psycopg2."""
        url = "postgresql+asyncpg://user:pass@db:5432/mydb"
        assert _make_sync_db_url(url) == "postgresql+psycopg2://user:pass@db:5432/mydb"

    def test_plain_postgresql_unchanged(self):
        """Plain postgresql:// URLs are not modified."""
        url = "postgresql://user:pass@db:5432/mydb"
        assert _make_sync_db_url(url) == url

    def test_psycopg2_url_unchanged(self):
        """URLs already using psycopg2 are not modified."""
        url = "postgresql+psycopg2://user:pass@db:5432/mydb"
        assert _make_sync_db_url(url) == url

    def test_sqlite_url_unchanged(self):
        """SQLite URLs are not modified."""
        url = "sqlite:///./dmarq.db"
        assert _make_sync_db_url(url) == url

    def test_database_url_setting_asyncpg(self):
        """Settings with an asyncpg DATABASE_URL still initialise correctly."""
        settings = Settings(DATABASE_URL="postgresql+asyncpg://user:pass@db:5432/mydb")
        assert settings.DATABASE_URL == "postgresql+asyncpg://user:pass@db:5432/mydb"
        # Normalised URL used by the engine must not contain asyncpg
        assert "asyncpg" not in _make_sync_db_url(settings.DATABASE_URL)


class TestEnsureSqliteDir:
    """Tests for the _ensure_sqlite_dir() helper."""

    def test_relative_sqlite_path_creates_directory(self, tmp_path, monkeypatch):
        """A relative SQLite URL creates its parent directory."""
        monkeypatch.chdir(tmp_path)
        _ensure_sqlite_dir("sqlite:///./subdir/dmarq.db")
        assert (tmp_path / "subdir").is_dir()

    def test_absolute_sqlite_path_creates_directory(self, tmp_path):
        """An absolute SQLite URL creates its parent directory."""
        db_path = tmp_path / "nested" / "dmarq.db"
        _ensure_sqlite_dir(f"sqlite:///{db_path}")
        assert db_path.parent.is_dir()

    def test_in_memory_sqlite_no_directory_created(self, tmp_path, monkeypatch):
        """An in-memory SQLite URL does not create any directory."""
        monkeypatch.chdir(tmp_path)
        _ensure_sqlite_dir("sqlite://")
        _ensure_sqlite_dir("sqlite:///:memory:")
        # tmp_path itself exists but no new subdirectories should appear
        assert list(tmp_path.iterdir()) == []

    def test_postgres_url_no_directory_created(self, tmp_path, monkeypatch):
        """Non-SQLite URLs are ignored entirely."""
        monkeypatch.chdir(tmp_path)
        _ensure_sqlite_dir("postgresql://user:pass@db:5432/mydb")
        assert list(tmp_path.iterdir()) == []

    def test_existing_directory_is_noop(self, tmp_path):
        """Calling _ensure_sqlite_dir when the directory already exists is a no-op."""
        existing = tmp_path / "data"
        existing.mkdir()
        _ensure_sqlite_dir(f"sqlite:///{existing}/dmarq.db")  # should not raise
        assert existing.is_dir()

    def test_default_database_url_uses_data_subdir(self):
        """Default DATABASE_URL places the SQLite file inside a data/ subdirectory."""
        settings = Settings()
        assert settings.DATABASE_URL.endswith("data/dmarq.db")


class TestAdminApiKeySetting:
    """Tests for the ADMIN_API_KEY settings field."""

    def test_admin_api_key_defaults_to_none(self):
        """ADMIN_API_KEY is None when not set."""
        settings = Settings()
        assert settings.ADMIN_API_KEY is None

    def test_admin_api_key_reads_from_env(self, monkeypatch):
        """ADMIN_API_KEY is read from the environment variable."""
        monkeypatch.setenv("ADMIN_API_KEY", "mytestapikey1234")
        settings = Settings()
        assert settings.ADMIN_API_KEY == "mytestapikey1234"

    def test_admin_api_key_warns_when_short(self, monkeypatch, caplog):
        """A warning is logged when ADMIN_API_KEY is shorter than 32 characters."""
        import logging

        monkeypatch.setenv("ADMIN_API_KEY", "short")
        with caplog.at_level(logging.WARNING, logger="app.core.config"):
            settings = Settings()
        assert settings.ADMIN_API_KEY == "short"
        assert any("too short" in record.message for record in caplog.records)

    def test_admin_api_key_accepts_long_key(self, monkeypatch):
        """A 64-char hex key (openssl rand -hex 32 output) is accepted without warnings."""
        long_key = "a" * 64
        monkeypatch.setenv("ADMIN_API_KEY", long_key)
        settings = Settings()
        assert settings.ADMIN_API_KEY == long_key


class TestLogtoSettings:
    def test_ssl_verification_is_enabled_by_default(self, monkeypatch):
        monkeypatch.delenv("LOGTO_SKIP_SSL_VERIFY", raising=False)
        settings = Settings()

        assert settings.LOGTO_SKIP_SSL_VERIFY is False

    def test_ssl_verification_can_be_skipped_explicitly(self, monkeypatch):
        monkeypatch.setenv("LOGTO_SKIP_SSL_VERIFY", "true")
        settings = Settings()

        assert settings.LOGTO_SKIP_SSL_VERIFY is True


class TestImapSettings:
    def test_delete_imported_emails_defaults_false(self, monkeypatch):
        monkeypatch.delenv("DELETE_IMPORTED_EMAILS", raising=False)
        settings = Settings()

        assert settings.DELETE_IMPORTED_EMAILS is False

    def test_delete_imported_emails_reads_env(self, monkeypatch):
        monkeypatch.setenv("DELETE_IMPORTED_EMAILS", "true")
        settings = Settings()

        assert settings.DELETE_IMPORTED_EMAILS is True


class TestProductionStartupSettings:
    """Tests for production-critical settings and startup validation."""

    def test_environment_defaults_to_development(self):
        settings = Settings()

        assert settings.ENVIRONMENT == "development"
        assert settings.is_production is False

    def test_production_requires_stable_secret_key(self):
        with pytest.raises(Exception) as excinfo:
            Settings(ENVIRONMENT="production")

        assert "SECRET_KEY" in str(excinfo.value)

    def test_production_rejects_short_secret_key(self):
        with pytest.raises(Exception) as excinfo:
            Settings(ENVIRONMENT="production", SECRET_KEY="short")

        assert "SECRET_KEY" in str(excinfo.value)

    def test_production_startup_passes_with_admin_key(self):
        from app.core.startup_checks import validate_startup_configuration

        settings = Settings(
            ENVIRONMENT="production",
            SECRET_KEY="s" * 32,
            ADMIN_API_KEY="a" * 64,
            DATABASE_URL="postgresql://dmarq:password@db/dmarq",
        )

        result = validate_startup_configuration(settings)

        assert result.ok is True
        assert result.errors == ()

    def test_production_startup_requires_auth_path(self):
        from app.core.startup_checks import validate_startup_configuration

        settings = Settings(
            ENVIRONMENT="production",
            SECRET_KEY="s" * 32,
            DATABASE_URL="postgresql://dmarq:password@db/dmarq",
        )

        result = validate_startup_configuration(settings)

        assert result.ok is False
        assert any("authentication path or ADMIN_API_KEY" in error for error in result.errors)

    def test_production_startup_accepts_authentik_oidc(self):
        from app.core.startup_checks import validate_startup_configuration

        settings = Settings(
            ENVIRONMENT="production",
            SECRET_KEY="s" * 32,
            AUTH_MODE="authentik",
            AUTHENTIK_ISSUER_URL="https://idp.example.test/application/o/dmarq",
            AUTHENTIK_CLIENT_ID="client-id",
            AUTHENTIK_CLIENT_SECRET="client-secret",
            DATABASE_URL="postgresql://dmarq:password@db/dmarq",
        )

        result = validate_startup_configuration(settings)

        assert result.ok is True

    def test_production_startup_rejects_auth_disabled_without_override(self):
        from app.core.startup_checks import validate_startup_configuration

        settings = Settings(
            ENVIRONMENT="production",
            SECRET_KEY="s" * 32,
            AUTH_DISABLED=True,
            DATABASE_URL="postgresql://dmarq:password@db/dmarq",
        )

        result = validate_startup_configuration(settings)

        assert any("AUTH_DISABLED=true" in error for error in result.errors)

    def test_production_startup_rejects_auth_mode_disabled_without_override(self):
        from app.core.startup_checks import validate_startup_configuration

        settings = Settings(
            ENVIRONMENT="production",
            SECRET_KEY="s" * 32,
            AUTH_MODE="disabled",
            DATABASE_URL="postgresql://dmarq:password@db/dmarq",
        )

        result = validate_startup_configuration(settings)

        assert result.ok is False
        assert any("AUTH_MODE=disabled" in error for error in result.errors)

    def test_production_startup_allows_auth_disabled_with_explicit_override(self):
        from app.core.startup_checks import validate_startup_configuration

        settings = Settings(
            ENVIRONMENT="production",
            SECRET_KEY="s" * 32,
            AUTH_DISABLED=True,
            ALLOW_AUTH_DISABLED_IN_PRODUCTION=True,
            DATABASE_URL="postgresql://dmarq:password@db/dmarq",
        )

        result = validate_startup_configuration(settings)

        assert result.ok is True

    def test_production_startup_rejects_logto_ssl_skip_without_override(self):
        from app.core.startup_checks import validate_startup_configuration

        settings = Settings(
            ENVIRONMENT="production",
            SECRET_KEY="s" * 32,
            ADMIN_API_KEY="a" * 64,
            LOGTO_SKIP_SSL_VERIFY=True,
            DATABASE_URL="postgresql://dmarq:password@db/dmarq",
        )

        result = validate_startup_configuration(settings)

        assert any("LOGTO_SKIP_SSL_VERIFY=true" in error for error in result.errors)

    def test_production_startup_warns_for_sqlite(self):
        from app.core.startup_checks import validate_startup_configuration

        settings = Settings(
            ENVIRONMENT="production",
            SECRET_KEY="s" * 32,
            ADMIN_API_KEY="a" * 64,
            DATABASE_URL="sqlite:///./data/dmarq.db",
        )

        result = validate_startup_configuration(settings)

        assert result.ok is True
        assert any("SQLite" in warning for warning in result.warnings)

    def test_run_startup_checks_raises_for_unsafe_production(self):
        from app.core.startup_checks import StartupConfigurationError, run_startup_checks

        settings = Settings(
            ENVIRONMENT="production",
            SECRET_KEY="s" * 32,
            DATABASE_URL="postgresql://dmarq:password@db/dmarq",
        )

        with pytest.raises(StartupConfigurationError):
            run_startup_checks(settings)
