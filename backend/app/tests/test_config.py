"""
Tests for application settings / config.py.

Covers BACKEND_CORS_ORIGINS parsing including the empty-string case that
previously caused a JSONDecodeError in pydantic_settings v2 before validators
could run (see: pydantic_settings sources/providers/env.py decode_complex_value).
"""

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
