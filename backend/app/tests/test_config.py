"""
Tests for application settings / config.py.

Covers BACKEND_CORS_ORIGINS parsing including the empty-string case that
previously caused a JSONDecodeError in pydantic_settings v2 before validators
could run (see: pydantic_settings sources/providers/env.py decode_complex_value).
"""

import pytest

from app.core.config import Settings


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
