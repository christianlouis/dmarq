from app.services.mail_connector import (
    ConnectorImportContext,
    append_import_detail,
    clamp_search_window,
    connector_failure_stats,
    dump_ingested_ids,
    initial_import_stats,
    load_ingested_ids,
    sanitize_connector_error,
)


def test_initial_import_stats_includes_safe_context():
    context = ConnectorImportContext(
        source_type="M365_GRAPH",
        mailbox="shared@example.com",
        folder="DMARC Reports",
        search_window_days=30,
    )

    stats = initial_import_stats(context)

    assert stats["success"] is True
    assert stats["source_type"] == "M365_GRAPH"
    assert stats["target_mailbox"] == "shared@example.com"
    assert stats["target_folder"] == "DMARC Reports"
    assert stats["search_window_days"] == 30
    assert stats["details"] == []


def test_append_import_detail_redacts_secret_like_values():
    stats = initial_import_stats()

    append_import_detail(
        stats,
        status="error",
        reason="provider_error",
        error="access_token=abc123456789 client_secret=super-secret-value",
    )

    assert stats["details"] == [
        {
            "status": "error",
            "reason": "provider_error",
            "error": "access_token=**redacted** client_secret=**redacted**",
        }
    ]


def test_connector_failure_stats_uses_redacted_error():
    stats = initial_import_stats()
    fake_token = "".join(["not", "-a-real", "-token"])

    result = connector_failure_stats(
        stats,
        "Provider failed.",
        error=f"Authorization: Bearer {fake_token}",
    )

    assert result["success"] is False
    assert result["error"] == "Authorization: Bearer **redacted**"
    assert result["errors"] == ["Authorization: Bearer **redacted**"]


def test_ingested_id_helpers_normalize_values():
    assert load_ingested_ids(None) == []
    assert load_ingested_ids("{bad") == []
    assert load_ingested_ids('{"not": "a-list"}') == []
    assert load_ingested_ids('["a", 2]') == ["a", "2"]
    assert dump_ingested_ids(["a", 2]) == '["a", "2"]'


def test_clamp_search_window_bounds_values():
    assert clamp_search_window(None) == 7
    assert clamp_search_window("bad") == 7
    assert clamp_search_window(0) == 7
    assert clamp_search_window(-5) == 1
    assert clamp_search_window(400) == 365


def test_sanitize_connector_error_truncates_long_values():
    value = "x" * 600

    sanitized = sanitize_connector_error(value)

    assert len(sanitized) == 500
    assert sanitized.endswith("...")
