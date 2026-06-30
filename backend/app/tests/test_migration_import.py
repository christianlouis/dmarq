"""Tests for read-only historical DMARC export import previews."""

import pytest

from app.services import migration_import
from app.services.migration_import import preview_migration_import


def test_preview_migration_import_auto_json_list_limits_and_warns():
    """Auto-detected JSON previews cap sample size and surface mapping gaps."""
    content = """[
          {"domain": "example.com", "source": "192.0.2.1", "total": "1,200"},
          {"domain": "example.com", "source": "192.0.2.2", "total": 5, "unused_after_preview": true}
        ]"""
    preview = preview_migration_import(
        domain="example.com",
        content=content,
        max_rows=1,
    )
    repeated_preview = preview_migration_import(
        domain="example.com",
        content=content,
        max_rows=1,
    )

    assert preview["format"] == "json"
    assert preview["row_count"] == 2
    assert preview["normalized_count"] == 1
    assert preview["ignored_count"] == 1
    assert preview["rejected_count"] == 0
    assert preview["truncated_count"] == 1
    assert preview["planned_report_count"] == 0
    assert preview["importable_row_count"] == 0
    assert preview["needs_report_id_count"] == 1
    assert preview["sample_rows"][0]["import_status"] == "needs_report_id"
    assert preview["sample_rows"][0]["row_key"].startswith("mir_")
    assert preview["batch_fingerprint"].startswith("mib_")
    assert preview["batch_fingerprint"] == repeated_preview["batch_fingerprint"]
    assert preview["sample_rows"][0]["row_key"] == repeated_preview["sample_rows"][0]["row_key"]
    assert preview["baseline"]["total_emails"] == 1200
    assert preview["sample_rows"][0]["source_ip"] == "192.0.2.1"
    assert "total" in preview["detected_columns"]
    assert "unused_after_preview" not in preview["detected_columns"]
    assert "Preview limited to the first 1 rows." in preview["warnings"]
    assert "Missing recommended columns: dkim, spf, policy" in preview["warnings"]


def test_preview_migration_import_ignores_unmappable_rows():
    """Rows with neither source nor volume are ignored and flagged."""
    preview = preview_migration_import(
        domain="example.com",
        content="Domain,Reporter\nexample.com,LegacyVendor\n",
        source_format="csv",
    )

    assert preview["normalized_count"] == 0
    assert preview["ignored_count"] == 1
    assert preview["rejected_count"] == 1
    assert preview["truncated_count"] == 0
    assert preview["sample_rows"] == []
    assert "Ignored a row without a sending source or message count." in preview["warnings"]


def test_preview_migration_import_splits_rejected_and_truncated_counts():
    """Ignored counts distinguish rejected preview rows from truncated rows."""
    preview = preview_migration_import(
        domain="example.com",
        content="\n".join(
            [
                "Domain,Source IP,Messages",
                "example.com,,0",
                "example.com,192.0.2.10,3",
                "example.com,192.0.2.11,7",
            ]
        ),
        source_format="csv",
        max_rows=2,
    )

    assert preview["row_count"] == 3
    assert preview["normalized_count"] == 1
    assert preview["rejected_count"] == 1
    assert preview["truncated_count"] == 1
    assert preview["ignored_count"] == 2
    assert preview["duplicate_row_count"] == 0
    assert preview["baseline"]["total_emails"] == 3


def test_preview_migration_import_marks_existing_and_duplicate_reports():
    """Import planning marks existing reports without removing them from parity baselines."""
    content = "\n".join(
        [
            "Domain,Report ID,Date,Source IP,Messages,DKIM,SPF,Policy",
            "example.com,legacy-1,2026-06-01,192.0.2.10,3,pass,fail,reject",
            "example.com,legacy-1,2026-06-01,192.0.2.10,3,pass,fail,reject",
            "example.com,legacy-2,2026-06-01,192.0.2.11,7,fail,pass,reject",
        ]
    )
    preview = preview_migration_import(
        domain="example.com",
        content=content,
        source_format="csv",
        existing_report_ids={"legacy-1"},
    )
    repeated_preview = preview_migration_import(
        domain="example.com",
        content=content,
        source_format="csv",
        existing_report_ids={"legacy-1"},
    )

    assert preview["baseline"]["total_emails"] == 13
    assert preview["existing_report_count"] == 1
    assert preview["planned_report_count"] == 1
    assert preview["importable_row_count"] == 1
    assert preview["duplicate_row_count"] == 1
    assert preview["sample_rows"][0]["import_status"] == "existing_report"
    assert preview["sample_rows"][1]["import_status"] == "existing_report"
    assert preview["sample_rows"][2]["import_status"] == "planned"
    assert preview["sample_rows"][2]["report_import_key"].startswith("mip_")
    assert preview["batch_fingerprint"] == repeated_preview["batch_fingerprint"]
    assert preview["sample_rows"][2]["row_key"] == repeated_preview["sample_rows"][2]["row_key"]
    assert (
        preview["sample_rows"][2]["report_import_key"]
        == repeated_preview["sample_rows"][2]["report_import_key"]
    )
    assert "Export contains reports that already exist in DMARQ." in preview["warnings"]


def test_preview_migration_import_json_object_without_row_collection():
    """A single JSON object can be previewed as one row."""
    preview = preview_migration_import(
        domain="example.com",
        content="""{
          "header_from": "example.com",
          "reportid": "legacy-single",
          "sender ip": "198.51.100.20",
          "message count": true,
          "dkim aligned": "OK",
          "spf aligned": "unaligned",
          "dmarc policy": "monitor"
        }""",
    )

    assert preview["format"] == "json"
    assert preview["baseline"]["report_count"] == 1
    assert preview["baseline"]["total_emails"] == 1
    assert preview["baseline"]["policy"] == "monitor"
    assert preview["sample_rows"][0]["dkim"] == "pass"
    assert preview["sample_rows"][0]["spf"] == "fail"


@pytest.mark.parametrize(
    ("content", "source_format", "message"),
    [
        ("{}", "xml", "format must be auto, csv, or json"),
        ("   ", "auto", "import content is empty"),
        ("42", "json", "JSON content must be an object or list"),
        ('["not-a-row"]', "json", "JSON rows must be objects"),
    ],
)
def test_preview_migration_import_rejects_invalid_inputs(content, source_format, message):
    """Invalid exports fail before any import-side effects can exist."""
    with pytest.raises(ValueError, match=message):
        preview_migration_import(
            domain="example.com",
            content=content,
            source_format=source_format,
        )


def test_preview_migration_import_rejects_oversized_content():
    """Oversized preview payloads fail without creating a huge parametrized test id."""
    content = "x" * (migration_import.MAX_PREVIEW_CONTENT_BYTES + 1)

    with pytest.raises(ValueError, match="import content is too large for preview"):
        preview_migration_import(
            domain="example.com",
            content=content,
            source_format="csv",
        )


def test_migration_import_cleaners_cover_edge_values():
    """Normalizers keep odd vendor values stable and conservative."""
    assert migration_import._clean_date(None) is None  # pylint: disable=protected-access
    assert (
        migration_import._clean_date("999999999999999999999999999999")
        == "999999999999999999999999999999"
    )
    assert migration_import._clean_date("not-a-date") == "not-a-date"
    assert migration_import._clean_int(None) == 0  # pylint: disable=protected-access
    assert migration_import._clean_int(-10.5) == 0  # pylint: disable=protected-access
    assert migration_import._clean_int("unknown") == 0  # pylint: disable=protected-access
    assert migration_import._clean_result(None) is None  # pylint: disable=protected-access
    assert (
        migration_import._clean_result("temperror") == "temperror"
    )  # pylint: disable=protected-access
    assert migration_import._clean_policy(None) is None  # pylint: disable=protected-access
    assert migration_import._clean_policy("custom") == "custom"  # pylint: disable=protected-access
