"""Tests for mailbox recovery guidance."""

from app.services.mailbox_recovery import connection_test_response, import_result_diagnostic


def test_connection_response_classifies_auth_failure_without_raw_secret():
    response = connection_test_response(
        False,
        "Login failed invalid password",
        {"diagnostic_detail": "password=super-secret rejected"},
    )

    assert response["diagnostic_category"] == "authentication"
    assert response["diagnostic_summary"]
    assert response["recovery_steps"]
    assert "super-secret" not in str(response)


def test_import_result_classifies_parsing_failure():
    diagnostic = import_result_diagnostic(
        {
            "success": True,
            "processed": 1,
            "reports_found": 0,
            "errors": ["Could not parse ZIP attachment report.zip"],
        }
    )

    assert diagnostic["category"] == "parsing"
    assert "parse" in diagnostic["summary"].lower()


def test_import_result_classifies_duplicate_only_as_no_outage():
    diagnostic = import_result_diagnostic(
        {
            "success": True,
            "processed": 2,
            "reports_found": 0,
            "duplicate_reports": 2,
            "errors": [],
        }
    )

    assert diagnostic["category"] == "duplicate_only"
    assert diagnostic["recovery_steps"]


def test_import_result_success_has_no_recovery_steps():
    diagnostic = import_result_diagnostic(
        {
            "success": True,
            "processed": 2,
            "reports_found": 2,
            "duplicate_reports": 0,
            "errors": [],
        }
    )

    assert diagnostic["category"] == "ok"
    assert diagnostic["recovery_steps"] == []
