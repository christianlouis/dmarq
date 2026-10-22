"""Regression tests for provider report duplicate authority and retries."""

from unittest.mock import patch

import pytest

from app.models.report import DMARCReport
from app.models.workspace import Workspace
from app.services.gmail_client import GmailClient
from app.services.microsoft_graph_client import MicrosoftGraphClient

REPORT = {
    "domain": "example.com",
    "report_id": "provider-retry-1",
    "org_name": "Example Sender",
    "begin_date": 1_700_000_000,
    "end_date": 1_700_003_600,
    "records": [],
}


def _clients(db, workspace_id):
    with patch("app.services.gmail_client.Credentials"):
        gmail = GmailClient(
            client_id="client-id",
            client_secret="client-secret",
            access_token="access-token",
            refresh_token="refresh-token",
            db=db,
            workspace_id=workspace_id,
        )
    graph = MicrosoftGraphClient(
        tenant_id="organizations",
        client_id="client-id",
        client_secret="client-secret",
        access_token="access-token",
        refresh_token="refresh-token",
        db=db,
        workspace_id=workspace_id,
    )
    return gmail, graph


def _store(client, report):
    return client._store_report_if_new(report)


@pytest.mark.parametrize("provider", ["gmail", "graph"])
def test_db_authority_allows_retry_after_outer_rollback(db_session, provider):
    workspace = Workspace(name=f"{provider} retry", slug=f"{provider}-retry")
    db_session.add(workspace)
    db_session.commit()
    client = _clients(db_session, workspace.id)[0 if provider == "gmail" else 1]

    assert _store(client, REPORT) is True
    db_session.rollback()

    assert _store(client, REPORT) is True
    db_session.commit()
    assert db_session.query(DMARCReport).filter_by(report_id=REPORT["report_id"]).count() == 1


@pytest.mark.parametrize("provider", ["gmail", "graph"])
def test_db_commit_remains_duplicate_on_retry(db_session, provider):
    workspace = Workspace(name=f"{provider} committed", slug=f"{provider}-committed")
    db_session.add(workspace)
    db_session.commit()
    client = _clients(db_session, workspace.id)[0 if provider == "gmail" else 1]

    assert _store(client, REPORT) is True
    db_session.commit()

    assert _store(client, REPORT) is False
    assert db_session.query(DMARCReport).filter_by(report_id=REPORT["report_id"]).count() == 1


@pytest.mark.parametrize("provider", ["gmail", "graph"])
def test_memory_only_mode_still_uses_process_cache(provider):
    client = _clients(None, None)[0 if provider == "gmail" else 1]

    assert _store(client, REPORT) is True
    assert _store(client, REPORT) is False
