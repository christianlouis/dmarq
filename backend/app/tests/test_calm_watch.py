"""Calm Watch delivery tests."""

from types import SimpleNamespace

from app.models.alert import MailHealthIncident
from app.models.workspace import Workspace
from app.services.calm_watch import evaluate_and_send_calm_watch


def _assessment():
    return {
        "outcome": "action_required",
        "domain": "example.com",
        "title": "Intended mail is failing",
        "summary": "A previously healthy sender now fails authentication.",
        "intended_mail_impact": "likely_affected",
        "urgency": "timely",
        "confidence": "high",
        "assessment_version": "v1",
        "claim_level": "inferred",
        "delivery_certainty": "authentication_only",
        "freshness": "current",
        "supporting_signals": [],
        "next_action": {
            "label": "Repair sender authentication",
            "href": "/domains/example.com#sending-sources",
        },
    }


def test_calm_watch_sends_once_for_an_unchanged_incident(db_session, monkeypatch):
    workspace = Workspace(slug="watch-cycle", name="Watch cycle")
    db_session.add(workspace)
    db_session.commit()
    sent = []
    webhooks = []

    monkeypatch.setattr(
        "app.services.calm_watch.build_workspace_mail_health_assessment",
        lambda *_args, **_kwargs: _assessment(),
    )
    monkeypatch.setattr(
        "app.services.calm_watch.send_notification",
        lambda _db, **kwargs: sent.append(kwargs)
        or SimpleNamespace(to_dict=lambda: {"success": True, "message": "sent"}),
    )
    monkeypatch.setattr(
        "app.services.calm_watch.enqueue_webhook_event",
        lambda _db, **kwargs: webhooks.append(kwargs),
    )

    first = evaluate_and_send_calm_watch(db_session)
    second = evaluate_and_send_calm_watch(db_session)
    incident = db_session.query(MailHealthIncident).one()

    assert len(first["sent"]) == 1
    assert second["sent"] == []
    assert len(sent) == 1
    assert "Intended mail impact: likely_affected" in sent[0]["body"]
    assert "Repair sender authentication" in sent[0]["body"]
    assert incident.last_notified_at is not None
    assert len(webhooks) == 1
