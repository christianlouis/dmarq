"""Delivery receipts suppress repeated scheduled alerts without losing pending ones."""

import pytest
from sqlalchemy.orm import Session

from app.models.alert import AlertHistory
from app.services import alert_rules
from app.services.alert_history import record_alert_evaluation
from app.services.notifications import NotificationResult


def _alert(domain="quiet.example", *, severity="warning", count=10):
    return {
        "rule": "new_sender_source",
        "domain": domain,
        "source_ip": "203.0.113.10",
        "severity": severity,
        "title": "New sending source",
        "detail": f"203.0.113.10 first appeared for {domain} with {count} messages.",
        "message_count": count,
    }


@pytest.fixture()
def delivery(monkeypatch):
    observed = [_alert()]
    messages = []
    state = {"result": NotificationResult(success=True, message="Sent.")}

    def send(db, *, title, body):  # pylint: disable=unused-argument
        messages.append({"title": title, "body": body})
        return state["result"]

    monkeypatch.setattr(alert_rules, "evaluate_alert_rules", lambda db: list(observed))
    monkeypatch.setattr(alert_rules, "send_notification", send)
    return observed, messages, state


def test_preview_is_not_a_receipt_and_receipt_survives_a_new_session(db_session, delivery):
    observed, messages, _ = delivery
    # Check Alerts and daily summary evaluation must not swallow unsent alerts.
    record_alert_evaluation(db_session, observed)
    first = alert_rules.send_current_alerts(db_session, only_unnotified=True)
    assert first["notification"]["success"] is True
    assert len(messages) == 1

    with Session(db_session.get_bind()) as restarted_session:
        repeated = alert_rules.send_current_alerts(restarted_session, only_unnotified=True)
    assert repeated["notification"]["skipped"] is True
    assert len(messages) == 1
    assert db_session.query(AlertHistory).one().observed_count == 3


def test_new_alert_is_sent_without_repeating_old_alerts(db_session, delivery):
    observed, messages, _ = delivery
    alert_rules.send_current_alerts(db_session, only_unnotified=True)
    observed.append(_alert("new.example"))
    result = alert_rules.send_current_alerts(db_session, only_unnotified=True)

    assert len(result["alerts"]) == 2
    assert messages[-1]["title"] == "DMARQ alert summary: 1 alert(s)"
    assert "new.example" in messages[-1]["body"]
    assert "quiet.example" not in messages[-1]["body"]
    assert all(row.last_notified_at is not None for row in db_session.query(AlertHistory))


@pytest.mark.parametrize(
    "result",
    [
        NotificationResult(success=False, message="Failed.", error="delivery_failed"),
        NotificationResult(success=False, skipped=True, message="Disabled."),
        NotificationResult(success=False, skipped=True, rate_limited=True, message="Cooldown."),
        NotificationResult(success=True, skipped=True, message="Skipped."),
    ],
    ids=["delivery-failure", "disabled", "cooldown", "skipped"],
)
def test_unsent_alerts_remain_pending(db_session, delivery, result):
    _, messages, state = delivery
    state["result"] = result
    alert_rules.send_current_alerts(db_session, only_unnotified=True)
    assert db_session.query(AlertHistory).one().last_notified_at is None
    assert db_session.query(AlertHistory).one().notified_severity is None

    state["result"] = NotificationResult(success=True, message="Sent.")
    alert_rules.send_current_alerts(db_session, only_unnotified=True)
    assert len(messages) == 2
    assert db_session.query(AlertHistory).one().last_notified_at is not None
    assert alert_rules.send_current_alerts(db_session, only_unnotified=True)["notification"][
        "skipped"
    ]
    assert len(messages) == 2


def test_resolved_alert_returning_is_notified_again_even_after_a_preview(db_session, delivery):
    observed, messages, _ = delivery
    alert_rules.send_current_alerts(db_session, only_unnotified=True)
    record_alert_evaluation(db_session, [])
    assert db_session.query(AlertHistory).one().is_active is False
    record_alert_evaluation(db_session, observed)
    assert db_session.query(AlertHistory).one().last_notified_at is None

    alert_rules.send_current_alerts(db_session, only_unnotified=True)
    assert len(messages) == 2
    assert db_session.query(AlertHistory).count() == 1


def test_severity_escalation_sends_once_but_count_changes_do_not(db_session, delivery):
    observed, messages, _ = delivery
    alert_rules.send_current_alerts(db_session, only_unnotified=True)
    observed[:] = [_alert(count=25)]
    assert alert_rules.send_current_alerts(db_session, only_unnotified=True)["notification"][
        "skipped"
    ]
    observed[:] = [_alert(severity="error", count=50)]
    alert_rules.send_current_alerts(db_session, only_unnotified=True)
    assert len(messages) == 2
    assert db_session.query(AlertHistory).one().notified_severity == "error"

    observed[:] = [_alert(severity="warning")]
    # Even a manual resend of a lower severity must not forget the escalation.
    alert_rules.send_current_alerts(db_session)
    observed[:] = [_alert(severity="error", count=75)]
    assert alert_rules.send_current_alerts(db_session, only_unnotified=True)["notification"][
        "skipped"
    ]
    assert len(messages) == 3


def test_manual_send_can_repeat_and_suppresses_the_next_automatic_send(db_session, delivery):
    _, messages, _ = delivery
    alert_rules.send_current_alerts(db_session)
    alert_rules.send_current_alerts(db_session)
    assert len(messages) == 2
    assert alert_rules.send_current_alerts(db_session, only_unnotified=True)["notification"][
        "skipped"
    ]
    assert len(messages) == 2


def test_empty_alert_set_is_a_quiet_success(db_session, delivery):
    observed, messages, _ = delivery
    observed.clear()
    result = alert_rules.send_current_alerts(db_session, only_unnotified=True)
    assert result["notification"]["success"] is True
    assert result["notification"]["skipped"] is True
    assert messages == []
