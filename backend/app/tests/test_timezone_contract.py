"""UTC wire contract and application-zone display regressions."""

import json
import os
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.core.app_timezone import ensure_utc


def test_mail_source_history_and_backfill_wire_instants_match(
    authed_client, db_session, monkeypatch
):
    from app.core.config import get_settings
    from app.models.mail_source import MailSource
    from app.models.mail_source_backfill import MailSourceBackfillJob
    from app.models.mail_source_import import MailSourceImport
    from app.services.workspaces import get_or_create_default_workspace

    monkeypatch.setenv("APP_TIMEZONE", "Europe/Berlin")
    get_settings.cache_clear()
    workspace = get_or_create_default_workspace(db_session)
    stored = datetime(2026, 10, 22, 10, 41)
    source = MailSource(
        workspace_id=workspace.id,
        name="Timezone contract",
        method="IMAP",
        server="imap.example.test",
        username="test@example.test",
        last_checked=stored,
        created_at=stored,
        updated_at=stored,
    )
    db_session.add(source)
    db_session.flush()
    history = MailSourceImport(
        mail_source_id=source.id,
        trigger="scheduled",
        status="success",
        started_at=stored,
        finished_at=stored + timedelta(seconds=30),
        created_at=stored,
    )
    backfill = MailSourceBackfillJob(
        workspace_id=workspace.id,
        mail_source_id=source.id,
        status="completed",
        requested_start=stored - timedelta(days=1),
        requested_end=stored,
        started_at=stored,
        finished_at=stored + timedelta(seconds=30),
        next_retry_at=None,
        created_at=stored,
        updated_at=stored,
    )
    db_session.add_all([history, backfill])
    db_session.commit()
    responses = [
        authed_client.get(f"/api/v1/mail-sources/{source.id}"),
        authed_client.get(f"/api/v1/mail-sources/{source.id}/imports"),
        authed_client.get(f"/api/v1/mail-sources/{source.id}/backfills"),
    ]
    assert all(response.status_code == 200 for response in responses)
    source_payload = responses[0].json()
    history_payload = responses[1].json()[0]
    backfill_payload = responses[2].json()[0]
    assert source_payload["application_timezone"] == "Europe/Berlin"
    assert source_payload["last_checked"] == "2026-10-22T10:41:00Z"
    for payload in (source_payload, history_payload, backfill_payload):
        for name, value in payload.items():
            if name.endswith("_at") or name in ("last_checked", "requested_start", "requested_end"):
                if value is not None:
                    assert datetime.fromisoformat(value).tzinfo is not None, (name, value)
    assert datetime.fromisoformat(source_payload["last_checked"]) == datetime.fromisoformat(
        history_payload["started_at"]
    )
    assert history_payload["started_at"] == backfill_payload["started_at"]
    assert backfill_payload["elapsed_seconds"] == 30
    assert backfill_payload["requested_window_days"] == 1
    assert backfill_payload["next_retry_at"] is None
    assert history.started_at == stored and history.started_at.tzinfo is None


def test_related_serializers_and_export_keep_dates_and_identity():
    from app.api.api_v1.endpoints.health import _iso
    from app.services.organizations import _metric
    from app.services.workspace_audit import audit_log_to_dict

    instant = datetime(2026, 10, 22, 23, 30)
    assert _iso(instant) == "2026-10-22T23:30:00+00:00"
    row = SimpleNamespace(
        id=1,
        workspace_id=1,
        actor_type="system",
        actor_id=None,
        action="test",
        entity_type="source",
        entity_id=1,
        entity_name="test",
        details="{}",
        ip_address=None,
        created_at=instant,
    )
    assert audit_log_to_dict(row)["created_at"] == ensure_utc(instant).isoformat()
    result = _metric("reports", 3, "reports", instant, instant + timedelta(days=1), 1)
    assert result["period_start"] == ensure_utc(instant).isoformat()
    assert result["period_end"] == ensure_utc(instant + timedelta(days=1)).isoformat()
    assert result["idempotency_key"] == "computed:1:org:reports:2026-10-22:2026-10-23"
    assert result["quantity"] == 3


@pytest.mark.parametrize("browser_timezone", ["UTC", "America/Los_Angeles", "Asia/Tokyo"])
def test_shared_ui_formatter_is_independent_of_browser_timezone(browser_timezone):
    script_dir = Path(__file__).parents[1] / "static" / "js"
    runtime = r"""
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const root = { dataset: { appLocale: 'en-GB', appTimezone: 'Europe/Berlin' }, lang: 'en', classList: {add: () => {}, remove: () => {}}, setAttribute: () => {} };
const context = { window: {}, document: { documentElement: root, addEventListener: () => {} }, localStorage: {getItem: () => null}, Date, Intl };
vm.createContext(context);
for (const name of ['localization.js', 'base-layout.js', 'operations-page.js', 'delivery-events-page.js', 'mail-sources-page.js', 'domain-details-page.js', 'report-detail-page.js', 'reports-page.js']) {
    vm.runInContext(fs.readFileSync(`${process.argv[1]}/${name}`, 'utf8'), context);
}
const format = context.window.dmarqFormatDateTime;
const date = context.window.dmarqFormatDate;
assert.equal(format('2026-10-22T10:41:00'), '22/10/2026, 12:41:00');
assert.equal(format('2026-10-22T10:41:00Z'), format('2026-10-22T12:41:00+02:00'));
assert.equal(format('2026-10-22 10:41:00.123'), format('2026-10-22T10:41:00.123Z'));
assert.equal(format('2026-01-22T10:41:00Z'), '22/01/2026, 11:41:00');
assert.equal(format('2026-03-29T00:59:59Z'), '29/03/2026, 01:59:59');
assert.equal(format('2026-03-29T01:00:00Z'), '29/03/2026, 03:00:00');
assert.equal(format('2026-10-25T00:59:59Z'), '25/10/2026, 02:59:59');
assert.equal(format('2026-10-25T01:00:00Z'), '25/10/2026, 02:00:00');
assert.equal(format('2026-10-22T23:30:00Z'), '23/10/2026, 01:30:00');
assert.equal(format(null), '—');
assert.equal(format('', 'unavailable'), 'unavailable');
assert.equal(format('invalid'), 'invalid');
assert.equal(format(0), '01/01/1970, 01:00:00');
assert.equal(date('2026-10-22'), '22/10/2026');
assert.equal(context.mailSourcesApp().formatDate('2026-10-22T10:41:00'), '22/10/2026, 12:41:00');
assert.equal(context.mailSourcesApp().formatDate('2026-10-22T12:41:00+02:00'), '22/10/2026, 12:41:00');
assert.equal(context.operationsHealth().formatDate('2026-10-22T10:41:00Z'), '22/10/2026, 12:41:00');
assert.equal(context.deliveryEventsApp().formatDate('2026-10-22T10:41:00Z'), '22/10/2026, 12:41:00');
root.dataset.appTimezone = 'America/Los_Angeles';
assert.equal(format('2026-10-22T01:30:00Z'), '21/10/2026, 18:30:00');
assert.equal(date('2026-10-22'), '22/10/2026');
assert.equal(format('2026-10-22'), '22/10/2026');
root.dataset.appTimezone = 'Pacific/Kiritimati';
assert.equal(date('2026-10-22'), '22/10/2026');
assert.equal(format('2026-10-22'), '22/10/2026');
assert.equal(format('2026-10-22T10:41:00Z'), '23/10/2026, 00:41:00');
root.dataset.appTimezone = 'invalid/timezone';
assert.equal(format('2026-10-22T10:41:00Z'), new Intl.DateTimeFormat('en', {
    dateStyle: 'short', timeStyle: 'medium', timeZone: 'UTC'
}).format(new Date('2026-10-22T10:41:00Z')));
console.log(JSON.stringify({ ok: true }));
"""
    result = subprocess.run(
        ["node", "-e", runtime, str(script_dir)],
        env={**os.environ, "TZ": browser_timezone},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["ok"] is True


class _NonUtcHostClock(datetime):
    """Simulate a UTC+2 host without changing the test runner's process timezone."""

    @classmethod
    def now(cls, tz=None):
        if tz is None:
            return datetime(2026, 10, 22, 12, 41)
        return datetime(2026, 10, 22, 10, 41, tzinfo=timezone.utc).astimezone(tz)

    @classmethod
    def utcnow(cls):
        return datetime(2026, 10, 22, 10, 41)


def test_poll_status_producer_is_utc_on_non_utc_server(monkeypatch):
    import asyncio
    from unittest.mock import MagicMock

    import app.main as main_module

    source = SimpleNamespace(
        server="imap.example.test",
        port=993,
        username="test",
        password=None,
        use_ssl=True,
        folder="INBOX",
        workspace_id=1,
    )
    monkeypatch.setattr(main_module, "datetime", _NonUtcHostClock)
    monkeypatch.setattr(main_module, "IMAPClient", MagicMock())
    monkeypatch.setattr(main_module, "record_import_attempt", MagicMock())
    monkeypatch.setattr(main_module, "_trigger_poll_result", lambda *_args: {})
    monkeypatch.setattr(main_module, "_mail_source_status_summary", lambda: {})
    monkeypatch.setattr(main_module, "last_check_time", None)
    main_module._trigger_poll_imap_source(source, MagicMock())
    assert main_module.last_check_time == datetime(2026, 10, 22, 10, 41, tzinfo=timezone.utc)
    assert source.last_checked == datetime(2026, 10, 22, 10, 41)
    payload = asyncio.run(main_module.get_poll_status({"auth_type": "api_key"}))
    assert payload["last_check"] == "2026-10-22T10:41:00+00:00"


def test_stats_cache_metadata_is_utc_on_non_utc_server(tmp_path, monkeypatch):
    from app.utils import stats_summarizer

    monkeypatch.setattr(stats_summarizer, "datetime", _NonUtcHostClock)
    summarizer = stats_summarizer.StatsSummarizer(cache_dir=str(tmp_path))
    stats = {"reports_processed": 1}
    assert summarizer.save_summary(stats)
    assert stats["cached_at"] == "2026-10-22T10:41:00+00:00"


def test_settings_timestamp_labels_evaluate_with_shipped_alpine_csp():
    from html.parser import HTMLParser

    class TimestampLabels(HTMLParser):
        def __init__(self):
            super().__init__()
            self.expressions = []

        def handle_starttag(self, _tag, attrs):
            self.expressions.extend(
                value for name, value in attrs if name == "x-text" and "formatDateTime(" in value
            )

    app_root = Path(__file__).parents[1]
    parser = TimestampLabels()
    parser.feed((app_root / "templates" / "settings.html").read_text())
    assert len(parser.expressions) == 3
    runtime = r"""
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const Element = class {};
const root = {
    dataset: {appTimezone: 'Europe/Berlin', appLocale: 'en-GB'}, lang: 'en',
    classList: {add: () => {}, remove: () => {}}, setAttribute: () => {},
};
const context = {
    window: {Element}, document: {
        documentElement: root, createElement: () => ({}), addEventListener: () => {},
    },
    Element, ShadowRoot: class {}, HTMLIFrameElement: class {}, HTMLScriptElement: class {},
    MutationObserver: class {}, queueMicrotask: () => {},
    localStorage: {getItem: () => null}, Date, Intl,
};
vm.createContext(context);
for (const name of ['vendor/alpine.min.js', 'localization.js', 'base-layout.js', 'settings-page.js']) {
    vm.runInContext(fs.readFileSync(`${process.argv[1]}/${name}`, 'utf8'), context);
}
const Alpine = context.window.Alpine;
Alpine.setErrorHandler(error => {throw error;});
const expressions = JSON.parse(process.argv[2]);
const instant = '2026-10-22T10:41:00Z';
const formatted = '22/10/2026, 12:41:00';
const hook = {last_success_at: instant, last_failure_at: null};
const scope = {baseline: {expires_at: instant, record_count: 3}, item: {changed_at: instant}, hook};
const evaluate = expression => Alpine.evaluate({_x_dataStack: [scope, context.settingsApp()]}, expression);
assert.deepEqual(expressions.map(evaluate), [
    ` · 3 records · expires ${formatted}`, formatted, `Success ${formatted}`,
]);
hook.last_success_at = null;
hook.last_failure_at = instant;
assert.equal(evaluate(expressions[2]), `Failed ${formatted}`);
hook.last_failure_at = null;
assert.equal(evaluate(expressions[2]), 'No deliveries');
"""
    result = subprocess.run(
        ["node", "-e", runtime, str(app_root / "static" / "js"), json.dumps(parser.expressions)],
        env={**os.environ, "TZ": "America/Los_Angeles"},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
