"""Runtime checks for the import-history recovery controls."""

import subprocess
from pathlib import Path


def test_import_history_retry_runtime_handles_ignored_and_failed_results():
    script_path = Path(__file__).parents[1] / "static" / "js" / "mail-sources-page.js"
    runtime = r"""
const fs = require('fs');
const vm = require('vm');
const source = fs.readFileSync(process.argv[1], 'utf8');
const calls = [];
let retryResult = { success: true };
let fetchMode = 'normal';
let releaseRetry;
let releaseIgnore;
const context = {
  window: {},
  document: { addEventListener: () => {} },
  Alpine: { data: () => {} },
  fetch: async (url, options) => {
    calls.push({ url, options });
    if (fetchMode === 'reject') throw new Error('network down');
    if (fetchMode === 'retry-wait') await new Promise(resolve => { releaseRetry = resolve; });
    if (fetchMode === 'ignore-wait') await new Promise(resolve => { releaseIgnore = resolve; });
    return { ok: true, json: async () => retryResult };
  },
};
vm.createContext(context);
vm.runInContext(source, context);
const app = context.mailSourcesApp();
const normalized = app.normalizeImportHistory([{
  id: 17,
  recovery_items: [
    { message_id: 'pending-message', supported: true, disposition: 'pending' },
    { message_id: 'settled-message', supported: true, disposition: 'settled' },
  ],
}]);
const pending = normalized[0].recovery_items[0];
const settled = normalized[0].recovery_items[1];
if (pending.loading !== false || settled.loading !== false) process.exit(1);
if (!(pending.supported && pending.disposition === 'pending')) process.exit(1);
if (settled.supported && settled.disposition === 'pending') process.exit(1);
const item = { message_id: 'ignored-message', supported: true, disposition: 'ignored' };
const entry = { id: 17, recovery_items: [item] };
app.historySource = { id: 9 };
app.importHistory = [entry];
if (app.recoveryItemLabel({ label: 'report.xml', message_id: 'ignored-message' }) !== 'report.xml') process.exit(1);
if (app.recoveryItemLabel({ message_id: 'provider-message-id' }) !== 'Message …message-id') process.exit(1);
app.loadImportHistory = async (_source, preserveFeedback) => {
  app.reloaded = true;
  app.preservedFeedback = preserveFeedback;
};
(async () => {
  app.historySource = null;
  await app.retryImportItem(entry, { message_id: 'missing-history' });
  if (calls.length !== 0) process.exit(1);
  app.historySource = { id: 9 };
  await app.retryImportItem(entry, item);
  if (calls.length !== 1 || !calls[0].url.endsWith('/9/imports/17/retry')) process.exit(1);
  if (!app.reloaded || !app.preservedFeedback || item.loading) process.exit(1);

  retryResult = {
    success: false,
    diagnostic: { summary: 'Provider rejected the message.' },
    recovery_steps: ['Refresh provider authorization and retry.'],
  };
  app.reloaded = false;
  await app.retryImportItem(entry, item);
  if (calls.length !== 2 || !app.reloaded || item.loading) process.exit(1);
  if (app.feedback.type !== 'error' || app.feedback.message !== 'Provider rejected the message.') process.exit(1);
  if (app.feedback.recovery_steps.length !== 1) process.exit(1);

  fetchMode = 'reject';
  await app.retryImportItem(entry, item);
  if (calls.length !== 3 || item.loading || app.feedback.message !== 'Error: network down') process.exit(1);

  fetchMode = 'retry-wait';
  const firstRetry = app.retryImportItem(entry, item);
  await Promise.resolve();
  await app.retryImportItem(entry, item);
  if (calls.length !== 4 || !item.loading) process.exit(1);
  releaseRetry();
  await firstRetry;
  if (item.loading) process.exit(1);

  fetchMode = 'ignore-wait';
  const firstIgnore = app.ignoreImportItem(entry, item);
  await Promise.resolve();
  await app.ignoreImportItem(entry, item);
  if (calls.length !== 5 || !item.loading) process.exit(1);
  releaseIgnore();
  await firstIgnore;
  if (item.loading) process.exit(1);
})().catch(() => process.exit(1));
"""
    result = subprocess.run(
        ["node", "-e", runtime, str(script_path)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_import_history_template_has_csp_safe_recovery_state_bindings():
    template = (Path(__file__).parents[1] / "templates" / "mail_sources.html").read_text()
    assert "source.latest_import?." not in template
    assert ':disabled="historyLoading || item.loading"' in template
    assert "x-show=\"item.supported && item.disposition === 'pending'\"" in template


def test_recovery_runtime_resets_loading_and_ignores_interrupted_or_repeated_actions():
    script_path = Path(__file__).parents[1] / "static" / "js" / "mail-sources-page.js"
    runtime = r"""
const assert = require('assert');
const fs = require('fs');
const vm = require('vm');
const source = fs.readFileSync(process.argv[1], 'utf8');
const deferred = () => {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
};
let requests = [];
const context = {
  window: {}, document: { addEventListener: () => {} }, Alpine: { data: () => {} },
  fetch: (url, options) => {
    const result = deferred(); requests.push({ url, options, ...result }); return result.promise;
  },
};
vm.createContext(context);
vm.runInContext(source, context);
const response = (body, ok = true) => ({ ok, json: async () => body });
const app = context.mailSourcesApp();
const reset = () => {
  requests = [];
  app.historySource = { id: 9 };
  app.feedback = app.emptyFeedback();
  const item = { message_id: 'message', supported: true, disposition: 'pending' };
  const entry = { id: 17, recovery_items: [item] };
  app.importHistory = [entry];
  return { item, entry };
};
(async () => {
  for (const action of ['retryImportItem', 'ignoreImportItem']) {
    // A repeated click, including the other action, cannot issue another request.
    let { item, entry } = reset();
    const operation = app[action](entry, item);
    await app[action](entry, item);
    await app[action === 'retryImportItem' ? 'ignoreImportItem' : 'retryImportItem'](entry, item);
    assert.strictEqual(requests.length, 1);
    assert.strictEqual(item.loading, true);
    requests[0].reject(new Error('Network interrupted'));
    await operation;
    assert.strictEqual(item.loading, false);
    assert.match(app.feedback.message, /Network interrupted/);

    // JSON failures also release the controls, and a subsequent attempt can run.
    const malformed = app[action](entry, item);
    requests[1].resolve({ ok: true, json: async () => { throw new Error('Malformed response'); } });
    await malformed;
    assert.strictEqual(item.loading, false);
    const retried = app[action](entry, item);
    requests[2].resolve(response({ detail: 'Provider unavailable' }, false));
    await retried;
    assert.strictEqual(item.loading, false);
    assert.match(app.feedback.message, /Provider unavailable/);

    // Closing the history must not reopen it when an in-flight action completes.
    ({ item, entry } = reset());
    const closed = app[action](entry, item);
    app.closeHistory();
    requests[0].resolve(response({ success: true }));
    await closed;
    assert.strictEqual(app.historySource, null);
    assert.strictEqual(app.importHistory.length, 0);
    assert.strictEqual(requests.length, 1);
    assert.strictEqual(item.loading, false);

    // A completed action cannot overwrite or reload a newer source's history.
    ({ item, entry } = reset());
    const old = app[action](entry, item);
    const newer = app.loadImportHistory({ id: 10 });
    requests[1].resolve(response([{ id: 99 }]));
    await newer;
    requests[0].resolve(response({ success: true }));
    await old;
    assert.strictEqual(app.historySource.id, 10);
    assert.strictEqual(app.importHistory[0].id, 99);
    assert.strictEqual(requests.length, 2);
    assert.strictEqual(item.loading, false);
  }

  // Different items in the same open history may finish around a refresh.
  // Both successful actions must refresh; request generations keep GET responses ordered.
  let { item, entry } = reset();
  const other = { message_id: 'other', supported: true, disposition: 'pending' };
  entry.recovery_items.push(other);
  const slow = app.retryImportItem(entry, item);
  const fast = app.ignoreImportItem(entry, other);
  requests[1].resolve(response({ success: true }));
  await new Promise(resolve => setImmediate(resolve));
  assert.strictEqual(requests.length, 3);
  requests[2].resolve(response([{ id: 17, recovery_items: [item] }]));
  await fast;
  requests[0].resolve(response({ success: true }));
  await new Promise(resolve => setImmediate(resolve));
  assert.strictEqual(requests.length, 4);
  requests[3].resolve(response([{ id: 17, recovery_items: [] }]));
  await slow;
  assert.strictEqual(app.importHistory[0].recovery_items.length, 0);
  assert.strictEqual(item.loading, false);
  assert.strictEqual(other.loading, false);

  // Older history requests cannot replace newer results or clear their loading state.
  reset();
  const first = app.loadImportHistory({ id: 1 });
  const second = app.loadImportHistory({ id: 2 });
  requests[0].resolve(response([{ id: 1 }]));
  await first;
  assert.strictEqual(app.historyLoading, true);
  assert.strictEqual(app.importHistory.length, 0);
  requests[1].resolve(response([{ id: 2 }]));
  await second;
  assert.strictEqual(app.importHistory[0].id, 2);
  assert.strictEqual(app.historyLoading, false);

  const dismissed = app.loadImportHistory({ id: 3 });
  app.closeHistory();
  requests[2].reject(new Error('Late history failure'));
  await dismissed;
  assert.strictEqual(app.historySource, null);
  assert.strictEqual(app.historyLoading, false);
  assert.strictEqual(app.feedback.message, '');
})().catch(error => { console.error(error); process.exit(1); });
"""
    result = subprocess.run(
        ["node", "-e", runtime, str(script_path)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
