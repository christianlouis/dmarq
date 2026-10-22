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


def test_import_history_ignores_stale_source_and_action_responses():
    script_path = Path(__file__).parents[1] / "static" / "js" / "mail-sources-page.js"
    runtime = r"""
const fs = require('fs');
const vm = require('vm');
const source = fs.readFileSync(process.argv[1], 'utf8');
const historyResponses = {};
let actionResponse;
const context = {
  window: {},
  document: { addEventListener: () => {} },
  Alpine: { data: () => {} },
  fetch: async (url) => {
    if (url.includes('/imports?')) return new Promise(resolve => { historyResponses[url] = resolve; });
    return new Promise(resolve => { actionResponse = resolve; });
  },
};
vm.createContext(context);
vm.runInContext(source, context);
const app = context.mailSourcesApp();
const sourceA = { id: 1, name: 'A' };
const sourceB = { id: 2, name: 'B' };
const response = entries => ({ ok: true, json: async () => entries });
(async () => {
  const loadA = app.loadImportHistory(sourceA);
  const loadB = app.loadImportHistory(sourceB);
  historyResponses['/api/v1/mail-sources/2/imports?limit=20'](response([{ id: 'B' }]));
  await loadB;
  historyResponses['/api/v1/mail-sources/1/imports?limit=20'](response([{ id: 'A' }]));
  await loadA;
  if (app.historySource.id !== 2 || app.importHistory[0].id !== 'B') process.exit(1);

  app.historySource = sourceA;
  app.historyRequestGeneration += 1;
  const item = { message_id: 'message-a', loading: false };
  const action = app.retryImportItem({ id: 9 }, item);
  const loadNewSource = app.loadImportHistory(sourceB);
  actionResponse(response({ success: true }));
  await action;
  if (app.historySource.id !== 2 || app.historySource.name !== 'B') process.exit(1);
  historyResponses['/api/v1/mail-sources/2/imports?limit=20'](response([{ id: 'B-again' }]));
  await loadNewSource;
  if (app.importHistory[0].id !== 'B-again' || item.loading) process.exit(1);
})().catch(error => { console.error(error); process.exit(1); });
"""
    result = subprocess.run(
        ["node", "-e", runtime, str(script_path)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
