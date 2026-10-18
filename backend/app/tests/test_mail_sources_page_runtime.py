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
const context = {
  window: {},
  document: { addEventListener: () => {} },
  Alpine: { data: () => {} },
  fetch: async (url, options) => {
    calls.push({ url, options });
    return { ok: true, json: async () => retryResult };
  },
};
vm.createContext(context);
vm.runInContext(source, context);
const app = context.mailSourcesApp();
const item = { message_id: 'ignored-message', supported: true, disposition: 'ignored' };
const entry = { id: 17, recovery_items: [item] };
app.historySource = { id: 9 };
app.importHistory = [entry];
app.loadImportHistory = async (_source, preserveFeedback) => {
  app.reloaded = true;
  app.preservedFeedback = preserveFeedback;
};
(async () => {
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
})().catch(() => process.exit(1));
"""
    result = subprocess.run(
        ["node", "-e", runtime, str(script_path)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
