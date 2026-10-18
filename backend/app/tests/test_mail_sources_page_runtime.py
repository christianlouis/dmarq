"""Runtime checks for the import-history recovery controls."""

import subprocess
from pathlib import Path


def test_ignored_history_item_can_retry_from_the_page_runtime():
    script_path = Path(__file__).parents[1] / "static" / "js" / "mail-sources-page.js"
    runtime = r"""
const fs = require('fs');
const vm = require('vm');
const source = fs.readFileSync(process.argv[1], 'utf8');
const calls = [];
const context = {
  window: {},
  document: { addEventListener: () => {} },
  Alpine: { data: () => {} },
  fetch: async (url, options) => {
    calls.push({ url, options });
    return { ok: true, json: async () => ({ success: true }) };
  },
};
vm.createContext(context);
vm.runInContext(source, context);
const app = context.mailSourcesApp();
const item = { message_id: 'ignored-message', supported: true, disposition: 'ignored' };
const entry = { id: 17, recovery_items: [item] };
app.historySource = { id: 9 };
app.importHistory = [entry];
app.loadImportHistory = async () => { app.reloaded = true; };
app.retryImportItem(entry, item).then(() => {
  if (calls.length !== 1 || !calls[0].url.endsWith('/9/imports/17/retry')) process.exit(1);
  if (!app.reloaded || item.loading) process.exit(1);
});
"""
    result = subprocess.run(
        ["node", "-e", runtime, str(script_path)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
