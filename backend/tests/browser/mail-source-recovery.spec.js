const fs = require('fs');
const http = require('http');
const path = require('path');
const { test, expect } = require('@playwright/test');

const repoRoot = path.resolve(__dirname, '../../');
const alpine = fs.readFileSync(path.join(repoRoot, 'app/static/js/vendor/alpine.min.js'), 'utf8');
const pageScript = fs.readFileSync(path.join(repoRoot, 'app/static/js/mail-sources-page.js'), 'utf8');
const template = fs.readFileSync(path.join(repoRoot, 'app/templates/mail_sources.html'), 'utf8');
const recoveryMarkupStart = template.indexOf('<template x-for="item in (entry.recovery_items || [])"');
const recoveryMarkupEnd = template.indexOf('</template>', recoveryMarkupStart) + '</template>'.length;
const recoveryMarkup = template.slice(recoveryMarkupStart, recoveryMarkupEnd);

test('mail source recovery controls use shipped Alpine and actual page bindings', async ({ page }) => {
  const consoleErrors = [];
  const pageErrors = [];
  page.on('console', message => {
    if (message.type() === 'error') consoleErrors.push(message.text());
  });
  page.on('pageerror', error => pageErrors.push(error.message));

  let retryRequest;
  const server = http.createServer((request, response) => {
    if (request.url === '/api/v1/mail-sources') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end('[]');
      return;
    }
    if (request.url === '/api/v1/mail-sources/1/imports/42/retry') {
      retryRequest = response;
      return;
    }
    response.writeHead(200, { 'content-type': 'text/html' });
    response.end(`
      <div x-data="mailSourcesApp">
        <template x-for="entry in importHistory" :key="entry.id">
          ${recoveryMarkup}
        </template>
      </div>
      <script>${pageScript}</script>
      <script>
        document.addEventListener('alpine:init', () => {
          const pageApp = mailSourcesApp;
          Alpine.data('mailSourcesApp', () => {
            const app = pageApp();
            app.historySource = { id: 1 };
            app.historyLoading = false;
            app.loading = true;
            app.importHistory = app.normalizeImportHistory([
              { id: 42, recovery_items: [
                { message_id: 'pending', supported: true, disposition: 'pending' },
                { message_id: 'settled', supported: true, disposition: 'ignored' },
              ] },
            ]);
            return app;
          });
        });
      </script>
      <script>${alpine}</script>
    `);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const address = server.address();
    await page.goto(`http://127.0.0.1:${address.port}`);

    const retry = page.locator('[data-mail-source-recovery-retry]');
    const ignore = page.locator('[data-mail-source-recovery-ignore]');
    const normalized = await page.evaluate(() => document.querySelector('[x-data]')._x_dataStack[0].importHistory[0].recovery_items[0]);
    expect(normalized).toHaveProperty('loading', false);
    await expect(retry.nth(0)).toBeVisible();
    await expect(retry.nth(0)).toBeEnabled();
    await expect(ignore.nth(0)).toBeVisible();
    await expect(ignore.nth(0)).toBeEnabled();
    await expect(retry.nth(1)).toBeHidden();
    await expect(ignore.nth(1)).toBeHidden();

    await retry.nth(0).click();
    await expect.poll(() => Boolean(retryRequest)).toBe(true);
    await expect(retry.nth(0)).toBeDisabled();
    retryRequest.writeHead(200, { 'content-type': 'application/json' });
    retryRequest.end(JSON.stringify({ success: true }));
    expect(consoleErrors).toEqual([]);
    expect(pageErrors).toEqual([]);
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});
