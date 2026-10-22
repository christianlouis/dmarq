const fs = require('fs');
const http = require('http');
const path = require('path');
const { test, expect } = require('@playwright/test');

const alpinePath = process.env.DMARQ_ALPINE_CSP_PATH
  || path.join(__dirname, '../../node_modules/@alpinejs/csp/dist/cdn.min.js');

test('recovery controls render through the bundled Alpine CSP runtime', async ({ page }) => {
  const consoleErrors = [];
  const pageErrors = [];
  page.on('console', message => {
    if (message.type() === 'error') consoleErrors.push(message.text());
  });
  page.on('pageerror', error => pageErrors.push(error.message));
  await page.addInitScript(() => {
    Object.defineProperty(window, 'localStorage', {
      value: { getItem: () => null, setItem: () => {}, removeItem: () => {} },
    });
  });

  const alpine = fs.readFileSync(alpinePath, 'utf8');
  const fixture = `
    <script>
      document.addEventListener('alpine:init', () => {
        Alpine.data('mailSourceRecoveryFixture', () => ({
          historyLoading: false,
          recoveryItems: [
            { message_id: 'pending', supported: true, disposition: 'pending', loading: false },
            { message_id: 'settled', supported: true, disposition: 'settled', loading: false },
          ],
        }));
      });
    </script>
    <script>${alpine}</script>
    <div x-data="mailSourceRecoveryFixture()">
      <template x-for="item in recoveryItems" :key="item.message_id">
        <div class="recovery-item">
          <button data-mail-source-recovery-retry
            :disabled="historyLoading || item.loading"
            x-show="item.supported && item.disposition === 'pending'"
            @click="item.loading = true">Retry</button>
          <button data-mail-source-recovery-ignore
            :disabled="historyLoading || item.loading"
            x-show="item.supported && item.disposition === 'pending'">Ignore</button>
        </div>
      </template>
    </div>
  `;
  const server = http.createServer((_request, response) => {
    response.writeHead(200, { 'content-type': 'text/html' });
    response.end(fixture);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  await page.goto(`http://127.0.0.1:${address.port}`);

  const retry = page.locator('[data-mail-source-recovery-retry]');
  const ignore = page.locator('[data-mail-source-recovery-ignore]');
  if (await retry.count() === 0) throw new Error(`fixture did not initialize: ${JSON.stringify({ consoleErrors, pageErrors })}`);
  await expect(retry.nth(0)).toBeVisible();
  await expect(retry.nth(0)).toBeEnabled();
  await expect(ignore.nth(0)).toBeVisible();
  await expect(ignore.nth(0)).toBeEnabled();
  await expect(retry.nth(1)).toBeHidden();
  await expect(ignore.nth(1)).toBeHidden();

  await retry.nth(0).click();
  await expect(retry.nth(0)).toBeDisabled();
  expect(consoleErrors).toEqual([]);
  expect(pageErrors).toEqual([]);
  await new Promise(resolve => server.close(resolve));
});
