const { test, expect } = require('@playwright/test');

test('German preference translates the core product and formats with de locale', async ({ page, context }) => {
  await context.addCookies([{
    name: 'dmarq_locale',
    value: 'de',
    url: process.env.PLAYWRIGHT_BASE_URL || 'http://127.0.0.1:18080',
  }]);

  await page.goto('/settings');

  await expect(page.locator('html')).toHaveAttribute('lang', 'de');
  await expect(page.getByRole('link', { name: 'Übersicht' }).first()).toBeVisible();
  await expect(page.getByRole('link', { name: 'Berichte' }).first()).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Führe den nächsten sicheren Einrichtungsschritt aus' })).toBeVisible();
  await expect(page.locator('#settings-language-selector')).toHaveValue('de');

  const formatted = await page.evaluate(() => window.dmarqFormatNumber(12345.6));
  expect(formatted).toContain('12.345');
});

test('language selector persists an explicit English choice', async ({ page }) => {
  await page.goto('/settings?lang=de');

  await expect(page.locator('html')).toHaveAttribute('lang', 'de');
  await expect(page.getByRole('link', { name: 'Übersicht' }).first()).toBeVisible();
  await expect(page.locator('#settings-language-selector')).toHaveValue('de');

  await page.locator('#settings-language-selector').selectOption('en');
  await page.waitForLoadState('domcontentloaded');

  await expect(page.locator('html')).toHaveAttribute('lang', 'en');
  await expect(page.getByRole('link', { name: 'Dashboard' }).first()).toBeVisible();
  await expect(page.locator('#settings-language-selector')).toHaveValue('en');
});

test('language selector in the asynchronously rendered account menu persists the choice', async ({ page }) => {
  await page.goto('/?lang=en');

  const accountMenu = page.getByLabel('Open account menu');
  await expect(accountMenu).toBeVisible();
  await accountMenu.click();

  const languageSelector = page.locator('#account-language-selector');
  await expect(languageSelector).toBeVisible();
  await expect(languageSelector).toHaveValue('en');
  await languageSelector.selectOption('de');
  await page.waitForLoadState('domcontentloaded');

  await expect(page.locator('html')).toHaveAttribute('lang', 'de');
  await expect(page.getByRole('link', { name: 'Übersicht' }).first()).toBeVisible();

  await page.reload();
  await expect(page.locator('html')).toHaveAttribute('lang', 'de');
  await accountMenu.click();
  await expect(page.locator('#account-language-selector')).toHaveValue('de');
});

test('German dashboard remains responsive while Alpine renders translated data', async ({ page }) => {
  await page.route('**/api/v1/domains/summary?*', route => route.fulfill({
    contentType: 'application/json',
    body: JSON.stringify({
      domains: [{
        domain_name: 'example.com',
        total_reports: 1,
        total_emails: 10,
        passed_emails: 9,
        failed_emails: 1,
        compliance_rate: 90,
      }],
      total_reports: 1,
      total_emails: 10,
      empty_domains_hidden: 0,
    }),
  }));
  await page.route('**/api/v1/stats/dashboard?*', route => route.fulfill({
    contentType: 'application/json',
    body: JSON.stringify({
      total_domains: 1,
      total_emails: 10,
      compliant_emails: 9,
      compliance_rate: 90,
      reports_processed: 1,
      top_sources: [],
      compliance_trend: [],
      change_summary: [],
    }),
  }));
  const domainResponse = page.waitForResponse(
    response => response.url().includes('/api/v1/domains/summary?') && response.ok(),
  );
  const statsResponse = page.waitForResponse(
    response => response.url().includes('/api/v1/stats/dashboard?') && response.ok(),
  );

  await page.goto('/?lang=de');
  await domainResponse;
  await statsResponse;

  await expect(page.locator('html')).toHaveAttribute('lang', 'de');
  await expect(page.getByRole('link', { name: 'Übersicht' }).first()).toBeVisible();
  await page.locator('[data-dashboard-analytics]').evaluate(element => { element.open = true; });
  await expect(page.locator('#total-emails')).toHaveText('10');
  await expect(page.getByText('DMARC-Konformitätsrate').first()).toBeVisible();
});
