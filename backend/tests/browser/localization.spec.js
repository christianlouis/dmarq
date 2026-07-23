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
  await page.locator('#settings-language-selector').selectOption('en');
  await page.waitForLoadState('domcontentloaded');

  await expect(page.locator('html')).toHaveAttribute('lang', 'en');
  await expect(page.getByRole('link', { name: 'Dashboard' }).first()).toBeVisible();
  await expect(page.locator('#settings-language-selector')).toHaveValue('en');
});
