const { defineConfig, devices } = require('@playwright/test');

const port = process.env.DMARQ_BROWSER_SMOKE_PORT || '18080';
const baseURL = process.env.PLAYWRIGHT_BASE_URL || `http://127.0.0.1:${port}`;
const useExternalServer = Boolean(process.env.PLAYWRIGHT_BASE_URL);
const python = process.env.DMARQ_BROWSER_SMOKE_PYTHON || 'python3';

const config = {
  testDir: './tests/browser',
  timeout: 30_000,
  expect: { timeout: 6_000 },
  use: {
    baseURL,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
};

if (!useExternalServer) {
  config.webServer = {
    command: `${python} tests/browser/smoke_server.py`,
    url: `${baseURL}/health`,
    timeout: 30_000,
    reuseExistingServer: !process.env.CI,
    env: {
      ...process.env,
      DMARQ_BROWSER_SMOKE_PORT: port,
      CSP_REPORT_ONLY: process.env.CSP_REPORT_ONLY || 'true',
    },
  };
}

module.exports = defineConfig(config);
