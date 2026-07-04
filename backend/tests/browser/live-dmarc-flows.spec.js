const { test, expect } = require('@playwright/test');

const sourcePostmark = {
  hostname: 'mta203-ab1.mtasv.net',
  country: 'United States',
  country_code: 'US',
  region: 'North America',
  asn: 'AS23352',
  network: 'SERVERCENTRAL - DEFT.COM, US',
  bgp_prefix: '50.31.128.0/17',
  registry: 'arin',
  allocated: '2011-02-03',
  radar_url: 'https://radar.cloudflare.com/ip/50.31.205.203',
  sender: {
    label: 'Postmark',
    status: 'known',
    provider: 'ActiveCampaign Postmark',
    confidence: 95,
    reason: 'PTR hostname matched mta203-ab1.mtasv.net',
  },
};

const sourceOwned = {
  hostname: 'mx1.cklnet.com',
  country: 'Germany',
  country_code: 'DE',
  region: 'Europe',
  asn: 'AS24940',
  network: 'HETZNER-AS - Hetzner Online GmbH, DE',
  bgp_prefix: '2a01:4f8::/32',
  registry: 'ripencc',
  allocated: '2007-10-10',
  radar_url: 'https://radar.cloudflare.com/ip/2a01:4f8:c17:311b::1',
  sender: {
    label: 'Owned infrastructure',
    status: 'known',
    provider: 'cklnet.com',
    confidence: 70,
    reason: 'PTR hostname matched mx1.cklnet.com',
  },
};

const reputationClean = {
  status: 'clean',
  status_label: 'Reputation clean',
  status_detail: 'External feeds checked clean.',
  risk_score: 0,
  feed_status: 'checked',
  feed_summary: 'No blacklist listings found.',
  evidence_summary: 'Abusix checked clean',
  checked_at: '2026-07-03T12:00:00Z',
  evidence: [{ label: 'Abusix', value: 'not listed', source: 'abusix' }],
  recommendations: [],
};

const reputationUnknown = {
  status: 'unknown',
  status_label: 'Reputation not checked',
  status_detail: 'No external feed result is available yet.',
  risk_score: 0,
  feed_status: 'not_configured',
  feed_summary: 'Reputation feeds are disabled.',
  evidence_summary: 'Local report evidence only',
  checked_at: null,
  evidence: [],
  recommendations: [],
};

const domainSummary = {
  total_domains: 2,
  total_emails: 2873,
  overall_pass_rate: 92.6,
  reports_processed: 3,
  health_summary: {
    score: 84,
    grade: 'B',
    status: 'needs attention',
    attention_domains: 1,
    domain_count: 2,
    top_actions: [
      {
        domain: 'cklnet.com',
        type: 'dkim_alignment',
        severity: 'high',
        title: 'Fix DKIM alignment for owned infrastructure',
        detail: 'One recent source is SPF-aligned but DKIM is failing.',
        score_impact: 8,
        next_step: 'Open cklnet.com sending sources and verify the mail selector.',
        evidence: [{ label: 'source_ip', value: '2a01:4f8:c17:311b::1' }],
      },
    ],
    domains: [
      { domain: 'cklnet.com', score: 78, grade: 'C', status: 'needs attention' },
      { domain: 'dmarq.org', score: 96, grade: 'A', status: 'healthy' },
    ],
  },
  domains: [
    {
      domain_name: 'cklnet.com',
      dmarc_status: true,
      dmarc_policy: 'reject',
      spf_status: true,
      dkim_status: true,
      dns_pending: false,
      dns_cached: true,
      dns_checked_at: '2026-07-03T12:00:00Z',
      report_count: 2,
      total_emails: 2849,
      pass_rate: 92.1,
      description: 'Primary mail domain with mixed source evidence',
      dkim_selectors: ['pm', 'mail'],
    },
    {
      domain_name: 'dmarq.org',
      dmarc_status: true,
      dmarc_policy: 'quarantine',
      spf_status: true,
      dkim_status: true,
      dns_pending: false,
      dns_cached: true,
      report_count: 1,
      total_emails: 24,
      pass_rate: 100,
      description: 'Demo product domain',
      dkim_selectors: ['google'],
    },
  ],
};

const reports = [
  {
    report_id: 'browser-smoke-cklnet',
    domain: 'cklnet.com',
    org_name: 'google.com',
    begin_date: '2026-07-01',
    end_date: '2026-07-02',
    total_count: 9,
    passed_count: 8,
    failed_count: 1,
    pass_rate: 88.9,
  },
  {
    report_id: 'browser-smoke-dmarq',
    domain: 'dmarq.org',
    org_name: 'google.com',
    begin_date: '2026-07-01',
    end_date: '2026-07-02',
    total_count: 24,
    passed_count: 24,
    failed_count: 0,
    pass_rate: 100,
  },
];

const healthHistory = {
  points: [
    { date: '2026-07-01', score: 78, grade: 'C' },
    { date: '2026-07-02', score: 84, grade: 'B' },
  ],
  current_score: 84,
  previous_score: 78,
  score_delta: 6,
  current_grade: 'B',
  previous_grade: 'C',
  top_drivers: [],
};

const dashboardStats = {
  total_domains: 2,
  total_emails: 2873,
  overall_pass_rate: 92.6,
  reports_processed: 3,
  date_range: {
    label: 'Last 30 days',
    start_date: '2026-06-04',
    end_date: '2026-07-03',
  },
  compliance_trend: [
    { date: '2026-07-01', total: 9, passed: 8, failed: 1, compliance_rate: 88.9 },
    { date: '2026-07-02', total: 2864, passed: 2858, failed: 6, compliance_rate: 99.8 },
  ],
  top_sources: [
    { name: 'Postmark', domain: 'cklnet.com', count: 2736, pass_rate: 100 },
    { name: 'Owned infrastructure', domain: 'cklnet.com', count: 137, pass_rate: 94.2 },
  ],
  change_summary: [
    {
      domain: 'cklnet.com',
      title: 'Owned infrastructure still has DKIM failures',
      detail: 'Keep SPF aligned, then repair DKIM signing.',
      severity: 'high',
    },
  ],
};

const reportDetail = {
  report_id: 'browser-smoke-cklnet',
  org_name: 'google.com',
  email: 'noreply-dmarc-support@google.com',
  domain: 'cklnet.com',
  begin_date: '2026-07-01',
  end_date: '2026-07-02',
  begin_timestamp: 1782864000,
  end_timestamp: 1782950399,
  policy: { p: 'reject', sp: 'reject', pct: '100' },
  summary: { total_count: 9, passed_count: 8, failed_count: 1, pass_rate: 88.9 },
  records: [
    {
      source_ip: '50.31.205.203',
      count: 8,
      disposition: 'none',
      dkim_result: 'pass',
      spf_result: 'pass',
      header_from: 'cklnet.com',
      review_status: 'pass',
      failure_reasons: [],
      next_steps: [],
      source_details: sourcePostmark,
      reputation: reputationClean,
    },
    {
      source_ip: '2a01:4f8:c17:311b::1',
      count: 1,
      disposition: 'reject',
      dkim_result: 'fail',
      spf_result: 'pass',
      header_from: 'mx1.cklnet.com',
      review_status: 'needs_review',
      failure_reasons: ['DKIM did not pass for this source.'],
      next_steps: ['Check the DKIM selector in this report against the sender DNS record.'],
      source_details: sourceOwned,
      reputation: reputationUnknown,
    },
  ],
};

const domainReports = {
  reports,
  compliance_timeline: dashboardStats.compliance_trend,
};

const domainSources = {
  sources: [
    {
      ip: '50.31.205.203',
      source_ip: '50.31.205.203',
      hostname: sourcePostmark.hostname,
      total_count: 2736,
      count: 2736,
      dmarc: 'pass',
      dmarc_result: 'pass',
      spf: 'pass',
      spf_result: 'pass',
      dkim: 'pass',
      dkim_result: 'pass',
      disposition: 'none',
      last_seen: 1782950399,
      first_seen: 1754697600,
      active_days: 141,
      report_count: 151,
      source_details: sourcePostmark,
      sender: sourcePostmark.sender,
      reputation: reputationClean,
      recommendations: [],
      volume_history: [{ date: '2026-07-02', count: 2736, passed: 2736, failed: 0 }],
    },
    {
      ip: '2a01:4f8:c17:311b::1',
      source_ip: '2a01:4f8:c17:311b::1',
      hostname: sourceOwned.hostname,
      total_count: 137,
      count: 137,
      dmarc: 'mixed',
      dmarc_result: 'mixed',
      spf: 'pass',
      spf_result: 'pass',
      dkim: 'mixed',
      dkim_result: 'mixed',
      disposition: 'none',
      last_seen: 1782950399,
      first_seen: 1754352000,
      active_days: 40,
      report_count: 44,
      source_details: sourceOwned,
      sender: sourceOwned.sender,
      reputation: reputationUnknown,
      recommendations: [
        {
          title: 'Fix DKIM on owned infrastructure',
          detail: 'DMARC is passing through SPF, but DKIM is unreliable.',
          action: 'Publish or repair the mail selector for mx1.cklnet.com.',
        },
      ],
      volume_history: [{ date: '2026-07-02', count: 137, passed: 130, failed: 7 }],
    },
  ],
};

const dnsCached = {
  dmarc: true,
  dmarcRecord: 'v=DMARC1; p=reject; rua=mailto:dmarc@cklnet.com',
  spf: true,
  spfRecord: 'v=spf1 include:spf.mtasv.net ip6:2a01:4f8:c17:311b::1 -all',
  dkim: true,
  dkimSelectors: ['pm', 'mail'],
  nameservers: ['ns1.cloudflare.com', 'ns2.cloudflare.com'],
  dnsProvider: { id: 'cloudflare', name: 'Cloudflare', confidence: 98 },
  providerContext: { provider_id: 'cloudflare', provider_name: 'Cloudflare' },
  lookupStatus: 'stale_cache',
  lookupError: 'TXT lookup timed out; showing cached DNS evidence from 2026-07-03T12:00:00Z.',
};

function json(body, status = 200) {
  return { status, contentType: 'application/json', body: JSON.stringify(body) };
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function installApiMocks(page) {
  await page.route('**/api/v1/**', async (route) => {
    const url = new URL(route.request().url());
    const path = url.pathname;
    const method = route.request().method();

    if (method === 'POST' && path === '/api/v1/domains/cklnet.com/remediation/notifications/audit') {
      await route.fulfill(
        json({
          domain: 'cklnet.com',
          item_id: 'manual-dkim-review',
          event: 'dmarq.remediation.manual_action_required',
          dedupe_key: 'dmarq:remediation:cklnet.com:manual-dkim-review',
          lifecycle_state: 'previewed',
          audit: {
            action: 'remediation.notification_lifecycle_recorded',
            details: { dns_write_attempted: false },
          },
        })
      );
      return;
    }

    const responses = {
      '/api/v1/domains/summary': domainSummary,
      '/api/v1/stats/dashboard': dashboardStats,
      '/api/v1/domains/summary/health/history': healthHistory,
      '/api/v1/reports': reports,
      '/api/v1/reports/browser-smoke-cklnet': reportDetail,
      '/api/v1/domains/cklnet.com/stats': {
        complianceRate: 92.1,
        totalEmails: 2849,
        failedEmails: 7,
        reportCount: 2,
      },
      '/api/v1/domains/cklnet.com/reports': domainReports,
      '/api/v1/domains/cklnet.com/sources': domainSources,
      '/api/v1/domains/cklnet.com/dns': dnsCached,
      '/api/v1/domains/cklnet.com/dns/health': {
        status: 'warning',
        checks: [{ name: 'DMARC', status: 'pass' }, { name: 'SPF', status: 'pass' }],
        recommendations: ['Review cached lookup warning before changing policy.'],
      },
      '/api/v1/domains/cklnet.com/dns/lint': {
        status: 'warning',
        findings: [
          {
            id: 'dkim-owned-infra',
            severity: 'warning',
            title: 'Owned infrastructure DKIM needs review',
            detail: 'The mail selector is seen in reports but should be verified in DNS.',
            next_step: 'Check mx1.cklnet.com signing and publish the selector if missing.',
          },
        ],
        target_records: [],
        dns_provider: { id: 'cloudflare', name: 'Cloudflare' },
        recommended_provider: { id: 'cloudflare', name: 'Cloudflare' },
        available_write_providers: [{ id: 'cloudflare', name: 'Cloudflare', status: 'ready' }],
        change_plans: [],
        safety_notes: [],
      },
      '/api/v1/domains/dns/providers': {
        providers: [{ id: 'cloudflare', name: 'Cloudflare', status: 'ready' }],
      },
      '/api/v1/domains/cklnet.com/ownership': {
        verified: true,
        proof_record_name: '_dmarq.cklnet.com',
        proof_record_value: 'dmarq-verify-browser-smoke',
        proof_reason: 'Cloudflare zone access verified ownership for DNS repair.',
        next_steps: ['Use one-click DNS repair only after reviewing the proposed change.'],
      },
      '/api/v1/domains/cklnet.com/posture': {
        status: 'needs_attention',
        score: 78,
        health: {
          grade: 'C',
          score: 78,
          status: 'needs attention',
          factors: {},
          actions: domainSummary.health_summary.top_actions,
        },
        summary: 'Mostly healthy, with DKIM repair needed on owned infrastructure.',
        coverage: [],
        recommendations: [],
        changes: [],
        playbooks: [],
      },
      '/api/v1/domains/cklnet.com/remediation': {
        status: 'ready',
        summary: {
          total: 1,
          approval_ready: 0,
          manual_action: 1,
          investigate: 0,
          informational: 0,
          dispatch_ready: 0,
          dispatch_blocked: 1,
          dispatch_disabled: 0,
          dispatch_awaiting_acknowledgement: 1,
          dispatch_webhook_routes: 0,
        },
        items: [
          {
            id: 'manual-dkim-review',
            title: 'Review owned infrastructure DKIM',
            detail: 'mx1.cklnet.com is passing through SPF but DKIM is not reliably aligned.',
            state: 'manual_action',
            severity: 'medium',
            source: 'source_intelligence',
            next_steps: ['Enable DKIM signing on the owned mail host.'],
            blast_radius: 'single source',
            expected_health_score_impact: '+5',
            evidence: [{ label: 'source', value: 'mx1.cklnet.com' }],
            action_plan: {
              owner: 'mail operator',
              diagnosis: 'Owned infrastructure needs DKIM signing review.',
              steps: ['Check the selector', 'Publish DKIM DNS if needed'],
              completion_criteria: 'DKIM passes on the next aggregate report.',
            },
            notification: {
              state: 'action_required',
              event: 'dmarq.remediation.manual_action_required',
              dedupe_key: 'dmarq:remediation:cklnet.com:manual-dkim-review',
              dispatch: {
                enabled: true,
                eligible: false,
                blocked_reasons: ['Record a previewed or acknowledged remediation notification audit marker.'],
                next_steps: ['Record a previewed or acknowledged remediation notification audit marker.'],
              },
              history: [],
            },
          },
        ],
      },
      '/api/v1/domains/cklnet.com/posture/history': healthHistory,
      '/api/v1/domains/cklnet.com/dns/mta-sts': {
        status: 'missing',
        dns_record: '',
        mode: 'unknown',
        max_age: null,
        mx: [],
        errors: [],
        warnings: [],
      },
      '/api/v1/domains/cklnet.com/dns/bimi': {
        status: 'present',
        selector: 'default',
        query_name: 'default._bimi.cklnet.com',
        dns_record: 'v=BIMI1; l=https://example.com/logo.svg; a=;',
        logo_url: 'https://example.com/logo.svg',
        certificate_url: '',
        errors: [],
        warnings: [],
      },
      '/api/v1/domains/cklnet.com/selectors': [{ selector: 'pm' }, { selector: 'mail' }],
      '/api/v1/forensics/analysis': { total: 0, failure_counts: {} },
      '/api/v1/poll-status': {
        is_running: true,
        enabled_sources: 1,
        source_labels: ['Gmail API: dmarc-reports@example.com'],
        latest_source_check: '2026-07-03T12:00:00Z',
      },
      '/api/v1/onboarding/preview': {
        plan: {
          tasks: [
            {
              id: 'dns-review',
              title: 'Review DNS posture',
              description: 'Check DMARC, SPF, DKIM, and ownership evidence.',
              category: 'DNS',
              href: '/domains/cklnet.com',
            },
          ],
        },
      },
      '/api/v1/onboarding/apply': {
        result: {
          tasks: [
            {
              id: 'dns-review',
              title: 'Review DNS posture',
              description: 'Check DMARC, SPF, DKIM, and ownership evidence.',
              category: 'DNS',
              href: '/domains/cklnet.com',
            },
          ],
        },
      },
    };

    if (
      path === '/api/v1/domains/summary' ||
      path === '/api/v1/reports' ||
      path === '/api/v1/domains/cklnet.com/reports' ||
      path === '/api/v1/domains/cklnet.com/sources'
    ) {
      await sleep(150);
    }

    await route.fulfill(json(responses[path] || {}));
  });
}

async function installCspViolationRecorder(page) {
  await page.addInitScript(() => {
    window.__dmarqCspViolations = [];
    document.addEventListener('securitypolicyviolation', (event) => {
      window.__dmarqCspViolations.push({
        blockedURI: event.blockedURI,
        disposition: event.disposition,
        effectiveDirective: event.effectiveDirective,
        lineNumber: event.lineNumber,
        originalPolicy: event.originalPolicy,
        sample: event.sample,
        sourceFile: event.sourceFile,
        violatedDirective: event.violatedDirective,
      });
    });
  });
}

function isKnownStrictCspMigrationBlocker(violation) {
  const sourceFile = violation.sourceFile || '';
  const blockedURI = violation.blockedURI || '';
  const effectiveDirective = violation.effectiveDirective || violation.violatedDirective || '';

  if (violation.disposition !== 'report') {
    return false;
  }

  if (sourceFile.endsWith('/static/js/vendor/alpine.min.js')) {
    return (
      (effectiveDirective === 'script-src' && blockedURI === 'eval') ||
      (effectiveDirective === 'style-src' && blockedURI === 'inline')
    );
  }

  return false;
}

test.beforeEach(async ({ page }) => {
  await installCspViolationRecorder(page);
  await installApiMocks(page);
});

test.afterEach(async ({ page }) => {
  const violations = await page.evaluate(() => window.__dmarqCspViolations || []);
  const unexpectedViolations = violations.filter(
    (violation) => !isKnownStrictCspMigrationBlocker(violation)
  );

  expect(unexpectedViolations).toEqual([]);
});

test('dashboard becomes useful before false empty states appear', async ({ page }) => {
  const started = Date.now();
  const response = await page.goto('/dashboard');
  expect(response.headers()['content-security-policy-report-only']).toContain("script-src 'self'");

  await expect(page.getByText('Fix DKIM alignment for owned infrastructure')).toBeVisible();
  await expect(page.getByText('cklnet.com').first()).toBeVisible();
  await expect(page.getByText('92.6%')).toBeVisible();

  expect(Date.now() - started).toBeLessThan(2_000);
  await expect(page.getByText('Dashboard could not be loaded')).not.toBeVisible();
  await expect(page.getByText('No reports match this filter')).not.toBeVisible();
  await expect(page.getByText('Publish DMARC')).not.toBeVisible();
});

test('domain list loads domain rows and keeps edit action wired', async ({ page }) => {
  await page.goto('/domains');

  await expect(page.getByRole('cell', { name: 'cklnet.com' })).toBeVisible();
  await expect(page.getByRole('cell', { name: 'dmarq.org' })).toBeVisible();
  await expect(page.getByText('No domains found. Add a domain to get started.')).not.toBeVisible();

  await page.getByRole('button', { name: '+ Add Domain' }).click();
  await expect(page.getByRole('heading', { name: 'Add monitored domain' })).toBeVisible();
  await expect(page.locator('[data-domain-create-dialog]')).toHaveJSProperty('open', true);
  await page.locator('[data-domain-create-close]').first().click();
  await expect(page.locator('[data-domain-create-dialog]')).toHaveJSProperty('open', false);

  await page.getByRole('button', { name: 'Edit' }).first().click();
  await expect(page.getByRole('heading', { name: 'Edit monitored domain' })).toBeVisible();
  await expect(page.locator('[data-domain-edit-dialog]')).toHaveJSProperty('open', true);
  await expect(page.getByRole('dialog').getByText('cklnet.com')).toBeVisible();
  await page.locator('[data-domain-edit-close]').first().click();
  await expect(page.locator('[data-domain-edit-dialog]')).toHaveJSProperty('open', false);
});

test('upload page keeps queue controls wired without inline handlers', async ({ page }) => {
  await page.goto('/upload');

  const fileInput = page.locator('[data-upload-file-input]');
  await fileInput.setInputFiles({
    name: 'not-a-dmarc-report.txt',
    mimeType: 'text/plain',
    buffer: Buffer.from('not xml'),
  });
  await expect(page.getByText('Invalid file type. Only XML, ZIP, or GZIP files are supported.')).toBeVisible();

  await page.getByRole('button', { name: 'Remove file' }).click();
  await expect(page.getByText('Select or drop files above to begin uploading automatically.')).toBeVisible();

  await fileInput.setInputFiles({
    name: 'report.xml',
    mimeType: 'application/xml',
    buffer: Buffer.from('<feedback></feedback>'),
  });
  await expect(page.getByText('0 records for unknown domain')).toBeVisible();

  await page.getByText('Clear all').click();
  await expect(page.getByText('Select or drop files above to begin uploading automatically.')).toBeVisible();
});

test('onboarding page keeps setup controls wired without inline handlers', async ({ page }) => {
  await page.goto('/onboarding');

  await expect(page.getByRole('heading', { name: 'Mail health setup' })).toBeVisible();
  await page.getByRole('button', { name: 'DNS only' }).click();
  await expect(page.getByText('without storing mailbox credentials')).toBeVisible();

  await page.getByRole('textbox', { name: 'Domain' }).fill('cklnet.com');
  await page.getByRole('button', { name: 'Preview tasks' }).click();
  await expect(page.getByText('Preview is ready. Review the task list before applying setup.')).toBeVisible();
  await expect(page.getByText('Review DNS posture')).toBeVisible();
});

test('domain detail shows cached DNS evidence and sender reputation context', async ({ page }) => {
  await page.goto('/domains/cklnet.com');

  await expect(page.getByRole('heading', { name: 'cklnet.com' })).toBeVisible();
  await expect(page.getByText('TXT lookup timed out; showing cached DNS evidence')).toBeVisible();
  await expect(page.getByText('v=DMARC1; p=reject; rua=mailto:dmarc@cklnet.com')).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Source Intelligence' })).toBeVisible();
  await expect(page.getByText('Postmark').first()).toBeVisible();
  await expect(page.getByText('Owned infrastructure').first()).toBeVisible();
  await expect(page.getByText('Reputation clean').first()).toBeVisible();
  await expect(page.getByText('Reputation not checked').first()).toBeVisible();
  await expect(page.getByText('Review owned infrastructure DKIM')).toBeVisible();
  await page.getByRole('button', { name: 'Reviewed' }).click();
  await expect(page.getByText('Marked previewed. No DNS changes were made.')).toBeVisible();
  await expect(page.getByText('Sending sources could not be loaded.')).not.toBeVisible();
  await expect(page.getByText('No data available for this time period')).not.toBeVisible();
});

test('reports list and aggregate detail keep source evidence actionable', async ({ page }) => {
  await page.goto('/reports');

  await expect(page.getByRole('cell', { name: 'cklnet.com' })).toBeVisible();
  await expect(page.getByText('Reports unavailable')).not.toBeVisible();
  await expect(page.getByText('No reports match this filter.')).not.toBeVisible();

  await page.getByRole('link', { name: 'View Details' }).first().click();
  await expect(page.getByRole('heading', { name: 'Report: browser-smoke-cklnet' })).toBeVisible();
  await expect(page.getByText('50.31.205.203')).toBeVisible();
  await expect(page.getByText('mta203-ab1.mtasv.net')).toBeVisible();
  await expect(page.getByText('AS23352').first()).toBeVisible();
  await expect(page.getByText('SERVERCENTRAL - DEFT.COM, US').first()).toBeVisible();
  await expect(page.getByRole('columnheader', { name: 'Reputation' })).toBeVisible();
  await expect(page.getByText('Reputation clean').first()).toBeVisible();
  await expect(page.getByText('risk 0/100').first()).toBeVisible();
  await expect(page.getByText('No blacklist listings found.').first()).toBeVisible();
  await expect(page.getByText('Reputation not checked').first()).toBeVisible();
  await expect(page.getByText('Reputation feeds are disabled.').first()).toBeVisible();
  await expect(page.getByText('DKIM did not pass for this source.')).toBeVisible();
  await expect(page.getByText('Failed to load report')).not.toBeVisible();
});
