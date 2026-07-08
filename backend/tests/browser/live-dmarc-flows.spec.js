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

const operationsHealth = {
  status: 'ok',
  database: { ok: true, detail: 'SQLite ready' },
  scheduler: {
    running: true,
    enabled_sources: 2,
    total_sources: 3,
    last_cycle_started_at: '2026-07-04T08:20:00Z',
    last_success_at: '2026-07-04T08:21:00Z',
    last_error: '',
  },
  imports: {
    latest: {
      status: 'completed',
      reports_found: 4,
      finished_at: '2026-07-04T08:22:00Z',
    },
    latest_successful: {
      status: 'completed',
      reports_found: 4,
      finished_at: '2026-07-04T08:22:00Z',
    },
  },
  reports: {
    count: 151,
    latest_processed_at: '2026-07-04T08:22:30Z',
  },
  checks: ['DNS cache refresh queue is healthy'],
  mailbox_recovery: [
    {
      category: 'gmail_backfill',
      summary: 'Gmail backfill can resume from the saved cursor.',
      recovery_steps: ['Open Mail Sources', 'Run backfill from cursor'],
    },
  ],
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

const tlsSummary = {
  totals: {
    reports: 2,
    successful_sessions: 9870,
    failed_sessions: 13,
    failure_rate: 0.0013,
  },
  trends: [
    { date: '2026-07-02', successful_sessions: 4831, failed_sessions: 7 },
    { date: '2026-07-03', successful_sessions: 5039, failed_sessions: 6 },
  ],
  top_failures: [
    {
      result_type: 'certificate-host-mismatch',
      failed_sessions: 9,
      affected_domains: ['cklnet.com'],
      receiving_mx_hostnames: ['mx1.cklnet.com'],
    },
  ],
  affected_domains: [
    {
      domain: 'cklnet.com',
      reports: 2,
      failed_sessions: 13,
      failure_rate: 0.0013,
    },
  ],
  privacy: {
    retention: 'TLS reports are retained for 365 days.',
    stored_fields: ['report metadata', 'policy domain', 'failure aggregate counts'],
    not_stored: ['message body', 'recipient local-parts'],
  },
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
          lifecycle_state: 'acknowledged',
          audit: {
            action: 'remediation.notification_lifecycle_recorded',
            details: { dns_write_attempted: false },
          },
        })
      );
      return;
    }

    if (method === 'POST' && path === '/api/v1/operator/demo/support-session') {
      await route.fulfill(
        json({
          demo_mode: true,
          session: {
            mode: 'read_only_customer_view',
            target_user: {
              name: 'Taylor Brooks',
              email: 'taylor@bakery.example',
              workspace_slug: 'bakery-example',
              domain: 'bakery.example',
            },
            audit_events: [
              {
                event_id: 'audit-demo-browser-001',
                action: 'support_access.started',
                operator_email: 'nora.ops@northstar.example',
                target_user_email: 'taylor@bakery.example',
                workspace_slug: 'bakery-example',
                domain: 'bakery.example',
                result: 'demo_session_ready',
              },
            ],
          },
          audit_event: {
            event_id: 'audit-demo-browser-001',
            action: 'support_access.started',
            operator_email: 'nora.ops@northstar.example',
            target_user_email: 'taylor@bakery.example',
            workspace_slug: 'bakery-example',
            domain: 'bakery.example',
            result: 'demo_session_ready',
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
      '/api/v1/health/operations': operationsHealth,
      '/api/v1/reports/browser-smoke-cklnet': reportDetail,
      '/api/v1/tls-reports/summary': tlsSummary,
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
            operator_decisions: ['acknowledged', 'snoozed', 'rejected'],
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
      '/api/v1/forensics': {
        reports: [
          {
            id: 'forensic-1',
            report_id: 'forensic-1',
            arrival_date: '2026-07-04T08:10:00Z',
            processed_at: '2026-07-04T08:12:00Z',
            domain: 'cklnet.com',
            reported_domain: 'cklnet.com',
            source_ip: '193.138.195.141',
            auth_failure: 'dkim',
            delivery_result: 'reject',
            original_from: 'alerts@cklnet.com',
            original_subject: 'Authentication failed',
            authentication_results: 'dkim=fail spf=pass dmarc=fail',
          },
        ],
        total: 1,
      },
      '/api/v1/forensics/analysis': {
        total: 1,
        priority_counts: { high: 1, medium: 0 },
        failure_counts: { dkim: 1 },
        result_counts: { reject: 1 },
        groups: [
          {
            key: 'cklnet.com:193.138.195.141:dkim',
            domain: 'cklnet.com',
            source_ip: '193.138.195.141',
            priority: 'high',
            diagnosis: 'DKIM failed for a source that still sends mail.',
            recommendations: ['Check selector DNS', 'Confirm signing in the mail service'],
            count: 1,
            auth_failure: 'dkim',
          },
        ],
      },
      '/api/v1/poll-status': {
        is_running: true,
        enabled_sources: 1,
        source_labels: ['Gmail API: dmarc-reports@example.com'],
        latest_source_check: '2026-07-03T12:00:00Z',
      },
      '/api/v1/auth/me': {
        email: 'operator@example.com',
        full_name: 'Demo Operator',
        username: 'operator',
        logto_id: 'auth-disabled-local',
        is_superuser: true,
        auth_disabled: true,
        auth_provider_label: 'Auth disabled',
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
      '/api/v1/operator/demo/multi-user': {
        demo_mode: true,
        deployment: {
          organizations: [
            {
              slug: 'dmarq-foundation',
              name: 'DMARQ Foundation',
              billing_mode: 'direct_stripe',
              demo_story: 'One admin manages dmarq.org and dmarq.com.',
              billing_profile: {
                invoice_owner: 'DMARQ',
                collection_model: 'self_service_subscription',
                payment_rail: 'card_on_file',
                invoice_reference: 'DMQ-BROWSER-001',
              },
              workspaces: [
                {
                  slug: 'dmarq-org',
                  name: 'dmarq.org Public Infrastructure',
                  domains: ['dmarq.org'],
                  health: 'attention',
                  primary_findings: ['newsletter DKIM selector intermittently fails'],
                },
              ],
              usage: [{ metric: 'aggregate_messages', quantity: 197430 }],
              users: [],
            },
            {
              slug: 'northstar-isp',
              name: 'Northstar ISP Demo',
              billing_mode: 'provider_resale',
              demo_story: 'Provider operators triage customer workspaces.',
              billing_profile: {
                invoice_owner: 'Northstar ISP',
                collection_model: 'provider_pass_through',
                payment_rail: 'isp_monthly_invoice',
                invoice_reference: 'NS-ISP-BROWSER',
              },
              workspaces: [
                {
                  slug: 'bakery-example',
                  name: 'Bakery Example Customer',
                  domains: ['bakery.example'],
                  health: 'healthy',
                  primary_findings: ['ready to move from quarantine to reject'],
                },
                {
                  slug: 'lawfirm-example',
                  name: 'Law Firm Example Customer',
                  domains: ['lawfirm.example'],
                  health: 'critical',
                  primary_findings: ['new mail platform sends without DKIM'],
                },
              ],
              provider_customers: [
                {
                  external_customer_id: 'ns-cust-10042',
                  workspace_slug: 'bakery-example',
                  name: 'Bakery Example Customer',
                  billing_status: 'included',
                  subscription_tier: 'DMARQ Protect',
                  monthly_charge_cents: 1900,
                  aggregate_messages: 64300,
                },
                {
                  external_customer_id: 'ns-cust-10087',
                  workspace_slug: 'lawfirm-example',
                  name: 'Law Firm Example Customer',
                  billing_status: 'billable_addon',
                  subscription_tier: 'DMARQ Protect Plus',
                  monthly_charge_cents: 3900,
                  aggregate_messages: 142700,
                },
              ],
              usage: [{ metric: 'aggregate_messages', quantity: 2423900 }],
              users: [
                {
                  name: 'Nora Patel',
                  email: 'nora.ops@northstar.example',
                  roles: ['provider_operator'],
                },
                {
                  name: 'Taylor Brooks',
                  email: 'taylor@bakery.example',
                  demo_persona: 'customer-admin',
                },
              ],
            },
          ],
          journey_steps: [
            {
              step: 1,
              label: 'Start in the daily domain view',
              zoom_level: 'workspace',
              scenario_id: 'single-user-multiple-domains',
              organization_slug: 'dmarq-foundation',
              workspace_slug: 'dmarq-org',
              domain: 'dmarq.org',
              action: 'Inspect dmarq.org and dmarq.com as one administrator.',
              expected_takeaway: 'DMARQ first explains normal domain posture.',
            },
            {
              step: 2,
              label: 'Zoom out to provider operations',
              zoom_level: 'provider',
              scenario_id: 'isp-operator',
              organization_slug: 'northstar-isp',
              workspace_slug: 'lawfirm-example',
              domain: 'lawfirm.example',
              action: 'Review ISP customers and usage export samples.',
              expected_takeaway: 'Providers can operate many customer workspaces.',
            },
            {
              step: 3,
              label: 'Impersonate a customer user',
              zoom_level: 'workspace',
              scenario_id: 'customer-admin',
              organization_slug: 'northstar-isp',
              workspace_slug: 'bakery-example',
              domain: 'bakery.example',
              action: 'Switch into a customer admin view.',
              expected_takeaway: 'Support access is explicit demo state.',
            },
          ],
          viewer_scenarios: [
            { id: 'single-user-multiple-domains', label: 'Single user, multiple domains' },
            { id: 'isp-operator', label: 'ISP operator' },
            { id: 'customer-admin', label: 'ISP customer admin' },
          ],
          zoom_levels: [
            { level: 'workspace', label: 'Single user, multiple domains' },
            { level: 'provider', label: 'ISP / managed provider view' },
          ],
          operator_playbook: [
            { id: 'domain-posture', label: 'Open owned domains', next_action: 'Start with dmarq.org.', primary_step: 1 },
            { id: 'provider-queue', label: 'Triage provider queue', next_action: 'Open the highest-risk customer first.', primary_step: 2 },
            { id: 'audited-support', label: 'Start audited support access', next_action: 'Generate the demo audit event.', primary_step: 3 },
          ],
          tenant_health_segments: [
            {
              segment: 'healthy',
              label: 'Healthy tenants',
              count: 1,
              example_workspace_slug: 'bakery-example',
              operator_action: 'Prepare reject rollout or keep weekly monitoring.',
            },
            {
              segment: 'misconfigured',
              label: 'Misconfigured tenants',
              count: 1,
              example_workspace_slug: 'lawfirm-example',
              operator_action: 'Fix DKIM and SPF lookup budget before policy enforcement.',
            },
          ],
          impersonation_policy: {
            mode: 'demo_only',
            scope: 'Support access is shown as an explicit audited demo workflow.',
          },
          support_access_demo: {
            mode: 'read_only_customer_view',
            reason: 'Customer support walkthrough',
            operator: { name: 'Nora Patel', email: 'nora.ops@northstar.example' },
            target_user: { name: 'Taylor Brooks', email: 'taylor@bakery.example' },
            audit_events: [
              {
                event_id: 'audit-demo-browser-initial',
                action: 'support_access.started',
                operator_email: 'nora.ops@northstar.example',
                target_user_email: 'taylor@bakery.example',
                domain: 'bakery.example',
              },
            ],
          },
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
  page.__dmarqCspViolations = [];
  await page.exposeFunction('__recordDmarqCspViolation', (violation) => {
    page.__dmarqCspViolations.push(violation);
  });

  await page.addInitScript(() => {
    document.addEventListener('securitypolicyviolation', (event) => {
      window.__recordDmarqCspViolation({
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

test.beforeEach(async ({ page }) => {
  await installCspViolationRecorder(page);
  await installApiMocks(page);
});

test.afterEach(async ({ page }) => {
  expect(page.__dmarqCspViolations || [], 'unexpected CSP report-only violations').toEqual([]);
});

test('dashboard becomes useful before false empty states appear', async ({ page }) => {
  const started = Date.now();
  const response = await page.goto('/dashboard');
  expect(response, 'dashboard navigation should return a response').not.toBeNull();
  const csp = response.headers()['content-security-policy'];
  expect(csp, 'dashboard should enforce strict CSP').toContain("script-src 'self'");
  expect(csp, 'dashboard CSP should not need eval').not.toContain("'unsafe-eval'");
  expect(csp, 'dashboard CSP should not need inline styles').not.toContain("'unsafe-inline'");

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

test('settings page exposes clear next actions and labeled navigation', async ({ page }) => {
  await page.goto('/settings');

  await expect(page.getByRole('heading', { name: 'Finish the next safe setup step' })).toBeVisible();
  await expect(page.getByRole('link', { name: 'Review DMARC defaults' })).toBeVisible();
  await expect(page.getByRole('link', { name: 'Connect report mailbox' })).toBeVisible();
  await expect(page.getByRole('navigation', { name: 'Settings sections' })).toContainText('DNS providers');
  await expect(page.getByRole('link', { name: 'Dashboard' }).first()).toBeVisible();
  await expect(page.getByRole('link', { name: 'Settings' }).first()).toBeVisible();
  await expect(page.locator('summary', { hasText: 'Advanced webhook delivery' })).toBeVisible();
  await expect(page.locator('summary', { hasText: 'Advanced AI and agent automation' })).toBeVisible();
  await expect(page.getByText('Save token or OAuth profile changes before discovering provider zones.')).toBeVisible();
});

test('forensic reports page renders normalized links and analysis cards', async ({ page }) => {
  await page.goto('/forensics');

  await expect(page.getByRole('heading', { name: 'Forensic Reports' })).toBeVisible();
  await expect(page.getByText('DKIM failed for a source that still sends mail.')).toBeVisible();
  await expect(page.getByText('1 samples')).toBeVisible();

  const domainLink = page.getByRole('link', { name: 'cklnet.com' }).first();
  await expect(domainLink).toHaveAttribute('href', '/domains/cklnet.com');
  await expect(page.getByRole('link', { name: 'Investigate' })).toHaveAttribute(
    'href',
    '/forensics/forensic-1'
  );
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

test('profile page renders the registered Alpine component', async ({ page }) => {
  await page.goto('/profile');

  const main = page.getByRole('main');
  await expect(page.getByRole('heading', { name: 'My Profile' })).toBeVisible();
  await expect(main.getByText('Demo Operator')).toBeVisible();
  await expect(main.getByText('operator@example.com')).toBeVisible();
  await expect(main.getByText('Username')).toBeVisible();
  await expect(main.getByText('operator', { exact: true })).toBeVisible();
  await expect(main.getByText('Auth mode')).toBeVisible();
  await expect(main.getByText('Auth disabled')).toBeVisible();
  await expect(page.getByText('Failed to load user profile')).not.toBeVisible();
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
  await expect(page.getByRole('heading', { name: 'Review owned infrastructure DKIM' }).first()).toBeVisible();
  await page.getByRole('link', { name: 'Review remediation queue' }).click();
  const acknowledgeButton = page.getByRole('button', { name: 'Acknowledge' }).first();
  await acknowledgeButton.scrollIntoViewIfNeeded();
  page.once('dialog', async (dialog) => {
    await dialog.accept('');
  });
  await acknowledgeButton.click();
  await expect(page.getByText('Marked acknowledged. No DNS changes were made.')).toBeVisible();
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

test('operations health page renders the registered Alpine component', async ({ page }) => {
  await page.goto('/operations');

  await expect(page.getByRole('heading', { name: 'System Health' })).toBeVisible();
  await expect(page.getByText('ok')).toBeVisible();
  await expect(page.getByText('Connected')).toBeVisible();
  await expect(page.getByText('2/3')).toBeVisible();
  await expect(page.getByText('151')).toBeVisible();
  await expect(page.getByText('Running')).toBeVisible();
  await expect(page.getByText('completed (4 reports)')).toHaveCount(2);
  await expect(page.getByText('DNS cache refresh queue is healthy')).toBeVisible();
  await expect(page.getByText('gmail backfill', { exact: true })).toBeVisible();
  await expect(page.getByText('Gmail backfill can resume from the saved cursor.')).toBeVisible();
});

test('tls reports page renders summary data from the registered Alpine component', async ({ page }) => {
  await page.goto('/tls-reports');

  await expect(page.getByRole('heading', { name: 'TLS Reports' })).toBeVisible();
  const successfulSessions = page.locator(
    '[x-text="formatNumber(summary.totals.successful_sessions)"]',
  );
  await expect(successfulSessions).toHaveText(
    /^9(?:[\s,.\u202f])?870$/,
  );
  await expect(page.locator('[x-text="formatNumber(summary.totals.failed_sessions)"]')).toHaveText('13');
  await expect(page.locator('[x-text="formatPercent(summary.totals.failure_rate)"]')).toHaveText('0.1%');
  await expect(page.getByText('7 failed')).toBeVisible();
  await expect(page.getByText('certificate-host-mismatch')).toBeVisible();
  await expect(page.getByText('mx1.cklnet.com')).toBeVisible();
  await expect(page.getByText('TLS reports are retained for 365 days.')).toBeVisible();

  const domainLink = page.getByRole('link', { name: 'cklnet.com' });
  await expect(domainLink).toHaveAttribute('href', '/domains/cklnet.com');
  await expect(page.getByText('No TLS report data is available for the current filters.')).not.toBeVisible();
});

test('provider demo exposes tenant, billing, and user management console', async ({ page }) => {
  const response = await page.goto('/');
  expect(response, 'provider demo navigation should return a response').not.toBeNull();
  await expect(page).toHaveURL(/\/provider-demo$/);

  await expect(page.getByRole('heading', { name: 'Mandanten & Billing verwalten' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Mandanten', exact: true })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Neuen Mandanten anlegen', exact: true })).toBeVisible();

  await page.getByRole('button', { name: 'Mandant anlegen' }).click();
  await page.getByPlaceholder('Acme GmbH').fill('Demo Kanzlei');
  await page.getByPlaceholder('acme.example').fill('kanzlei.example');
  await page.getByRole('button', { name: 'Mandant erstellen' }).click();
  await expect(page.getByRole('heading', { name: 'Demo Kanzlei' })).toBeVisible();
  await expect(page.locator('[data-provider-demo-workspace="demo-kanzlei-main"]').getByText('kanzlei.example')).toBeVisible();
  await expect(page.getByText('Mandant wurde lokal angelegt.')).toBeVisible();

  await page.reload();
  await expect(page.getByRole('heading', { name: 'Demo Kanzlei' })).toBeVisible();
  await expect(page.getByText('Lokale Demo-Aenderungen wurden wiederhergestellt.')).toBeVisible();

  await page.locator('nav [data-provider-demo-tab="billing"]').click();
  await page.getByLabel('Invoice owner').fill('Demo Provider GmbH');
  await page.getByLabel('Monatlicher Betrag').fill('499');
  await page.getByRole('button', { name: 'Billing speichern' }).click();
  await expect(page.getByText(/Gespeichert/)).toBeVisible();
  await page.locator('nav [data-provider-demo-tab="provider"]').click();
  await expect(page.getByRole('cell', { name: 'Demo Kanzlei' })).toBeVisible();
  await expect(page.getByRole('cell', { name: '499 €' })).toBeVisible();
  await page.locator('[data-provider-demo-drill-workspace][data-provider-demo-workspace="demo-kanzlei-main"]').click();
  await expect(page.getByText('Mandantenkontext aktiv:', { exact: true })).toBeVisible();
  await expect(page.getByText('Demo Kanzlei / Primary workspace')).toBeVisible();
  await expect(page.getByRole('link', { name: 'Domain-Detail oeffnen' })).toHaveAttribute(
    'href',
    '/domains/kanzlei.example?tenant=demo-kanzlei&workspace=demo-kanzlei-main'
  );
  await page.getByRole('button', { name: 'Benutzerverwaltung oeffnen' }).click();
  await expect(page.getByRole('heading', { name: 'User im Mandanten' })).toBeVisible();

  await page.locator('nav [data-provider-demo-tab="users"]').click();
  const userForm = page.locator('[data-provider-demo-user-form]');
  await userForm.getByLabel('Name', { exact: true }).fill('Mara Admin');
  await userForm.getByLabel('E-Mail', { exact: true }).fill('mara@kanzlei.example');
  await userForm.getByRole('button', { name: 'User hinzufuegen' }).click();
  await expect(page.getByText('mara@kanzlei.example')).toBeVisible();
  await userForm.getByLabel('Name', { exact: true }).fill('Mara Duplicate');
  await userForm.getByLabel('E-Mail', { exact: true }).fill('mara@kanzlei.example');
  await userForm.getByRole('button', { name: 'User hinzufuegen' }).click();
  await expect(page.getByText('Diese E-Mail existiert bereits in diesem Mandanten.')).toBeVisible();

  await page.getByRole('button', { name: 'Support-View oeffnen' }).click();
  await expect(page.getByText('Support-View bereit')).toBeVisible();
  await expect(page.getByText('demo_session_ready')).toBeVisible();
});
