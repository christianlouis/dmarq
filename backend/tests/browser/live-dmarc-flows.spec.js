const { test, expect } = require('@playwright/test');
const realProviderBackend = process.env.DMARQ_PROVIDER_REAL_BROWSER === 'true';
const productProviderBackend = process.env.DMARQ_PROVIDER_PRODUCT_BROWSER === 'true';

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

const reportIntakeRecommendation = {
  schema: 'dmarq.report_intake_recommendation.v1',
  generated_from: 'persisted_state_and_operator_preferences',
  primary_action: {label: 'Connect IMAP', href: '/mail-sources?method=IMAP'},
  recommended: {
    id: 'local_imap',
    title: 'Your own report mailbox over IMAP',
    summary: 'DMARQ reads a dedicated mailbox in an environment you control.',
    flow: ['Report sender', 'Your mailbox', 'IMAP', 'DMARQ'],
    processors: ['Your mail provider or server', 'Your DMARQ instance'],
    public_exposure: 'No public DMARQ URL is required.',
    credentials: 'Mailbox user and password; scope access to the report mailbox.',
    complexity: 'medium',
    test_method: 'Test the connection, trigger one poll, and inspect import status.',
    action_label: 'Connect IMAP',
    href: '/mail-sources?method=IMAP',
    confidence: 'medium',
    reason: 'This path best matches your data-path preference and detected state.',
    already_configured: false,
  },
  alternatives: [
    {
      id: 'cloudflare_worker',
      title: 'Cloudflare Email Routing and Worker',
      tradeoff: 'No mailbox polling, but public HTTPS reachability is required.',
      available: false,
      availability_reason: 'A public HTTPS DMARQ URL is required before this path can be tested.',
      action_label: 'Open Worker how-to',
      href: '/docs/cloudflare-worker',
    },
    {
      id: 'manual_upload',
      title: 'Upload an existing report',
      tradeoff: 'Very simple, but unsuitable for unattended monitoring.',
      available: true,
      availability_reason: null,
      action_label: 'Upload report',
      href: '/upload',
    },
  ],
  first_report: {
    state: 'setup_required',
    headline: 'Choose a report-intake path',
    description: 'No continuous report source is enabled yet.',
    latest_import: {status: null, accepted: 0, duplicates: 0, rejected: 0},
  },
  verification: [
    {id: 'component_test', label: 'Test the connection and inspect import status.', complete: false},
    {id: 'first_report', label: 'DMARQ accepts or safely deduplicates the first aggregate report.', complete: false},
  ],
  journey: [
    {
      id: 'journey_1',
      position: 1,
      title: 'Choose a report destination',
      description: 'Choose a dedicated destination address for aggregate reports.',
      complete: false,
      href: '/domains/cklnet.com#dns-records',
    },
    {
      id: 'journey_8',
      position: 8,
      title: 'Open the first interpretation',
      description: 'Finish setup in the explanation, not on a raw import row.',
      complete: false,
      href: '/reports',
    },
  ],
  preferences: {
    selected_option: 'not_sure',
    setup_effort: 'balanced',
    continuous_monitoring: false,
    local_bridge_available: false,
  },
  public_endpoint: {https_ready: false, webhook_configured: false},
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
      dmarc: 'pass',
      dmarc_result: 'pass',
      spf: 'pass',
      spf_result: 'pass',
      dkim: 'fail',
      dkim_result: 'fail',
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
      volume_history: [{ date: '2026-07-02', count: 137, passed: 137, failed: 0 }],
    },
  ],
  mailflow_assessment: {
    domain: 'cklnet.com',
    status: 'action_required',
    title: 'Repair DKIM signing for an active mailflow',
    summary: 'DMARQ observed one active path for cklnet.com without reliable aligned DKIM.',
    next_step: 'Confirm DKIM signing for this domain in the sending service',
    cta_label: 'Review DKIM repair',
    cta_href: '#mailflow-diagnosis',
    confidence: 'High',
    evidence_scope: 'Aggregate DMARC reports prove receiver authentication observations, not final delivery.',
    known_facts: ['2 active source paths were observed in the selected window.'],
    inferences: ['The owned path passes through SPF but has no aligned DKIM pass.'],
    unknowns: ['The exact provider-side root cause remains unknown without provider evidence.'],
    repair_steps: [
      'Confirm DKIM signing is enabled for cklnet.com in the sending service.',
      'Publish the exact selector record supplied by the sender.',
      'Send or forward one controlled message.',
    ],
    verification_condition: 'A fresh aggregate report shows aligned DKIM passing on the affected path.',
    primary_source_ip: '2a01:4f8:c17:311b::1',
    counts: { healthy: 1, aligned_dkim_not_observed: 1 },
    flows: [
      {
        source_ip: '50.31.205.203',
        sender_name: 'Postmark',
        sender_status: 'known',
        status: 'healthy',
        label: 'Aligned DKIM observed',
        detail: 'Receivers reported aligned DKIM for 2736 messages.',
        message_count: 2736,
        header_from_domains: ['cklnet.com'],
        envelope_from_domains: ['pm.mtasv.net'],
        spf_domains: ['pm.mtasv.net'],
        dkim_domains: ['cklnet.com'],
        dkim_selectors: ['pm'],
        spf_alignment: 'pass',
        dkim_alignment: 'pass',
        dmarc_status: 'pass',
        receiver_disposition: 'none',
        intended_mail_impact: 'likely_not_affected',
        evidence_level: 'observed',
        provider_evidence_status: 'not_connected',
        next_step: 'Keep report intake running',
        verification_condition: 'Keep receiving aligned DKIM passes.',
      },
      {
        source_ip: '2a01:4f8:c17:311b::1',
        sender_name: 'Owned infrastructure',
        sender_status: 'known',
        status: 'aligned_dkim_not_observed',
        label: 'Aligned DKIM not observed',
        detail: 'Receivers evaluated 137 messages without aligned DKIM.',
        message_count: 137,
        header_from_domains: ['cklnet.com'],
        envelope_from_domains: ['cklnet.com'],
        spf_domains: ['cklnet.com'],
        dkim_domains: ['cklnet.com'],
        dkim_selectors: ['mail'],
        spf_alignment: 'pass',
        dkim_alignment: 'not_observed',
        dmarc_status: 'pass',
        receiver_disposition: 'none',
        intended_mail_impact: 'fragile',
        evidence_level: 'observed',
        provider_evidence_status: 'not_connected',
        next_step: 'Confirm DKIM signing for this domain in the sending service',
        verification_condition: 'A fresh aggregate report shows aligned DKIM passing.',
      },
    ],
  },
};

const domainSourceIntelligence = {
  domain: 'cklnet.com',
  period_days: 30,
  recent_days: 14,
  regions: [
    {
      region: 'Europe',
      country_codes: ['DE'],
      source_count: 1,
      message_count: 137,
      failure_rate: 5.1,
    },
  ],
  anomalies: [],
  summary: { sources: 2, anomalies: 0 },
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

function providerAccount({ slug, name, customerNumber, health, planCode, planLabel, domain, messages, compliance, billingStatus, userName, userEmail }) {
  return {
    id: `acct-${slug}`,
    slug,
    customer_number: customerNumber,
    name,
    short_name: name,
    status: 'active',
    health,
    plan_code: planCode,
    plan_label: planLabel,
    created_at: '2026-01-10T09:00:00Z',
    last_activity_at: '2026-07-09T08:00:00Z',
    primary_contact: { name: userName, email: userEmail, phone: '+49 30 555 0100' },
    billing: {
      status: billingStatus,
      invoice_owner: 'Northstar ISP',
      billing_contact: `billing@${domain}`,
      collection_model: 'provider_pass_through',
      payment_rail: 'isp_monthly_invoice',
      invoice_reference: customerNumber,
      monthly_charge_cents: planCode === 'protect_plus' ? 7900 : 1900,
      next_invoice_at: '2026-07-21',
    },
    usage: {
      messages_30d: messages,
      reports_30d: 92,
      compliance_rate: compliance,
      change_percent: 4.2,
    },
    entitlements: {
      domains: { used: 1, included: planCode === 'protect_plus' ? 50 : 5 },
      users: { used: 2, included: planCode === 'protect_plus' ? 100 : 10 },
      messages: { used: messages, included: planCode === 'protect_plus' ? 10000000 : 500000 },
      retention_days: { used: 90, included: planCode === 'protect_plus' ? 400 : 90 },
    },
    onboarding: {
      completed_steps: 5,
      total_steps: 5,
      next_step: health === 'critical' ? 'DKIM aktivieren und SPF-Lookups reduzieren.' : 'Reject-Rollout planen.',
    },
    recommended_action: health === 'critical'
      ? 'DKIM-Ausfall beheben, bevor die Policy verschärft wird.'
      : 'DMARC von quarantine auf reject anheben.',
    domains: [
      {
        name: domain,
        health,
        policy: 'quarantine',
        compliance_rate: compliance,
        messages_30d: messages,
        reports_30d: 92,
        source_count: 7,
        spf_alignment: compliance + 0.5,
        dkim_alignment: compliance - 0.5,
        last_report_at: '2026-07-09T07:40:00Z',
        open_findings: [health === 'critical' ? 'Neue Quelle sendet ohne DKIM.' : 'Policy ist bereit für reject.'],
      },
    ],
    users: [
      {
        id: `usr-${slug}-admin`,
        name: userName,
        email: userEmail,
        role: 'workspace_admin',
        status: 'active',
        last_active_at: '2026-07-09T07:32:00Z',
        mfa_enabled: true,
        can_impersonate: true,
      },
      {
        id: `usr-${slug}-audit`,
        name: 'Audit User',
        email: `audit@${domain}`,
        role: 'auditor',
        status: 'active',
        last_active_at: '2026-07-04T09:10:00Z',
        mfa_enabled: false,
        can_impersonate: false,
      },
    ],
    reports: [
      {
        id: `${slug}-google-2026-07-09`,
        provider: 'Google',
        domain,
        period_start: '2026-07-08',
        period_end: '2026-07-09',
        received_at: '2026-07-09T08:45:00Z',
        messages: Math.round(messages / 4),
        pass_rate: compliance,
        status: 'processed',
      },
      {
        id: `${slug}-microsoft-2026-07-08`,
        provider: 'Microsoft',
        domain,
        period_start: '2026-07-07',
        period_end: '2026-07-08',
        received_at: '2026-07-08T08:45:00Z',
        messages: Math.round(messages / 5),
        pass_rate: compliance,
        status: 'processed',
      },
    ],
    activity: [
      {
        id: `${slug}-report`,
        occurred_at: '2026-07-09T08:45:00Z',
        actor: 'DMARQ Import',
        action: 'report.imported',
        summary: 'Aktuelle Aggregate-Reports verarbeitet.',
      },
    ],
    settings: {
      report_mailbox: `dmarc@${domain}`,
      timezone: 'Europe/Berlin',
      weekly_digest: true,
      ai_redaction: 'strict',
    },
  };
}

const providerConsole = {
  source: 'demo_provider_accounts_v2',
  generated_for: '2026-07-09',
  provider: {
    id: 'provider-northstar',
    slug: 'northstar-isp',
    name: 'Northstar ISP',
    operator: { name: 'Sofia Weber', email: 'sofia.ops@northstar.example', role: 'site_manager' },
  },
  summary: {},
  plans: [
    { code: 'monitor', label: 'DMARQ Monitor', monthly_charge_cents: 1900, domains: 5, users: 10, messages: 500000, retention_days: 90 },
    { code: 'protect', label: 'DMARQ Protect', monthly_charge_cents: 3900, domains: 15, users: 25, messages: 2000000, retention_days: 180 },
    { code: 'protect_plus', label: 'DMARQ Protect Plus', monthly_charge_cents: 7900, domains: 50, users: 100, messages: 10000000, retention_days: 400 },
  ],
  accounts: [
    providerAccount({ slug: 'bakery-example', name: 'Bäckerei Morgenrot GmbH', customerNumber: 'NS-10042', health: 'healthy', planCode: 'monitor', planLabel: 'DMARQ Monitor', domain: 'bakery.example', messages: 64300, compliance: 98.7, billingStatus: 'current', userName: 'Taylor Brooks', userEmail: 'taylor@bakery.example' }),
    providerAccount({ slug: 'lawfirm-example', name: 'Kanzlei Hansen & Partner', customerNumber: 'NS-10087', health: 'critical', planCode: 'protect_plus', planLabel: 'DMARQ Protect Plus', domain: 'lawfirm.example', messages: 142700, compliance: 71.4, billingStatus: 'current', userName: 'Dr. Lena Hansen', userEmail: 'admin@lawfirm.example' }),
  ],
  support_access_demo: {
    mode: 'read_only_customer_view',
    operator: { name: 'Sofia Weber', email: 'sofia.ops@northstar.example', role: 'site_manager' },
    reason: 'Kundensupport und Konfigurationsprüfung',
    safeguards: [
      'Zeitlich begrenzte Demo-Sitzung',
      'Operator, Zielbenutzer und Grund werden protokolliert',
      'Kundenansicht ist schreibgeschützt',
      'DNS- und Provider-Schreibzugriffe bleiben deaktiviert',
    ],
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
      const requestBody = route.request().postDataJSON();
      const account = providerConsole.accounts.find((item) => item.slug === requestBody.account_slug) || providerConsole.accounts[0];
      const targetUser = account.users.find((user) => user.email === requestBody.target_user_email) || account.users[0];
      const auditEvent = {
        event_id: 'audit-demo-browser-001',
        action: 'support_access.started',
        occurred_at: '2026-07-09T09:45:00Z',
        operator_email: 'sofia.ops@northstar.example',
        target_user_email: targetUser.email,
        target_user_name: targetUser.name,
        target_role: targetUser.role,
        account_slug: account.slug,
        workspace_slug: account.slug,
        domain: account.domains[0].name,
        reason: requestBody.reason,
        result: 'demo_session_ready',
      };
      await route.fulfill(
        json({
          demo_mode: true,
          session: {
            mode: 'read_only_customer_view',
            account: { slug: account.slug, name: account.name, customer_number: account.customer_number },
            target_user: { ...targetUser, workspace_slug: account.slug, domain: account.domains[0].name },
            audit_events: [auditEvent],
          },
          audit_event: auditEvent,
        })
      );
      return;
    }

    if (method === 'POST' && path === '/api/v1/domains/cklnet.com/dns/change-plan/apply') {
      const requestBody = route.request().postDataJSON();
      await sleep(150);
      await route.fulfill(
        json({
          plan_id: requestBody.plan_id,
          provider: requestBody.provider,
          dry_run: true,
          applied: false,
          mutation: {
            operation: 'create',
            record_type: 'TXT',
            name: '_dmarc.cklnet.com',
            content: 'v=DMARC1; p=none; rua=mailto:dmarc@cklnet.com',
            ttl: 300,
            provider: requestBody.provider,
            zone_id: 'zone-browser-smoke',
            zone_name: 'cklnet.com',
            current_values: [],
            applicable: true,
          },
          verification: { status: 'not_run', verified: false, message: '' },
          rollback: { summary: 'Delete the created record.', steps: [] },
          changes: [{ type: 'demo_preview', message: 'Preview ready.' }],
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
      '/api/v1/domains/cklnet.com/source-intelligence': domainSourceIntelligence,
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
        change_plans: [{
          plan_id: 'dmarc-missing-cklnet-com-txt',
          finding_code: 'dmarc_missing',
          severity: 'error',
          operation: 'create',
          record_type: 'TXT',
          name: '_dmarc.cklnet.com',
          proposed_value: 'v=DMARC1; p=none; rua=mailto:dmarc@cklnet.com',
          current_values: [],
          rationale: 'Publish a DMARC TXT record in monitoring mode.',
          risk: 'Low delivery risk when starting with p=none.',
          rollback: 'Delete the newly created TXT record.',
          expected_health_impact: 'Expected to improve DNS health.',
          manual_steps: ['Publish the planned TXT record.'],
          provider_write_available: true,
          provider_value_required: false,
          changes: ['Create this record; no current value was observed.'],
          safety_notes: ['Preview the provider mutation before applying this DNS change.'],
        }],
        safety_notes: [],
      },
      '/api/v1/domains/dns/providers': {
        providers: [{ id: 'cloudflare', name: 'Cloudflare', status: 'ready', credentials_configured: true }],
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
      '/api/v1/workspaces/guidance': {
        available: true,
        enabled: false,
        requested_enabled: false,
        depth: 'standard',
        context: 'watch',
        teaching_hints_enabled: false,
        preference_scope: 'workspace',
        profile_version: 1,
        goal: null,
        installation_goals: [],
        sovereignty_preference: 'not_sure',
        mail_context: {dns_provider: 'Cloudflare'},
        notification_posture: 'actionable_only',
        interview_version: 1,
        interview_completed: false,
      },
      '/api/v1/workspaces/guidance/preferences': {
        depth: 'guided',
        context: 'diagnose',
        teaching_hints_enabled: true,
        preference_scope: 'workspace',
        profile_version: 1,
      },
      '/api/v1/workspaces/guidance/workspace-profile': {
        installation_goals: ['understand_reports'],
        sovereignty_preference: 'privacy_first',
        notification_posture: 'actionable_only',
        mail_context: {dns_provider: 'Cloudflare'},
        interview_version: 1,
        interview_completed: true,
        profile_version: 1,
      },
      '/api/v1/workspaces/guidance/diagnostic-plan': {
        schema: 'dmarq.diagnostic_plan.v1',
        plan_version: 1,
        generated_from: 'persisted_evidence',
        primary_goal: 'learn_or_explore',
        domain: 'cklnet.com',
        conclusion: {
          code: 'monitoring_ready',
          title: 'Monitoring is ready',
          summary: 'DMARQ has persisted evidence for cklnet.com.',
        },
        current_action: {
          id: 'open_domain',
          title: 'Monitoring is ready',
          description: 'DMARQ has persisted evidence for cklnet.com.',
          label: 'Open domain overview',
          href: '/domains/cklnet.com',
          why: 'The next useful work comes from changes in stored evidence.',
          verification: 'New reports continue arriving.',
          blocked_by: [],
        },
        later_steps: [
          {id: 'classify_senders', title: 'Classify intended sending services', href: '/domains/cklnet.com#sending-sources'},
        ],
        known_facts: ['1 monitored domain is stored.'],
        inferences: [],
        unknowns: [],
        evidence: {
          domain_count: 1,
          report_count: 4,
          message_count: 100,
          failed_message_count: 0,
          enabled_source_count: 1,
          checked_source_count: 1,
          dns_evidence_available: true,
          dns_provider_connected: true,
        },
        interview_completed: false,
        interview_step: 1,
      },
      '/api/v1/workspaces/guidance/report-intake-recommendation': reportIntakeRecommendation,
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
    responses['/api/v1/domains/cklnet.com/detail/cached'] = {
      dns: responses['/api/v1/domains/cklnet.com/dns'],
      dns_health: responses['/api/v1/domains/cklnet.com/dns/health'],
      dns_guidance: responses['/api/v1/domains/cklnet.com/dns/lint'],
      posture: responses['/api/v1/domains/cklnet.com/posture'],
    };
    responses['/api/v1/operator/demo/provider-console'] = {
      demo_mode: true,
      provider_console: providerConsole,
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
  if (!realProviderBackend && !productProviderBackend) await installApiMocks(page);
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
  expect(Date.now() - started).toBeLessThan(2_000);

  const analytics = page.locator('details', {
    has: page.locator('summary', { hasText: 'Analytics and evidence' }),
  });
  await analytics.locator(':scope > summary').click();
  await expect(analytics.getByText('92.6%')).toBeVisible();

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
  await expect(page.getByRole('link', { name: 'Connect report mailbox' })).toBeVisible();
  await expect(page.getByRole('link', { name: 'Add or review domains' })).toBeVisible();
  const settingsNavigation = page.getByLabel('Settings navigation');
  await expect(settingsNavigation).toContainText('DMARC defaults');
  await expect(settingsNavigation).toContainText('Domains and DNS');
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
  await expect(page.getByRole('heading', { name: 'How DMARQ explains findings' })).toBeVisible();
  await expect(page.getByRole('radio', { name: /Guide me/ })).toHaveAttribute('aria-checked', 'true');
  await expect(page.getByRole('radio', { name: 'Diagnose' })).toHaveAttribute('aria-checked', 'true');
  await expect(page.getByText('Failed to load user profile')).not.toBeVisible();
});

test('profile preferences save independently and remain usable on mobile', async ({ page }) => {
  let savedPreference = null;
  await page.route('**/api/v1/workspaces/guidance/preferences', async (route) => {
    if (route.request().method() !== 'PUT') return route.fallback();
    savedPreference = route.request().postDataJSON();
    await route.fulfill(json({...savedPreference, preference_scope: 'workspace', profile_version: 1}));
  });

  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto('/profile');
  await page.getByRole('radio', { name: /Show full technical detail/i }).click();
  await page.getByRole('radio', { name: 'Evidence', exact: true }).click();
  await page.getByRole('checkbox', { name: /Explain unfamiliar terms/ }).uncheck();
  await page.getByRole('button', { name: 'Save explanation preferences' }).click();

  await expect(page.getByText('Your explanation preferences are saved.')).toBeVisible();
  expect(savedPreference).toEqual({
    depth: 'expert',
    context: 'evidence',
    teaching_hints_enabled: false,
  });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1)).toBe(true);
});

test('authenticated users save a personal view without changing workspace context', async ({ page }) => {
  let savedPreference = null;
  await page.route('**/api/v1/auth/me', async (route) => {
    await route.fulfill(json({
      email: 'analyst@example.com',
      full_name: 'Workspace Analyst',
      username: 'analyst',
      logto_id: 'logto-analyst',
      is_superuser: false,
      auth_disabled: false,
      auth_provider_label: 'Logto',
    }));
  });
  await page.route('**/api/v1/workspaces/guidance/preferences', async (route) => {
    if (route.request().method() !== 'PUT') return route.fallback();
    savedPreference = route.request().postDataJSON();
    await route.fulfill(json({...savedPreference, preference_scope: 'user', profile_version: 1}));
  });

  await page.goto('/profile');
  const main = page.getByRole('main');
  await expect(main.getByText('Workspace Analyst')).toBeVisible();
  await expect(main.getByText('Logto', { exact: true })).toBeVisible();
  await page.getByRole('radio', { name: /Balanced/ }).click();
  await page.getByRole('radio', { name: 'Watch', exact: true }).click();
  await page.getByRole('button', { name: 'Save explanation preferences' }).click();

  await expect(page.getByText('Your explanation preferences are saved.')).toBeVisible();
  expect(savedPreference).toEqual({
    depth: 'standard',
    context: 'watch',
    teaching_hints_enabled: true,
  });
});

test('onboarding page keeps setup controls wired without inline handlers', async ({ page }) => {
  await page.goto('/onboarding');

  await expect(page.getByRole('heading', { name: 'Mail health setup' })).toBeVisible();
  await page.getByRole('button', { name: 'Reconfigure setup' }).click();
  await page.getByRole('button', { name: 'DNS only' }).click();
  await expect(page.getByText('without storing mailbox credentials')).toBeVisible();

  await page.getByRole('textbox', { name: 'Domain' }).fill('cklnet.com');
  await page.getByRole('button', { name: 'Preview tasks' }).click();
  await expect(page.getByText('Preview is ready. Review the task list before applying setup.')).toBeVisible();
  await expect(page.getByText('Review DNS posture')).toBeVisible();
});

test('onboarding persists the problem-first goal without losing existing mail context', async ({ page }) => {
  let savedPreference = null;
  let savedWorkspaceProfile = null;
  await page.route('**/api/v1/workspaces/guidance/preferences', async (route) => {
    if (route.request().method() !== 'PUT') return route.fallback();
    savedPreference = route.request().postDataJSON();
    await route.fulfill(json({...savedPreference, preference_scope: 'workspace', profile_version: 1}));
  });
  await page.route('**/api/v1/workspaces/guidance/workspace-profile', async (route) => {
    if (route.request().method() !== 'PUT') return route.fallback();
    savedWorkspaceProfile = route.request().postDataJSON();
    await route.fulfill(json({...savedWorkspaceProfile, profile_version: 1}));
  });
  await page.route('**/api/v1/domains/summary**', async (route) => {
    await route.fulfill(json({total_domains: 0, reports_processed: 0}));
  });
  await page.route('**/api/v1/mail-sources', async (route) => {
    await route.fulfill(json([]));
  });
  await page.route('**/api/v1/workspaces/guidance/diagnostic-plan', async (route) => {
    await route.fulfill(json({
      current_action: {
        id: 'explain_report',
        title: 'Open the newest report explanation',
        description: 'Start with one stored report.',
        label: 'Explain the newest report',
        href: '/reports',
        why: 'One bounded report is easier to understand.',
        verification: 'Intended and unrelated sources are distinguishable.',
      },
      later_steps: [],
      known_facts: ['No report has been stored yet.'],
      inferences: ['A report explains authentication, not individual delivery.'],
      unknowns: [],
    }));
  });

  await page.goto('/onboarding');
  await page.getByRole('button', { name: /I received DMARC reports/ }).click();
  await page.getByText('Also relevant to me').click();
  await page.getByRole('checkbox', {name: /Someone may be using my domain/}).check();
  await page.getByRole('button', { name: 'Continue' }).click();
  await page.locator('section[aria-labelledby="install-goal-heading"] input[placeholder="example.com"]').fill('mail.example');
  await page.getByRole('group', {name: 'Can you change DNS for this domain?'}).getByRole('radio', {name: 'Yes'}).check();
  await page.getByRole('button', { name: 'Continue' }).click();
  await page.getByRole('group', {name: 'Does this domain intentionally send email?'}).getByRole('radio', {name: 'Yes'}).check();
  await page.getByRole('button', { name: 'Continue' }).click();
  await page.getByLabel('Explanation detail').selectOption('expert');
  await page.getByLabel('Report data preference').selectOption('privacy_first');
  await page.getByRole('button', { name: 'Show my next step' }).click();

  await expect(page.getByRole('heading', { name: 'Open the newest report explanation' })).toBeVisible();
  await page.getByText('Why DMARQ chose this step').click();
  await expect(page.getByText('A report explains authentication, not individual delivery.')).toBeVisible();
  expect(savedPreference).toEqual({
    depth: 'expert',
    context: 'watch',
    teaching_hints_enabled: false,
  });
  expect(savedWorkspaceProfile).toEqual({
    installation_goals: ['understand_reports', 'protect_against_spoofing'],
    sovereignty_preference: 'privacy_first',
    notification_posture: 'actionable_only',
    mail_context: {
      dns_provider: 'Cloudflare',
      interview_step: 4,
      domains: ['mail.example'],
      controls_dns: true,
      domain_sends_mail: true,
      bounce_available: false,
      low_volume: false,
      report_intake_preference: 'not_sure',
      setup_effort: 'balanced',
      continuous_monitoring: false,
      local_bridge_available: false,
    },
    interview_version: 1,
    interview_completed: true,
  });
});

test('onboarding preserves valid specialist goals when preferences change', async ({ page }) => {
  let savedWorkspaceProfile = null;
  await page.route('**/api/v1/workspaces/guidance', async (route) => {
    await route.fulfill(json({
      available: true,
      enabled: false,
      depth: 'standard',
      context: 'watch',
      goal: 'investigate_bounces',
      installation_goals: ['investigate_bounces'],
      sovereignty_preference: 'not_sure',
      notification_posture: 'actionable_only',
      mail_context: {dns_provider: 'Cloudflare'},
      interview_completed: false,
    }));
  });
  await page.route('**/api/v1/workspaces/guidance/workspace-profile', async (route) => {
    if (route.request().method() !== 'PUT') return route.fallback();
    savedWorkspaceProfile = route.request().postDataJSON();
    await route.fulfill(json({...savedWorkspaceProfile, profile_version: 1}));
  });
  await page.route('**/api/v1/domains/summary**', async (route) => {
    await route.fulfill(json({total_domains: 0, reports_processed: 0}));
  });
  await page.route('**/api/v1/mail-sources', async (route) => {
    await route.fulfill(json([]));
  });

  await page.goto('/onboarding');
  await expect(page.getByRole('button', { name: /Messages are being rejected or bounced/ })).toBeVisible();
  await page.getByRole('button', { name: /Messages are being rejected or bounced/ }).click();
  await expect.poll(() => savedWorkspaceProfile?.installation_goals).toEqual(['investigate_bounces']);
  await page.getByRole('button', { name: 'Continue' }).click();
  await page.getByRole('button', { name: 'Continue' }).click();
  await page.getByRole('button', { name: 'Continue' }).click();
  await page.getByLabel('Report data preference').selectOption('balanced');

  await expect.poll(() => savedWorkspaceProfile?.sovereignty_preference).toBe('balanced');
});

test('guided onboarding keeps the primary action visible on mobile and resumes progress', async ({ page }) => {
  await page.route('**/api/v1/domains/summary**', async (route) => {
    await route.fulfill(json({total_domains: 0, reports_processed: 0}));
  });
  await page.route('**/api/v1/mail-sources', async (route) => {
    await route.fulfill(json([]));
  });
  await page.route('**/api/v1/workspaces/guidance/workspace-profile', async (route) => {
    if (route.request().method() !== 'PUT') return route.fallback();
    const profile = route.request().postDataJSON();
    await route.fulfill(json({...profile, profile_version: 1}));
  });
  await page.setViewportSize({width: 390, height: 844});

  await page.goto('/onboarding');
  await page.getByRole('button', {name: /I want to keep mail delivery healthy/}).click();
  await page.getByRole('button', {name: 'Continue'}).click();

  await expect(page.getByRole('heading', {name: 'Which domain is affected?'})).toBeVisible();
  await expect(page.getByRole('button', {name: 'Continue'})).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1)).toBe(true);
});

test('guided onboarding presents the problem-first path in German', async ({page, context, baseURL}) => {
  await context.addCookies([{
    name: 'dmarq_locale',
    value: 'de',
    url: baseURL,
  }]);
  await page.route('**/api/v1/workspaces/guidance', async (route) => {
    await route.fulfill(json({
      available: true,
      enabled: false,
      depth: 'guided',
      context: 'watch',
      installation_goals: [],
      sovereignty_preference: 'not_sure',
      notification_posture: 'actionable_only',
      mail_context: {},
      interview_completed: false,
    }));
  });
  await page.route('**/api/v1/domains/summary**', async (route) => {
    await route.fulfill(json({total_domains: 0, reports_processed: 0}));
  });
  await page.route('**/api/v1/mail-sources', async (route) => {
    await route.fulfill(json([]));
  });
  await page.route('**/api/v1/workspaces/guidance/workspace-profile', async (route) => {
    if (route.request().method() !== 'PUT') return route.fallback();
    const profile = route.request().postDataJSON();
    await route.fulfill(json({...profile, profile_version: 1}));
  });

  await page.goto('/onboarding');
  await expect(page.getByRole('heading', {name: 'Was hat dich zu DMARQ gebracht?'})).toBeVisible();
  await page.getByRole('button', {name: /Ich möchte meine Mailzustellung dauerhaft gesund halten/}).click();
  await page.getByRole('button', {name: 'Weiter'}).click();
  await expect(page.getByRole('heading', {name: 'Welche Domain ist betroffen?'})).toBeVisible();
  await expect(page.getByRole('button', {name: 'Weiter'})).toBeVisible();
});

test('guided onboarding exposes a recoverable diagnostic plan error', async ({ page }) => {
  let attempts = 0;
  await page.route('**/api/v1/workspaces/guidance/diagnostic-plan', async (route) => {
    attempts += 1;
    if (attempts === 1) {
      await route.fulfill(json({detail: 'Stored evidence is temporarily unavailable.'}, 503));
      return;
    }
    await route.fulfill(json({
      current_action: {
        id: 'open_domain',
        title: 'Monitoring is ready',
        description: 'Stored evidence is ready.',
        label: 'Open domain overview',
        href: '/domains/cklnet.com',
        why: 'Reports are arriving.',
        verification: 'New reports continue arriving.',
        blocked_by: [],
      },
      later_steps: [],
      known_facts: ['Reports are stored.'],
      inferences: [],
      unknowns: [],
    }));
  });

  await page.goto('/onboarding');
  await expect(page.getByText('Your next step could not be loaded')).toBeVisible();
  await page.getByRole('button', {name: 'Try again'}).click();
  await expect(page.getByRole('heading', {name: 'Monitoring is ready'})).toBeVisible();
});

test('guided onboarding shows one intake recommendation and keeps alternatives progressive', async ({page}) => {
  await page.goto('/onboarding');

  await expect(page.getByRole('heading', {name: 'Your own report mailbox over IMAP'})).toBeVisible();
  await expect(page.getByRole('link', {name: 'Connect IMAP'})).toBeVisible();
  await expect(page.getByText('Choose a report-intake path')).toBeVisible();
  await expect(page.getByText('Cloudflare Email Routing and Worker')).toBeHidden();

  await page.getByText('Data path and requirements').click();
  await expect(page.getByText(/Failure or forensic reports can contain message-specific metadata/)).toBeVisible();
  await page.getByText('Adjust recommendation').click();
  await expect(page.getByRole('combobox', {name: 'Preferred path'})).toBeDisabled();

  await page.getByText('Compare alternatives').click();
  await expect(page.getByText('Cloudflare Email Routing and Worker')).toBeVisible();
  await expect(page.getByText('A public HTTPS DMARQ URL is required before this path can be tested.')).toBeVisible();
  await expect(page.getByRole('link', {name: 'Upload report'})).toBeVisible();
  await page.getByText('Complete first-report journey').click();
  await expect(page.getByText('Choose a report destination')).toBeVisible();
  await expect(page.getByText('Open the first interpretation')).toBeVisible();
});

test('guided onboarding renders a persisted German Proton Bridge recommendation', async ({page, context, baseURL}) => {
  await context.addCookies([{name: 'dmarq_locale', value: 'de', url: baseURL}]);
  await page.route('**/api/v1/workspaces/guidance/report-intake-recommendation', async (route) => {
    await route.fulfill(json({
      ...reportIntakeRecommendation,
      primary_action: {label: 'Bridge-IMAP verbinden', href: '/mail-sources?method=IMAP&bridge=proton'},
      recommended: {
        ...reportIntakeRecommendation.recommended,
        id: 'proton_bridge',
        title: 'Proton Mail über lokale Bridge',
        summary: 'Eine Proton-Mailbox wird über Proton Mail Bridge lokal für DMARQ erreichbar.',
        flow: ['Report-Absender', 'Proton Mail', 'Lokale Bridge', 'DMARQ'],
        processors: ['Proton', 'Proton Mail Bridge', 'Deine DMARQ-Instanz'],
        public_exposure: 'Keine öffentliche DMARQ-URL erforderlich.',
        credentials: 'Von Bridge erzeugte lokale IMAP-Zugangsdaten.',
        test_method: 'Bridge-IMAP testen und danach einen DMARQ-Poll auslösen.',
        action_label: 'Bridge-IMAP verbinden',
        href: '/mail-sources?method=IMAP&bridge=proton',
      },
      first_report: {
        ...reportIntakeRecommendation.first_report,
        state: 'waiting',
        headline: 'Warten auf den ersten Aggregatreport',
        description: 'Der Intake-Weg ist eingerichtet.',
      },
      alternatives: [],
      preferences: {
        selected_option: 'proton_bridge',
        setup_effort: 'balanced',
        continuous_monitoring: true,
        local_bridge_available: true,
      },
    }));
  });

  await page.goto('/onboarding');
  await expect(page.getByText(/Empfohlener Report-Eingang/i)).toBeVisible();
  await expect(page.getByRole('heading', {name: 'Proton Mail über lokale Bridge'})).toBeVisible();
  await expect(page.getByRole('link', {name: 'Bridge-IMAP verbinden'})).toBeVisible();
  await expect(page.getByText('Warten auf den ersten Aggregatreport')).toBeVisible();
});

test('guided onboarding renders manual, hosted, and ready Worker recommendations', async ({page}) => {
  let selected = 'manual';
  const variants = {
    manual: {
      id: 'manual_upload',
      title: 'Upload an existing report',
      summary: 'Interpret one report without a persistent connection.',
      action_label: 'Upload report',
      href: '/upload',
      flow: ['Report file', 'DMARQ upload', 'Local interpretation'],
    },
    hosted: {
      id: 'gmail',
      title: 'Connect Gmail with OAuth',
      summary: 'Use revocable delegated access to a dedicated report mailbox.',
      action_label: 'Connect Gmail',
      href: '/mail-sources?method=GMAIL_API',
      flow: ['Report sender', 'Gmail', 'OAuth', 'DMARQ'],
    },
    worker: {
      id: 'cloudflare_worker',
      title: 'Cloudflare Email Routing and Worker',
      summary: 'Forward raw report mail to an authenticated HTTPS endpoint.',
      action_label: 'Open Worker how-to',
      href: '/docs/cloudflare-worker',
      flow: ['Report sender', 'Email Routing', 'Worker', 'DMARQ webhook'],
      availability_reason: 'HTTPS is ready; configure an inbound webhook secret next.',
    },
  };
  await page.route('**/api/v1/workspaces/guidance/report-intake-recommendation', async (route) => {
    const variant = variants[selected];
    await route.fulfill(json({
      ...reportIntakeRecommendation,
      recommended: {
        ...reportIntakeRecommendation.recommended,
        ...variant,
      },
      primary_action: {label: variant.action_label, href: variant.href},
      alternatives: [],
      public_endpoint: {
        https_ready: selected === 'worker',
        webhook_configured: selected === 'worker',
      },
    }));
  });

  await page.goto('/onboarding');
  await expect(page.getByRole('heading', {name: variants.manual.title})).toBeVisible();
  await expect(page.getByRole('link', {name: variants.manual.action_label})).toBeVisible();

  selected = 'hosted';
  await page.reload();
  await expect(page.getByRole('heading', {name: variants.hosted.title})).toBeVisible();
  await expect(page.getByRole('link', {name: variants.hosted.action_label})).toBeVisible();

  selected = 'worker';
  await page.reload();
  await expect(page.getByRole('heading', {name: variants.worker.title})).toBeVisible();
  await expect(page.getByRole('link', {name: variants.worker.action_label})).toBeVisible();
  await expect(page.getByText(variants.worker.availability_reason)).toBeVisible();
});

test('intake recommendation link opens a prefilled Proton Bridge source', async ({page}) => {
  await page.goto('/mail-sources?method=IMAP&bridge=proton');

  await expect(page.getByRole('heading', {name: 'Add Mail Source'})).toBeVisible();
  await expect(page.getByRole('textbox', {name: /Name/})).toHaveValue('Proton Mail Bridge');
  await expect(page.getByRole('combobox', {name: 'Method'})).toHaveValue('IMAP');
  await expect(page.getByRole('textbox', {name: /Server/})).toHaveValue('127.0.0.1');
  await expect(page.getByRole('spinbutton', {name: 'Port'})).toHaveValue('1143');
  await expect(page.getByRole('checkbox', {name: /Use TLS/})).not.toBeChecked();
});

test('domain sender view guides DKIM repair from saved mailflow evidence', async ({ page }) => {
  await page.goto('/domains/cklnet.com#sending-sources');

  const sendingSources = page.locator('details', {
    has: page.locator('summary', { hasText: 'Sending sources' }),
  });
  await expect(sendingSources).toHaveAttribute('open', '');
  await expect(sendingSources.getByRole('heading', { name: 'Repair DKIM signing for an active mailflow' })).toBeVisible();
  await expect(sendingSources.getByText('Next step: Confirm DKIM signing for this domain in the sending service')).toBeVisible();
  await expect(sendingSources.getByText('Confirm DKIM signing is enabled for cklnet.com')).toBeVisible();
  await sendingSources.getByText('Mailflow identities').click();
  await expect(sendingSources.getByText('DKIM domain: cklnet.com').first()).toBeVisible();
  await expect(sendingSources.getByText('Selector: mail')).toBeVisible();
  await expect(sendingSources.getByText('Aligned DKIM observed')).toBeVisible();
  await expect(sendingSources.getByText('Aligned DKIM not observed')).toBeVisible();
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto('/domains/cklnet.com#sending-sources');
  await expect(page.getByRole('heading', { name: 'Repair DKIM signing for an active mailflow' })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1)).toBe(true);
});

test('domain detail shows cached DNS evidence and sender reputation context', async ({ page }) => {
  await page.goto('/domains/cklnet.com');

  await expect(page.getByRole('heading', { name: 'cklnet.com' })).toBeVisible();
  const dnsEvidence = page.locator('details', {
    has: page.locator('summary', { hasText: 'Email authentication and DNS fixes' }),
  });
  await dnsEvidence.locator(':scope > summary').click();
  await expect(dnsEvidence.getByText('TXT lookup timed out; showing cached DNS evidence')).toBeVisible();
  await expect(dnsEvidence.getByText('v=DMARC1; p=reject; rua=mailto:dmarc@cklnet.com')).toBeVisible();
  const sourceIntelligence = page.locator('details', {
    has: page.locator('summary', { hasText: 'Source intelligence' }),
  });
  await sourceIntelligence.locator(':scope > summary').click();
  await expect(sourceIntelligence.getByRole('heading', { name: 'Source Intelligence' })).toBeVisible();
  await expect(sourceIntelligence.getByText('Europe', { exact: true })).toBeVisible();
  const sendingSources = page.locator('details', {
    has: page.locator('summary', { hasText: 'Sending sources' }),
  });
  await sendingSources.locator(':scope > summary').click();
  const postmarkSource = sendingSources.locator('article:visible').filter({ hasText: '50.31.205.203' });
  const ownedSource = sendingSources.locator('article:visible').filter({ hasText: '2a01:4f8:c17:311b::1' });
  await expect(postmarkSource.getByText('Postmark', { exact: true })).toBeVisible();
  await expect(ownedSource.getByText('Owned infrastructure', { exact: true })).toBeVisible();
  await postmarkSource.locator('summary', { hasText: 'Trust signals' }).click();
  await ownedSource.locator('summary', { hasText: 'Trust signals' }).click();
  await expect(postmarkSource.getByText('Reputation clean')).toBeVisible();
  await expect(ownedSource.getByText('Reputation not checked', { exact: true }).first()).toBeVisible();
  await expect(ownedSource.getByText('Fix DKIM on owned infrastructure')).toBeVisible();
  await expect(page.getByText('Sending sources could not be loaded.')).not.toBeVisible();
  await expect(page.getByText('No data available for this time period')).not.toBeVisible();
  const recentReports = page.locator('details', {
    has: page.locator('summary', { hasText: 'Reports' }),
  });
  await recentReports.locator(':scope > summary').click();
  await expect(recentReports.getByRole('heading', { name: 'Recent Reports' })).toBeVisible();
  await expect(recentReports.getByText('google.com').first()).toBeVisible();
});

test('DNS preview gives card-local progress and review feedback', async ({ page }) => {
  await page.goto('/domains/cklnet.com#dns-records');

  const dnsEvidence = page.locator('details', {
    has: page.locator('summary', { hasText: 'Email authentication and DNS fixes' }),
  });
  await expect(dnsEvidence.locator(':scope > summary')).toBeVisible();
  await dnsEvidence.locator(':scope > summary').click();

  const plan = page.locator('div.rounded.border.border-base-300.p-3').filter({
    hasText: '_dmarc.cklnet.com',
  }).first();
  await expect(plan.getByRole('button', { name: '1. Preview change' })).toBeVisible();
  await plan.getByRole('button', { name: '1. Preview change' }).click();
  await expect(plan.getByText('Preparing a Cloudflare preview...')).toBeVisible();
  await expect(plan.getByText('2. Review before applying')).toBeVisible();
  await expect(plan.getByText('Preview ready. Review the provider mutation before applying.')).toBeVisible();
  await expect(plan.getByRole('button', { name: /3\. Apply to Cloudflare/ })).toBeEnabled();
});

test('reports list and aggregate detail keep source evidence actionable', async ({ page }) => {
  await page.goto('/reports');

  await expect(page.getByRole('cell', { name: 'cklnet.com' })).toBeVisible();
  await expect(page.getByText('Reports unavailable')).not.toBeVisible();
  await expect(page.getByText('No reports match this filter.')).not.toBeVisible();

  await page.getByRole('link', { name: 'View Details' }).first().click();
  await expect(page.getByRole('heading', { name: 'Report: browser-smoke-cklnet' })).toBeVisible();
  const postmarkCluster = page.getByRole('article').filter({
    has: page.getByRole('heading', { name: 'ActiveCampaign Postmark' }),
  });
  await postmarkCluster.locator('summary', { hasText: 'Show IP evidence' }).click();
  await expect(postmarkCluster.getByText('50.31.205.203')).toBeVisible();

  await page.locator('select[x-model="recordRiskFilter"]').selectOption('all');
  const rawEvidence = page.locator('#report-records');
  await rawEvidence.locator(':scope > summary').click();
  await expect(rawEvidence.getByText('mta203-ab1.mtasv.net', { exact: true }).first()).toBeVisible();
  const evidenceRows = rawEvidence.locator('details summary', { hasText: 'View evidence' });
  await expect(evidenceRows).toHaveCount(2);
  await evidenceRows.first().click();
  await expect(rawEvidence.getByText('AS23352').first()).toBeVisible();
  await expect(rawEvidence.getByText('SERVERCENTRAL - DEFT.COM, US').first()).toBeVisible();
  await expect(rawEvidence.getByRole('columnheader', { name: 'Evidence' })).toBeVisible();
  await expect(rawEvidence.getByText('Reputation clean').first()).toBeVisible();
  await expect(rawEvidence.getByText('risk 0/100').first()).toBeVisible();
  await expect(rawEvidence.getByText('No blacklist listings found.').first()).toBeVisible();
  await evidenceRows.nth(1).click();
  const secondEvidence = evidenceRows.nth(1).locator('..');
  await expect(secondEvidence.getByText('Reputation not checked', { exact: true })).toBeVisible();
  await expect(secondEvidence.getByText('Reputation feeds are disabled.')).toBeVisible();
  await expect(rawEvidence.getByText('DKIM did not pass for this source.')).toBeVisible();
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

test('provider demo supports site-manager account management and full customer impersonation', async ({ page }) => {
  test.setTimeout(60_000);
  test.skip(!realProviderBackend, 'requires the relational provider-demo backend');
  const response = await page.goto('/');
  expect(response, 'provider demo navigation should return a response').not.toBeNull();
  await expect(page).toHaveURL(/\/provider-demo$/);

  await expect(page.getByRole('heading', { name: 'Kundenkonten verwalten' })).toBeVisible();
  await expect(page.getByText('Interaktive Demo:', { exact: true })).toBeVisible();
  await expect(page.locator('[data-provider-account-row]')).toHaveCount(6);

  const lawfirmRow = page.locator('[data-provider-account-row="lawfirm-example"]');
  await expect(lawfirmRow.getByText('Kanzlei Hansen & Partner')).toBeVisible();
  await expect(lawfirmRow.getByText('Kritisch')).toBeVisible();
  await lawfirmRow.getByRole('button', { name: 'Account öffnen', exact: true }).click();

  const accountView = page.locator('[data-provider-account-view]');
  await expect(accountView.getByRole('heading', { name: 'Kanzlei Hansen & Partner' })).toBeVisible();
  await expect(accountView.locator('header').getByText('Fehlgeschlagene Sender priorisieren und DKIM/SPF vor einer Policy-Änderung reparieren.')).toBeVisible();

  await page.locator('nav [data-provider-account-tab="domains"]').click();
  const lawfirmDomainCell = accountView.getByRole('cell', { name: 'lawfirm.example', exact: true });
  await expect(lawfirmDomainCell).toBeVisible();
  const lawfirmDomainRow = lawfirmDomainCell.locator('..');
  await expect(lawfirmDomainRow).toContainText('68,2 %');

  await page.locator('nav [data-provider-account-tab="users"]').click();
  await page.getByRole('button', { name: 'Benutzer einladen' }).click();
  const userDialog = page.getByRole('dialog', { name: 'Benutzer einladen' });
  await userDialog.getByLabel('Name', { exact: true }).fill('Mara Admin');
  await userDialog.getByLabel('E-Mail', { exact: true }).fill('mara@lawfirm.example');
  await userDialog.getByRole('button', { name: 'Einladung simulieren' }).click();
  await expect(accountView.getByRole('cell', { name: 'mara@lawfirm.example' })).toBeVisible();

  await page.locator('nav [data-provider-account-tab="billing"]').click();
  await page.getByLabel('Monatlicher Betrag').fill('99');
  await page.getByLabel('Rechnungsempfänger').fill('finance@lawfirm.example');
  await page.getByRole('button', { name: 'Billing speichern' }).click();
  await expect(page.getByText(/Lokal gespeichert/)).toBeVisible();

  await page.getByRole('button', { name: 'Kundenansicht öffnen' }).click();
  const supportDialog = page.getByRole('dialog', { name: 'Kundenansicht öffnen' });
  await expect(supportDialog.getByLabel('Ansicht als')).not.toHaveValue('');
  await supportDialog.getByLabel('Grund').fill('DKIM-Ausfall gemeinsam mit dem Kunden prüfen');
  await supportDialog.getByRole('button', { name: 'Support-Sitzung starten' }).click();

  await expect(page).toHaveURL(/\/dashboard$/);
  const supportBanner = page.locator('[data-support-session-banner]');
  await expect(supportBanner.getByText('Kanzlei Hansen & Partner · Ansicht als admin@lawfirm.example')).toBeVisible();
  await expect(supportBanner.getByText(/Modell: DMARQ Protect Plus/)).toBeVisible();
  await page.goto('/domains');
  const customerLawfirmRow = page.getByRole('row').filter({
    has: page.getByText('lawfirm.example', { exact: true }),
  });
  const secureLawfirmRow = page.getByRole('row').filter({
    has: page.getByText('secure.lawfirm.example', { exact: true }),
  });
  await expect(customerLawfirmRow).toContainText('quarantine');
  await expect(secureLawfirmRow).toContainText('none');
  await expect(page.getByRole('cell', { name: 'bakery.example' })).toHaveCount(0);
  await page.goto('/members');
  await expect(page.getByRole('table').getByText('admin@lawfirm.example', { exact: true })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Invite or Link Member' })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Deactivate' })).toHaveCount(0);
  await page.locator('[data-support-session-exit]').click();
  await expect(page).toHaveURL(/\/provider-demo#accounts$/);
  await expect(page.locator('[data-provider-account-row="lawfirm-example"]')).toContainText('Kanzlei Hansen & Partner');
  await expect(page.locator('[data-workspace-switcher]')).toHaveCount(0);

  await page.getByRole('button', { name: 'Neues Kundenkonto' }).click();
  const createDialog = page.getByRole('dialog', { name: 'Kundenkonto anlegen' });
  await createDialog.getByLabel('Firmenname').fill('Demo Kanzlei');
  await createDialog.getByLabel('Primäre Domain').fill('kanzlei.example');
  await createDialog.getByRole('button', { name: 'Account erstellen' }).click();
  await expect(accountView.getByRole('heading', { name: 'Demo Kanzlei' })).toBeVisible();

  await page.reload();
  await expect(accountView.getByRole('heading', { name: 'Demo Kanzlei' })).toBeVisible();
  await expect(
    accountView.locator('section[x-show="showAccountOverview"]').getByRole('cell', { name: 'kanzlei.example', exact: true })
  ).toBeVisible();

  await page.setViewportSize({ width: 390, height: 844 });
  await page.getByRole('button', { name: 'Provider-Verwaltung' }).click();
  const mobileAccountCard = page.locator('[data-provider-account-card="demo-kanzlei"]');
  await expect(mobileAccountCard).toBeVisible();
  await expect(page.locator('[data-provider-account-row="demo-kanzlei"]')).toBeHidden();
  await expect.poll(async () => page.evaluate(() => document.documentElement.scrollWidth)).toBe(390);
  await mobileAccountCard.getByRole('button', { name: 'Account öffnen' }).click();
  await page.getByRole('button', { name: 'Kundenansicht öffnen' }).click();
  await expect(page.getByRole('dialog', { name: 'Kundenansicht öffnen' })).toBeVisible();
  await expect.poll(async () => page.evaluate(() => document.documentElement.scrollWidth)).toBe(390);
  await page.getByRole('dialog', { name: 'Kundenansicht öffnen' }).getByRole('button', { name: 'Schließen' }).click();
  await expect(page.locator('[data-provider-demo-expression-error]')).toBeHidden();
});

test('provider demo can enter every seeded customer support scope', async ({ page }) => {
  test.setTimeout(120_000);
  test.skip(!realProviderBackend, 'requires the relational provider-demo backend');

  const expectedAccounts = {
    'bakery-example': { domains: ['bakery.example'], owner: 'anna@bakery.example' },
    'feldwerk-logistics': { domains: ['feldwerk.example'], owner: 'jonas@feldwerk.example' },
    'lawfirm-example': {
      domains: ['lawfirm.example', 'secure.lawfirm.example'],
      owner: 'admin@lawfirm.example',
    },
    'retail-example': {
      domains: ['retail.example', 'shop.retail.example'],
      owner: 'ops@retail.example',
    },
    'studio-example': {
      domains: ['alerts.studio.example', 'studio.example'],
      owner: 'elena@studio.example',
    },
    'praxis-stadtpark': { domains: ['praxis.example'], owner: 'nele@praxis.example' },
  };

  for (const [accountSlug, expected] of Object.entries(expectedAccounts)) {
    await page.goto('/provider-demo#accounts');
    const accountRow = page.locator(`[data-provider-account-row="${accountSlug}"]`);
    await expect(accountRow).toBeVisible();
    await accountRow.getByRole('button', { name: 'Account öffnen', exact: true }).click();
    await page.getByRole('button', { name: 'Kundenansicht öffnen' }).click();

    const supportDialog = page.getByRole('dialog', { name: 'Kundenansicht öffnen' });
    await expect(supportDialog.getByLabel('Ansicht als')).not.toHaveValue('');
    await supportDialog.getByLabel('Grund').fill(`Support-Scope für ${accountSlug} prüfen`);
    await supportDialog.getByRole('button', { name: 'Support-Sitzung starten' }).click();

    await expect(page).toHaveURL(/\/dashboard$/);
    await expect(page.locator('[data-support-session-banner]')).toBeVisible();
    await page.goto('/domains');
    for (const domain of expected.domains) {
      const domainRow = page.getByRole('row').filter({
        has: page.getByText(domain, { exact: true }),
      });
      await expect(domainRow).toBeVisible();
    }
    await page.goto('/members');
    await expect(page.getByRole('table').getByText(expected.owner, { exact: true })).toBeVisible();
    await page.locator('[data-support-session-exit]').click();
    await expect(page).toHaveURL(/\/provider-demo#accounts$/);
  }
});

test('production provider mode persists a customer and opens its role-scoped product view', async ({ page }) => {
  test.setTimeout(60_000);
  test.skip(!productProviderBackend, 'requires a fresh production provider backend');

  const response = await page.goto('/provider');
  expect(response, 'production provider navigation should return a response').not.toBeNull();
  await expect(page).toHaveURL(/\/provider$/);
  await expect(page.getByRole('heading', { name: 'Kundenkonten verwalten' })).toBeVisible();
  await expect(page.getByText('CKLNet · Site Manager')).toBeVisible();
  await expect(page.getByRole('link', { name: 'Single-user-Demo' })).toHaveCount(0);
  await expect(page.getByText('Sofia Weber')).toHaveCount(0);
  await expect(page.locator('[data-provider-account-row]')).toHaveCount(0);

  await page.getByRole('button', { name: 'Neues Kundenkonto' }).click();
  const createDialog = page.getByRole('dialog', { name: 'Kundenkonto anlegen' });
  await createDialog.getByLabel('Firmenname').fill('CKLNet Pilotkunde');
  await createDialog.getByLabel('Primäre Domain').fill('pilot.customer.example');
  await createDialog.getByLabel('Plan').selectOption('protect');
  await createDialog.getByRole('button', { name: 'Account erstellen' }).click();

  const accountView = page.locator('[data-provider-account-view]');
  await expect(accountView.getByRole('heading', { name: 'CKLNet Pilotkunde' })).toBeVisible();
  await expect(accountView.getByRole('cell', { name: 'pilot.customer.example', exact: true })).toBeVisible();

  await page.locator('nav [data-provider-account-tab="users"]').click();
  await page.getByRole('button', { name: 'Benutzer einladen' }).click();
  const userDialog = page.getByRole('dialog', { name: 'Benutzer einladen' });
  await userDialog.getByLabel('Name', { exact: true }).fill('Pilot Admin');
  await userDialog.getByLabel('E-Mail', { exact: true }).fill('admin@pilot.customer.example');
  await userDialog.getByLabel('Rolle').selectOption('workspace_admin');
  await userDialog.getByRole('button', { name: 'Benutzer einladen' }).click();
  await expect(accountView.getByRole('cell', { name: 'admin@pilot.customer.example' })).toBeVisible();

  await page.locator('nav [data-provider-account-tab="billing"]').click();
  await page.getByLabel('Monatlicher Betrag').fill('149');
  await page.getByLabel('Rechnungsempfänger').fill('billing@pilot.customer.example');
  await page.getByLabel('Rechnungsreferenz').fill('CKL-PILOT-001');
  await page.getByRole('button', { name: 'Billing speichern' }).click();
  await expect(page.getByText(/Gespeichert/)).toBeVisible();

  await page.evaluate(() => {
    sessionStorage.setItem('dmarq-provider-console-v3', JSON.stringify({
      accounts: [{slug: 'stale-browser-account', name: 'Stale browser account'}],
      selectedAccountSlug: 'cklnet-pilotkunde',
      viewMode: 'account',
      accountTab: 'billing',
    }));
  });
  await page.reload();
  await expect(page.getByText('Stale browser account')).toHaveCount(0);
  await expect(accountView.getByRole('heading', { name: 'CKLNet Pilotkunde' })).toBeVisible();
  await page.locator('nav [data-provider-account-tab="billing"]').click();
  await expect(page.getByLabel('Monatlicher Betrag')).toHaveValue('149');
  await expect(page.getByLabel('Rechnungsempfänger')).toHaveValue('billing@pilot.customer.example');
  await expect(page.getByLabel('Rechnungsreferenz')).toHaveValue('CKL-PILOT-001');

  await page.getByRole('button', { name: 'Kundenansicht öffnen' }).click();
  const supportDialog = page.getByRole('dialog', { name: 'Kundenansicht öffnen' });
  await supportDialog.getByLabel('Grund').fill('Produktiven Kundenzugang verifizieren');
  await supportDialog.getByRole('button', { name: 'Support-Sitzung starten' }).click();

  await expect(page).toHaveURL(/\/dashboard$/);
  const supportBanner = page.locator('[data-support-session-banner]');
  await expect(supportBanner).toContainText('CKLNet Pilotkunde · Ansicht als admin@pilot.customer.example');
  await expect(supportBanner).toContainText('Rollenberechtigungen aktiv');
  await expect(supportBanner).toContainText('Modell: DMARQ Protect');
  await page.goto('/members');
  await expect(page.getByRole('heading', { name: 'Invite or Link Member' })).toBeVisible();
  await page.locator('[data-support-session-exit]').click();
  await expect(page).toHaveURL(/\/provider#accounts$/);
  await expect(page.locator('[data-provider-account-row="cklnet-pilotkunde"]')).toContainText('CKLNet Pilotkunde');
});
