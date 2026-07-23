function dashboardApp() {
    return {
        hasDomainData: false,
        hasReportData: false,
        volumeTrendChart: null,
        complianceTrendChart: null,
        healthTrendChart: null,
        domains: [],
        healthSummary: null,
        healthHistory: null,
        dashboardLoading: true,
        dashboardError: '',
        dashboardRefreshError: '',
        domainSummaryLoadedAt: '',
        remediationRefreshRunning: false,
        dashboardRemediationFilter: 'all',
        dashboardRemediationSort: 'priority',
        showAllDashboardRemediationItems: false,
        dashboardRemediationFilterCountCache: null,
        dashboardRemediationFilterOptions: [
            { value: 'all', label: 'All' },
            { value: 'preview_ready', label: 'Preview ready' },
            { value: 'fresh_evidence', label: 'Fresh evidence' },
            { value: 'approval_verification', label: 'Approval' },
            { value: 'provider_apply', label: 'Provider apply' },
            { value: 'apply_blocked', label: 'Apply blocked' },
            { value: 'provider_history', label: 'Provider history' },
            { value: 'notify_ready', label: 'Ready to notify' },
            { value: 'dispatched', label: 'Dispatched' },
            { value: 'follow_up', label: 'Follow-up' },
            { value: 'aging_follow_up', label: 'Aging follow-up' },
            { value: 'dispatch_blocked', label: 'Dispatch blocked' },
            { value: 'stuck', label: 'Stuck' },
            { value: 'sender_review', label: 'Sender review' },
            { value: 'report_evidence', label: 'Report evidence' },
            { value: 'stale_evidence', label: 'Stale evidence' },
            { value: 'blocked', label: 'Blocked' },
            { value: 'waiting_operator', label: 'Waiting' },
            { value: 'manual', label: 'Manual' },
            { value: 'reputation', label: 'Reputation' }
        ],
        selectedDnsDomain: '',
        triggerPollRunning: false,
        hasEnabledMailSources: false,
        triggerPollStatus: '',
        triggerPollMessage: '',
        hiddenEmptyDomainsCount: 0,
        intakeState: {
            schedulerActive: false,
            attentionSources: 0,
            reauthSources: 0,
            lastCheck: '',
        },
        demoDeployment: null,
        selectedDemoScenarioId: 'single-user-multiple-domains',
        selectedDemoZoomLevel: 'workspace',
        selectedDemoOrganizationSlug: '',
        selectedDemoWorkspaceSlug: '',
        selectedDemoUserEmail: '',
        demoTourActive: false,
        demoTourStepIndex: 0,
        demoTourSteps: [
            {
                selector: '[data-tour="date-filter"]',
                title: 'Change the evidence window',
                body: 'Use sensible ranges or custom dates to inspect current incidents, week-to-date activity, or the full rolling demo history.'
            },
            {
                selector: '[data-tour="compliance-chart"]',
                title: 'Read the DMARC posture first',
                body: 'Compliance, message volume, reports, and trends show whether the domain is ready for stronger enforcement.'
            },
            {
                selector: '[data-tour="dns-health"]',
                title: 'Check DNS health by domain',
                body: 'Pick a domain and jump to its detail page to inspect SPF, DKIM, DMARC policy, and lint findings.'
            },
            {
                selector: '[data-tour="top-sources"]',
                title: 'Investigate senders',
                body: 'Top sources surface the systems sending mail on behalf of the selected account and where authentication breaks.'
            }
        ],
        dateInterval: 'last_30_days',
        customStartDate: '',
        customEndDate: '',
        dateRangeLabel: 'Last 30 days',
        dateIntervalOptions: [
            { value: 'last_24_hours', label: 'Last 24 hours' },
            { value: 'last_48_hours', label: 'Last 48 hours' },
            { value: 'last_7_days', label: 'Last 7 days' },
            { value: 'last_30_days', label: 'Last 30 days' },
            { value: 'last_90_days', label: 'Last 90 days' },
            { value: 'week_to_date', label: 'Week to date' },
            { value: 'month_to_date', label: 'Month to date' },
            { value: 'custom', label: 'Custom' }
        ],

        get selectedDnsDomainRecord() {
            if (!this.selectedDnsDomain) return null;
            return this.domains.find(domain => domain.domain_name === this.selectedDnsDomain) || null;
        },

        get selectedDomainHref() {
            const domain = this.selectedDnsDomainRecord;
            return domain ? this.domainHref(domain) : '/domains';
        },

        get healthScore() {
            return this.healthSummary && this.healthSummary.score !== undefined && this.healthSummary.score !== null
                ? this.healthSummary.score
                : 0;
        },

        get healthGrade() {
            return this.healthSummary && this.healthSummary.grade
                ? this.healthSummary.grade
                : 'F';
        },

        get healthStatus() {
            return this.healthSummary && this.healthSummary.status
                ? this.healthSummary.status
                : 'unknown';
        },

        get healthAttentionDomains() {
            return this.healthSummary && this.healthSummary.attention_domains
                ? this.healthSummary.attention_domains
                : 0;
        },

        get healthDomainCount() {
            return this.healthSummary && this.healthSummary.domain_count
                ? this.healthSummary.domain_count
                : 0;
        },

        get hasHealthHistoryPoints() {
            return Boolean(this.healthHistory && this.healthHistory.points && this.healthHistory.points.length);
        },

        get healthScoreDeltaClass() {
            return this.healthHistory && (Number(this.healthHistory.score_delta) || 0) >= 0
                ? 'text-[#247982]'
                : 'text-[#b8431d]';
        },

        get healthScoreDeltaLabel() {
            return this.formatScoreDelta(this.healthHistory ? this.healthHistory.score_delta : null);
        },

        get topHealthActions() {
            const actions = this.healthSummary && Array.isArray(this.healthSummary.top_actions)
                ? this.healthSummary.top_actions
                : [];
            return actions.slice(0, 3);
        },

        get hasTopHealthActions() {
            return this.topHealthActions.length > 0;
        },

        get secondaryHealthActions() {
            return this.topHealthActions.slice(1);
        },

        get hasSecondaryHealthActions() {
            return this.secondaryHealthActions.length > 0;
        },

        get dashboardNextAction() {
            if (this.intakeState.reauthSources > 0) {
                return {
                    eyebrow: 'Report intake blocked',
                    title: 'Reconnect the report mailbox',
                    detail: 'A connected mailbox needs authorization before scheduled imports can continue.',
                    label: 'Review mail source',
                    href: '/mail-sources',
                    severity: 'high',
                };
            }
            if (this.intakeState.attentionSources > 0) {
                return {
                    eyebrow: 'Report intake needs attention',
                    title: 'Resolve the mailbox connection warning',
                    detail: 'DMARQ cannot rely on fresh evidence until the affected source succeeds again.',
                    label: 'Review mail source',
                    href: '/mail-sources',
                    severity: 'high',
                };
            }
            const action = this.topHealthActions[0];
            if (action) {
                return {
                    eyebrow: `${action.severity || 'medium'} priority`,
                    title: action.title || 'Review the highest-priority domain issue',
                    detail: action.next_step || action.detail || 'Review current evidence before changing DNS or sender configuration.',
                    label: 'Open remediation',
                    href: this.domainActionHref(action),
                    severity: action.severity || 'medium',
                };
            }
            return {
                eyebrow: 'Monitoring',
                title: 'No immediate remediation action',
                detail: 'Keep report intake running and review new sender or DNS changes when they appear.',
                label: 'Review reports',
                href: '/reports',
                severity: 'info',
            };
        },

        get showDashboardNextAction() {
            return this.hasReportData ||
                this.intakeState.reauthSources > 0 ||
                this.intakeState.attentionSources > 0;
        },

        get dashboardScopeLabel() {
            const hidden = Number(this.hiddenEmptyDomainsCount || 0);
            if (!hidden) return 'Report-backed domains only';
            return `Report-backed domains only · ${hidden} empty domain${hidden === 1 ? '' : 's'} hidden`;
        },

        get configuredDomainCount() {
            return this.domains.length + Number(this.hiddenEmptyDomainsCount || 0);
        },

        get hasConfiguredDomainData() {
            return this.configuredDomainCount > 0;
        },

        get intakeSchedulerLabel() {
            if (this.triggerPollRunning) return 'Import running';
            if (this.intakeState.schedulerActive) return 'Scheduled checks active';
            return this.hasEnabledMailSources ? 'Scheduled checks stopped' : 'No source configured';
        },

        get selectedDnsPolicyLabel() {
            const record = this.selectedDnsDomainRecord;
            return record && record.dmarc_policy ? `Policy: ${record.dmarc_policy}` : 'Policy: unknown';
        },

        get selectedDnsWarningsCount() {
            const record = this.selectedDnsDomainRecord;
            const warnings = record && Array.isArray(record.dmarc_warnings)
                ? record.dmarc_warnings
                : [];
            return warnings.length;
        },

        get hasSelectedDnsWarnings() {
            return this.selectedDnsWarningsCount > 0;
        },

        get selectedDnsWarningsPlural() {
            return this.selectedDnsWarningsCount === 1 ? '' : 's';
        },

        get demoTourStepLabel() {
            return `Step ${this.demoTourStepIndex + 1} of ${this.demoTourSteps.length}`;
        },

        get currentDemoTourTitle() {
            const step = this.currentDemoTourStep();
            return step ? step.title : '';
        },

        get currentDemoTourBody() {
            const step = this.currentDemoTourStep();
            return step ? step.body : '';
        },

        get isLastDemoTourStep() {
            return this.demoTourStepIndex + 1 >= this.demoTourSteps.length;
        },

        get demoTourNextLabel() {
            return this.isLastDemoTourStep ? 'Finish' : 'Next';
        },

        get domainSummaryLoadedAtLabel() {
            if (!this.domainSummaryLoadedAt) return '';
            return new Date(this.domainSummaryLoadedAt).toLocaleString();
        },
        
        init() {
            this.bindControls();
            if (typeof this.$watch === 'function') {
                this.$watch('dashboardRemediationSort', () => {
                    this.showAllDashboardRemediationItems = false;
                });
            }

            // Fetch domain summary on page load
            this.fetchDomainSummary();
            
            // Check report intake status
            this.getReportIntakeStatus();
            this.fetchForensicSummary();
        },

        bindControls() {
            if (typeof document === 'undefined') return;
            const hasElement = typeof Element !== 'undefined';
            const root = hasElement && this.$root instanceof Element
                ? this.$root
                : document.querySelector('.dashboard-page');
            if (!root || root.dataset.dashboardControlsBound === 'true') return;
            root.dataset.dashboardControlsBound = 'true';

            root.addEventListener('change', event => {
                if (!hasElement || !(event.target instanceof Element)) return;

                const dateInterval = event.target.closest('[data-dashboard-date-interval]');
                if (dateInterval && root.contains(dateInterval)) {
                    this.dateInterval = dateInterval.value;
                    this.handleDateIntervalChange();
                    return;
                }

                const dnsDomain = event.target.closest('[data-dashboard-dns-health-domain]');
                if (dnsDomain && root.contains(dnsDomain)) {
                    this.selectedDnsDomain = dnsDomain.value;
                    this.updateDnsHealth();
                    return;
                }

                const remediationSort = event.target.closest('[data-dashboard-remediation-sort]');
                if (remediationSort && root.contains(remediationSort)) {
                    this.dashboardRemediationSort = remediationSort.value || 'priority';
                    this.showAllDashboardRemediationItems = false;
                }
            });

            root.addEventListener('click', event => {
                if (!hasElement || !(event.target instanceof Element)) return;

                const customApply = event.target.closest('[data-dashboard-custom-apply]');
                if (customApply && root.contains(customApply)) {
                    this.fetchDashboardStats();
                    this.fetchWorkspaceHealthHistory();
                    return;
                }

                const remediationRefresh = event.target.closest('[data-dashboard-remediation-refresh]');
                if (remediationRefresh && root.contains(remediationRefresh)) {
                    this.fetchDomainSummary({ refresh: true });
                    return;
                }

                const dashboardRefresh = event.target.closest('[data-dashboard-refresh]');
                if (dashboardRefresh && root.contains(dashboardRefresh)) {
                    this.fetchDomainSummary({ refresh: true });
                    return;
                }

                const remediationFilter = event.target.closest('[data-dashboard-remediation-filter]');
                if (remediationFilter && root.contains(remediationFilter)) {
                    this.dashboardRemediationFilter =
                        remediationFilter.dataset.dashboardRemediationFilter || 'all';
                    this.showAllDashboardRemediationItems = false;
                    return;
                }

                const remediationResetFilter = event.target.closest('[data-dashboard-remediation-reset-filter]');
                if (remediationResetFilter && root.contains(remediationResetFilter)) {
                    this.resetDashboardRemediationFilter();
                    return;
                }

                const remediationToggleAll = event.target.closest('[data-dashboard-remediation-toggle-all]');
                if (remediationToggleAll && root.contains(remediationToggleAll)) {
                    this.showAllDashboardRemediationItems = !this.showAllDashboardRemediationItems;
                    return;
                }

                const triggerPoll = event.target.closest('[data-dashboard-trigger-poll]');
                if (triggerPoll && root.contains(triggerPoll)) {
                    this.triggerPollNow();
                    return;
                }

                const closeTour = event.target.closest('[data-dashboard-demo-tour-close]');
                if (closeTour && root.contains(closeTour)) {
                    this.closeDemoTour();
                    return;
                }

                const previousTourStep = event.target.closest('[data-dashboard-demo-tour-previous]');
                if (previousTourStep && root.contains(previousTourStep)) {
                    this.previousDemoTourStep();
                    return;
                }

                const nextTourStep = event.target.closest('[data-dashboard-demo-tour-next]');
                if (nextTourStep && root.contains(nextTourStep)) {
                    this.nextDemoTourStep();
                }
            });

            const ownerDocument = root.ownerDocument || document;
            const keydownHandlerKey = '__dmarqDashboardKeydownHandler';
            if (ownerDocument[keydownHandlerKey]) {
                ownerDocument.removeEventListener('keydown', ownerDocument[keydownHandlerKey]);
            }
            ownerDocument[keydownHandlerKey] = event => {
                if (event.key === 'Escape' && this.demoTourActive) {
                    this.closeDemoTour();
                }
            };
            ownerDocument.addEventListener('keydown', ownerDocument[keydownHandlerKey]);
        },
        
        formatSourceMethods(methods) {
            const labels = {
                IMAP: 'IMAP',
                GMAIL_API: 'Gmail API',
                M365_GRAPH: 'Microsoft 365'
            };
            return (methods || []).map(method => labels[method] || method).join(', ');
        },

        summarizePollResults(data) {
            const sources = data.sources || [];
            const count = data.sources_polled || sources.length || 0;
            if (!count) {
                return data.message || 'No enabled mail sources configured.';
            }

            const sourceMethods = this.formatSourceMethods(data.source_methods || []);
            const methodSuffix = sourceMethods ? ` (${sourceMethods})` : '';
            const processed = sources.reduce((total, source) => total + (source.processed || 0), 0);
            const reportsFound = sources.reduce((total, source) => total + (source.reports_found || 0), 0);
            const forensicFound = sources.reduce(
                (total, source) => total + (source.forensic_reports_found || 0),
                0
            );
            const newDomains = Array.from(
                new Set(sources.flatMap(source => source.new_domains || []))
            );
            const skipped = sources.filter(source => source.skipped).length;
            const failed = sources.filter(source => !source.skipped && source.success === false).length;
            const attention = sources.filter(source => source.diagnostic_category && ![
                'ok',
                'duplicate_only'
            ].includes(source.diagnostic_category));

            const parts = [
                `Polling finished for ${count} source${count === 1 ? '' : 's'}${methodSuffix}`,
                `${processed} email${processed === 1 ? '' : 's'} processed`,
                `${reportsFound} aggregate report${reportsFound === 1 ? '' : 's'} found`
            ];
            if (forensicFound) {
                parts.push(`${forensicFound} forensic report${forensicFound === 1 ? '' : 's'} found`);
            }
            if (newDomains.length) {
                const domainPreview = newDomains.slice(0, 3).join(', ');
                const extra = newDomains.length > 3 ? ` +${newDomains.length - 3} more` : '';
                parts.push(`new domains: ${domainPreview}${extra}`);
            }
            if (skipped) {
                parts.push(`${skipped} skipped`);
            }
            if (failed) {
                parts.push(`${failed} failed`);
            }
            if (attention.length) {
                const firstSummary = attention[0].diagnostic_summary || attention[0].reason || 'check Mail Sources';
                parts.push(`attention: ${firstSummary}`);
            }
            return `${parts.join('; ')}.`;
        },

        async getReportIntakeStatus() {
            try {
                const response = await fetch('/api/v1/poll-status');
                if (!response.ok) {
                    console.error('Error checking report intake status:', response.status);
                    return;
                }
                const data = await response.json();
                this.hasEnabledMailSources = (data.enabled_sources || 0) > 0;
                this.intakeState = {
                    schedulerActive: Boolean(data.is_running),
                    attentionSources: Number(data.attention_sources || 0),
                    reauthSources: Number(data.reauth_required_sources || 0),
                    lastCheck: data.latest_source_check || data.last_check || '',
                };
                
                const statusIcon = document.getElementById('imap-status-icon');
                const statusText = document.getElementById('imap-status-text');
                const lastCheck = document.getElementById('imap-last-check');
                const attentionRow = document.getElementById('mail-source-attention-row');
                const attentionText = document.getElementById('mail-source-attention');
                const attentionCount = data.attention_sources || 0;
                
                if (attentionCount > 0) {
                    statusIcon.classList.remove('bg-green-500');
                    statusIcon.classList.add('bg-red-500');
                    statusText.textContent = 'Needs attention';
                } else if (data.is_running && (data.enabled_sources || 0) > 0) {
                    statusIcon.classList.remove('bg-red-500');
                    statusIcon.classList.add('bg-green-500');
                    statusText.textContent = 'Scheduled checks active';
                } else {
                    statusIcon.classList.remove('bg-green-500');
                    statusIcon.classList.add('bg-red-500');
                    statusText.textContent = (data.enabled_sources || 0) > 0 ? 'Stopped' : 'No enabled sources';
                }
                
                const lastCheckValue = data.latest_source_check || data.last_check;
                if (lastCheckValue) {
                    lastCheck.textContent = new Date(lastCheckValue).toLocaleString();
                } else {
                    lastCheck.textContent = 'Never';
                }

                const mailbox = document.getElementById('imap-mailbox');
                if (mailbox) {
                    if (data.source_labels && data.source_labels.length) {
                        mailbox.textContent = data.source_labels.join(', ');
                    } else {
                        mailbox.textContent = 'No enabled mail sources configured';
                    }
                }
                if (attentionRow && attentionText) {
                    if (attentionCount > 0) {
                        const sources = data.sources || [];
                        const first = sources.find(source => source.connection_attention) || {};
                        const label = first.label ? `${first.label}: ` : '';
                        attentionText.textContent = `${attentionCount} source${attentionCount === 1 ? '' : 's'} need attention. ${label}${first.connection_message || ''}`.trim();
                        attentionRow.hidden = false;
                    } else {
                        attentionRow.hidden = true;
                        attentionText.textContent = '';
                    }
                }
            } catch (error) {
                console.error('Error checking report intake status:', error);
            }
        },

        async triggerPollNow() {
            this.triggerPollRunning = true;
            this.triggerPollStatus = '';
            this.triggerPollMessage = '';
            try {
                const response = await fetch('/api/v1/admin/trigger-poll', {
                    method: 'POST',
                    headers: { 'Accept': 'application/json' }
                });
                const data = await response.json().catch(() => ({}));
                if (!response.ok) {
                    const detail = data.detail;
                    const message = typeof detail === 'string'
                        ? detail
                        : (detail?.message || data.message || 'Could not trigger polling.');
                    throw new Error(message);
                }
                this.triggerPollStatus = 'success';
                this.triggerPollMessage = this.summarizePollResults(data);
                await this.getReportIntakeStatus();
                await this.fetchDomainSummary({ refresh: true });
            } catch (error) {
                this.triggerPollStatus = 'error';
                this.triggerPollMessage = error.message || 'Could not trigger polling.';
            } finally {
                this.triggerPollRunning = false;
            }
        },
        
        async fetchDomainSummary(options = {}) {
            const refresh = Boolean(options.refresh);
            this.dashboardLoading = !refresh || !this.hasDomainData;
            this.remediationRefreshRunning = refresh;
            this.dashboardError = '';
            this.dashboardRefreshError = '';
            try {
                const response = await fetch('/api/v1/domains/summary?include_empty=false');
                if (!response.ok) {
                    throw new Error('Dashboard data could not be loaded. Check the API service and try again.');
                }
                const data = await response.json();
                this.domainSummaryLoadedAt = new Date().toISOString();
                this.hiddenEmptyDomainsCount = Number(data.empty_domains_hidden || 0);

                if (data && data.domains && data.domains.length > 0) {
                    this.domains = data.domains || [];
                    this.hasReportData = Number(data.total_reports || 0) > 0 ||
                        Number(data.total_emails || 0) > 0 ||
                        this.domains.some(domain => (
                            Number(domain.total_reports || 0) > 0 || Number(domain.total_emails || 0) > 0
                        ));
                    this.healthSummary = data.health_summary || null;
                    if (!this.domains.some(domain => domain.domain_name === this.selectedDnsDomain)) {
                        this.selectedDnsDomain = this.domains[0]?.domain_name || '';
                    }
                    this.hasDomainData = true;
                    this.updateDashboardStats(data);
                    this.updateEnforcement(data.domains || []);
                    this.populateDomainsTable(data.domains);
                    this.$nextTick(() => {
                        this.updateDnsHealth();
                        this.fetchDashboardStats();
                        this.fetchWorkspaceHealthHistory();
                    });
                } else {
                    this.domains = [];
                    this.healthSummary = null;
                    this.healthHistory = null;
                    this.selectedDnsDomain = '';
                    this.hasDomainData = false;
                    this.hasReportData = false;
                    this.clearDashboardCharts();
                    this.populateChangeSummary([]);
                    this.populateTopSources([]);
                }
            } catch (error) {
                console.error('Error fetching domain summary:', error);
                const message = error.message || 'Dashboard data could not be loaded.';
                if (refresh && this.hasDomainData) {
                    this.dashboardRefreshError = `${message} Showing the previously loaded dashboard data.`;
                    return;
                }
                this.dashboardError = message;
                this.domains = [];
                this.hiddenEmptyDomainsCount = 0;
                this.healthSummary = null;
                this.healthHistory = null;
                this.selectedDnsDomain = '';
                this.hasDomainData = false;
                this.hasReportData = false;
                this.clearDashboardCharts();
                this.populateChangeSummary([]);
                this.populateTopSources([]);
            } finally {
                this.dashboardLoading = false;
                this.remediationRefreshRunning = false;
            }
        },

        async fetchDashboardStats() {
            try {
                const response = await fetch(this.dashboardStatsUrl());
                if (!response.ok) {
                    console.error('Error fetching dashboard stats:', response.status);
                    return;
                }

                const data = await response.json();
                this.updateDashboardStats(data);
                this.updateDateRangeLabel(data.date_range);
                this.renderDashboardCharts(data.compliance_trend || []);
                this.populateChangeSummary(data.change_summary || []);
                this.populateTopSources(data.top_sources || []);
            } catch (error) {
                console.error('Error fetching dashboard stats:', error);
            }
        },

        async fetchWorkspaceHealthHistory() {
            try {
                const response = await fetch(this.workspaceHealthHistoryUrl());
                if (!response.ok) {
                    console.error('Error fetching workspace health history:', response.status);
                    return;
                }
                const data = await response.json();
                this.healthHistory = data;
                this.$nextTick(() => this.renderHealthTrend(data.points || []));
            } catch (error) {
                console.error('Error fetching workspace health history:', error);
            }
        },

        dashboardStatsUrl() {
            const params = new URLSearchParams();
            params.set('interval', this.dateInterval);
            if (this.dateInterval === 'custom') {
                if (this.customStartDate) params.set('start_date', this.customStartDate);
                if (this.customEndDate) params.set('end_date', this.customEndDate);
            }
            return `/api/v1/stats/dashboard?${params.toString()}`;
        },

        workspaceHealthHistoryUrl() {
            const params = new URLSearchParams();
            params.set('limit', '120');
            const range = this.healthHistoryDateRange();
            if (range.start) params.set('start_date', range.start);
            if (range.end) params.set('end_date', range.end);
            return `/api/v1/domains/summary/health/history?${params.toString()}`;
        },

        healthHistoryDateRange() {
            const today = new Date();
            const start = new Date(today);
            if (this.dateInterval === 'custom') {
                return { start: this.customStartDate || '', end: this.customEndDate || '' };
            }
            if (this.dateInterval === 'last_24_hours') {
                start.setDate(today.getDate() - 1);
            } else if (this.dateInterval === 'last_48_hours') {
                start.setDate(today.getDate() - 2);
            } else if (this.dateInterval === 'last_7_days') {
                start.setDate(today.getDate() - 6);
            } else if (this.dateInterval === 'last_90_days') {
                start.setDate(today.getDate() - 89);
            } else if (this.dateInterval === 'week_to_date') {
                const day = today.getDay() || 7;
                start.setDate(today.getDate() - day + 1);
            } else if (this.dateInterval === 'month_to_date') {
                start.setDate(1);
            } else {
                start.setDate(today.getDate() - 29);
            }
            return {
                start: start.toISOString().slice(0, 10),
                end: today.toISOString().slice(0, 10)
            };
        },

        handleDateIntervalChange() {
            if (this.dateInterval !== 'custom') {
                this.fetchDashboardStats();
                this.fetchWorkspaceHealthHistory();
                return;
            }
            if (!this.customEndDate) {
                this.customEndDate = new Date().toISOString().slice(0, 10);
            }
            if (!this.customStartDate) {
                const start = new Date();
                start.setDate(start.getDate() - 6);
                this.customStartDate = start.toISOString().slice(0, 10);
            }
        },

        updateDateRangeLabel(dateRange) {
            if (!dateRange) return;
            const start = dateRange.start_date || '';
            const end = dateRange.end_date || '';
            this.dateRangeLabel = start && end
                ? `${dateRange.label || 'Selected range'} · ${start} to ${end}`
                : (dateRange.label || this.dateRangeLabel);
        },

        updateDashboardStats(data) {
            if (!data) return;
            
            const totalDomains = document.getElementById('total-domains');
            const totalEmails = document.getElementById('total-emails');
            const passRate = document.getElementById('overall-pass-rate');
            const reportsProcessed = document.getElementById('reports-processed');
            
            if (totalDomains) totalDomains.textContent = this.formatLargeNumber(data.total_domains || 0);
            if (totalEmails) totalEmails.textContent = this.formatLargeNumber(data.total_emails || 0);
            const rate = data.overall_pass_rate ?? data.compliance_rate ?? 0;
            if (passRate) passRate.textContent = `${rate}%`;
            if (reportsProcessed) {
                reportsProcessed.textContent = this.formatLargeNumber(data.reports_processed || 0);
            }
        },

        updateEnforcement(domains) {
            const activePolicies = new Set(['quarantine', 'reject']);
            const enforced = domains.filter(domain => {
                return activePolicies.has(String(domain.dmarc_policy || '').toLowerCase());
            }).length;
            const rate = domains.length ? Math.round((enforced / domains.length) * 100) : 0;
            const label = rate === 100 ? 'enforced' : rate > 0 ? 'mixed' : 'monitoring';

            const gauge = document.getElementById('enforcement-gauge');
            const labelEl = document.getElementById('enforcement-label');
            const rateEl = document.getElementById('enforcement-rate');
            const degrees = Math.round((rate / 100) * 360);
            if (gauge) {
                gauge.style.background = `conic-gradient(#2f9da5 0deg, #2f9da5 ${degrees}deg, #e8e8e8 ${degrees}deg, #e8e8e8 360deg)`;
            }
            if (labelEl) labelEl.textContent = label;
            if (rateEl) rateEl.textContent = `${rate}%`;
        },

        updateDnsHealth() {
            const activePolicies = new Set(['quarantine', 'reject']);
            const selected = this.selectedDnsDomainRecord;
            if (!selected) {
                this.setDnsState('dns-spf-state', false);
                this.setDnsState('dns-dkim-state', false);
                this.setDnsState('dns-dmarc-state', false);
                this.setDnsState('dns-policy-state', false);
                return;
            }

            this.setDnsState('dns-spf-state', Boolean(selected.spf_status));
            this.setDnsState('dns-dkim-state', Boolean(selected.dkim_status));
            this.setDnsState('dns-dmarc-state', Boolean(selected.dmarc_status));
            this.setDnsState(
                'dns-policy-state',
                activePolicies.has(String(selected.dmarc_policy || '').toLowerCase())
            );
        },

        setDnsState(id, passing) {
            const el = document.getElementById(id);
            if (!el) return;
            el.textContent = passing ? '✓' : '!';
            el.className = passing ? 'text-emerald-600' : 'text-[#ff6f3c]';
        },

        async fetchForensicSummary() {
            const target = document.getElementById('forensic-summary');
            if (!target) return;
            try {
                const response = await fetch('/api/v1/forensics/analysis?page_size=200');
                if (!response.ok) return;
                const data = await response.json();
                target.textContent = '';
                if (!data.total) {
                    target.textContent = 'No failures';
                    return;
                }

                const wrapper = document.createElement('div');
                wrapper.className = 'w-full space-y-4 text-left';

                const total = document.createElement('p');
                total.className = 'text-5xl font-bold text-[#120d36]';
                total.textContent = data.total;
                wrapper.appendChild(total);

                const label = document.createElement('p');
                label.className = 'text-lg text-[#5f5c78]';
                label.textContent = 'failure samples';
                wrapper.appendChild(label);

                const groups = Object.entries(data.failure_counts || {})
                    .sort(([, leftCount], [, rightCount]) => rightCount - leftCount)
                    .slice(0, 3);
                groups.forEach(([name, count]) => {
                    const row = document.createElement('div');
                    row.className = 'flex items-center justify-between border-t border-[#e6e3e1] pt-3 text-sm';
                    const key = document.createElement('span');
                    key.className = 'uppercase tracking-wide text-[#5f5c78]';
                    key.textContent = name;
                    const value = document.createElement('span');
                    value.className = 'font-semibold text-[#120d36]';
                    value.textContent = count;
                    row.appendChild(key);
                    row.appendChild(value);
                    wrapper.appendChild(row);
                });
                target.appendChild(wrapper);
            } catch (error) {
                console.error('Error fetching forensic summary:', error);
            }
        },

        renderDashboardCharts(trendData) {
            if (!window.Chart || !trendData.length) {
                this.clearDashboardCharts();
                return;
            }

            this.renderVolumeTrend(trendData);
            this.renderComplianceTrend(trendData);
        },

        renderHealthTrend(points) {
            const canvas = document.getElementById('health-trend-chart');
            if (!canvas || !window.Chart) return;
            if (!points.length) {
                if (this.healthTrendChart) {
                    this.healthTrendChart.destroy();
                    this.healthTrendChart = null;
                }
                return;
            }

            if (this.healthTrendChart) {
                this.healthTrendChart.destroy();
            }

            this.healthTrendChart = new Chart(canvas.getContext('2d'), {
                type: 'line',
                data: {
                    labels: points.map(item => item.date),
                    datasets: [
                        {
                            label: 'Health Score',
                            data: points.map(item => item.score || 0),
                            borderColor: '#2f9da5',
                            backgroundColor: 'rgba(47, 157, 165, 0.14)',
                            pointRadius: 0,
                            pointHoverRadius: 4,
                            borderWidth: 3,
                            tension: 0.35,
                            fill: true
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: {
                            min: 0,
                            max: 100,
                            grid: { color: '#dfdfdf' },
                            ticks: { display: false }
                        },
                        x: {
                            grid: { display: false },
                            ticks: { display: false }
                        }
                    },
                    plugins: {
                        legend: { display: false },
                        tooltip: {
                            callbacks: {
                                label: context => `Health Score: ${context.parsed.y}/100`
                            }
                        }
                    }
                }
            });
        },

        renderVolumeTrend(trendData) {
            const canvas = document.getElementById('volume-trend-chart');
            if (!canvas) return;

            const labels = trendData.map(item => item.date);
            const compliant = trendData.map(item => item.passed || 0);
            const failed = trendData.map(item => item.failed || 0);

            if (this.volumeTrendChart) {
                this.volumeTrendChart.destroy();
            }

            this.volumeTrendChart = new Chart(canvas.getContext('2d'), {
                type: 'bar',
                data: {
                    labels,
                    datasets: [
                        {
                            label: 'Non-compliant',
                            data: failed,
                            backgroundColor: '#ff6f3c',
                            borderColor: '#ff6f3c',
                            borderWidth: 1,
                            borderRadius: 2,
                            maxBarThickness: 30,
                            stack: 'volume'
                        },
                        {
                            label: 'Compliant',
                            data: compliant,
                            backgroundColor: '#2f9da5',
                            borderColor: '#2f9da5',
                            borderWidth: 1,
                            borderRadius: 2,
                            maxBarThickness: 30,
                            stack: 'volume'
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: {
                            beginAtZero: true,
                            stacked: true,
                            grid: {
                                color: '#e1dedc'
                            },
                            ticks: {
                                precision: 0,
                                callback: value => this.formatLargeNumber(value)
                            }
                        },
                        x: {
                            stacked: true,
                            grid: {
                                display: false
                            },
                            ticks: {
                                display: false
                            }
                        }
                    },
                    plugins: {
                        legend: {
                            display: false
                        },
                        tooltip: {
                            callbacks: {
                                label: context => `${context.dataset.label}: ${this.formatLargeNumber(context.parsed.y)}`
                            }
                        }
                    }
                }
            });
        },

        renderComplianceTrend(trendData) {
            const canvas = document.getElementById('compliance-trend-chart');
            if (!canvas) return;

            const labels = trendData.map(item => item.date);
            const complianceRates = trendData.map(item => item.compliance_rate ?? item.rate ?? 0);

            if (this.complianceTrendChart) {
                this.complianceTrendChart.destroy();
            }

            this.complianceTrendChart = new Chart(canvas.getContext('2d'), {
                type: 'line',
                data: {
                    labels,
                    datasets: [
                        {
                            label: 'Compliance Rate',
                            data: complianceRates,
                            borderColor: '#171346',
                            backgroundColor: 'rgba(23, 19, 70, 0.12)',
                            pointBackgroundColor: '#171346',
                            pointRadius: 0,
                            pointHoverRadius: 5,
                            borderWidth: 4,
                            tension: 0.42,
                            fill: true
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: {
                            beginAtZero: false,
                            max: 100,
                            grid: {
                                color: '#dfdfdf'
                            },
                            ticks: {
                                display: false,
                                callback: value => `${value}%`
                            }
                        },
                        x: {
                            grid: {
                                display: false
                            },
                            ticks: {
                                display: false
                            }
                        }
                    },
                    plugins: {
                        legend: {
                            display: false
                        },
                        tooltip: {
                            callbacks: {
                                label: context => `${context.dataset.label}: ${context.parsed.y}%`
                            }
                        }
                    }
                }
            });
        },

        clearDashboardCharts() {
            if (this.volumeTrendChart) {
                this.volumeTrendChart.destroy();
                this.volumeTrendChart = null;
            }
            if (this.complianceTrendChart) {
                this.complianceTrendChart.destroy();
                this.complianceTrendChart = null;
            }
            if (this.healthTrendChart) {
                this.healthTrendChart.destroy();
                this.healthTrendChart = null;
            }
        },

        formatLargeNumber(value) {
            return typeof window !== 'undefined' && window.dmarqFormatNumber
                ? window.dmarqFormatNumber(value, { notation: 'compact' })
                : new Intl.NumberFormat().format(value);
        },

        formatScoreDelta(value) {
            if (value === null || value === undefined) return 'No prior score';
            const number = Number(value) || 0;
            if (number === 0) return 'No change';
            return `${number > 0 ? '+' : ''}${number} pts`;
        },

        formatMoney(cents, currency = 'EUR') {
            const locale = typeof window !== 'undefined' ? window.dmarqLocale : 'en';
            return new Intl.NumberFormat(locale || 'en', {
                style: 'currency',
                currency
            }).format((Number(cents) || 0) / 100);
        },

        formatDemoLabel(value) {
            return String(value || '').replaceAll('_', ' ');
        },

        healthDomains() {
            return this.healthSummary?.domains || [];
        },

        remediationTotals() {
            return this.healthSummary?.remediation || {};
        },

        remediationLoop() {
            return this.healthSummary?.remediation_loop || {};
        },

        remediationCompletion() {
            return this.remediationLoop().completion || {};
        },

        pathValue(source, path, fallback = null) {
            const value = String(path || '')
                .split('.')
                .filter(Boolean)
                .reduce((current, key) => (
                    current === null || current === undefined ? undefined : current[key]
                ), source);
            return value === null || value === undefined ? fallback : value;
        },

        dashboardRemediationRawItems() {
            const items = this.remediationLoop().items;
            return Array.isArray(items) ? items : [];
        },

        remediationLoopItems() {
            const items = this.dashboardRemediationRawItems();
            const filtered = items.filter(item =>
                this.dashboardRemediationFilterMatches(item, this.dashboardRemediationFilter)
            );
            return this.sortedDashboardRemediationItems(filtered);
        },

        sortedDashboardRemediationItems(items) {
            const list = Array.isArray(items) ? [...items] : [];
            if (this.dashboardRemediationSort === 'readiness') {
                return list.sort((a, b) => (
                    this.repairReadinessScore(b?.repair_progression) -
                    this.repairReadinessScore(a?.repair_progression) ||
                    this.remediationLoopItemRank(a) - this.remediationLoopItemRank(b) ||
                    (Number(b?.priority_score) || 0) - (Number(a?.priority_score) || 0)
                ));
            }
            if (this.dashboardRemediationSort === 'freshness') {
                return list.sort((a, b) => (
                    this.dashboardRemediationEvidenceRank(a) -
                    this.dashboardRemediationEvidenceRank(b) ||
                    this.remediationLoopItemRank(a) - this.remediationLoopItemRank(b) ||
                    (Number(b?.priority_score) || 0) - (Number(a?.priority_score) || 0)
                ));
            }
            if (this.dashboardRemediationSort === 'severity') {
                return list.sort((a, b) => (
                    this.remediationSeverityWeight(b?.severity) - this.remediationSeverityWeight(a?.severity) ||
                    this.remediationLoopItemRank(a) - this.remediationLoopItemRank(b) ||
                    (Number(b?.priority_score) || 0) - (Number(a?.priority_score) || 0)
                ));
            }
            if (this.dashboardRemediationSort === 'dispatch') {
                const nowMs = Date.now();
                return list.sort((a, b) => (
                    this.dashboardRemediationDispatchRank(a) -
                    this.dashboardRemediationDispatchRank(b) ||
                    this.dashboardRemediationFollowUpAgeMs(b, nowMs) -
                    this.dashboardRemediationFollowUpAgeMs(a, nowMs) ||
                    this.remediationLoopItemRank(a) - this.remediationLoopItemRank(b) ||
                    (Number(b?.priority_score) || 0) - (Number(a?.priority_score) || 0)
                ));
            }
            return Array.isArray(items)
                ? [...items].sort((a, b) => (
                    this.remediationLoopItemRank(a) - this.remediationLoopItemRank(b) ||
                    (Number(b?.priority_score) || 0) - (Number(a?.priority_score) || 0)
                ))
                : [];
        },

        hasRemediationLoopItems() {
            return this.dashboardRemediationRawItems().length > 0;
        },

        hasVisibleDashboardRemediationItems() {
            return this.remediationLoopItems().length > 0;
        },

        visibleDashboardRemediationItems() {
            const items = this.remediationLoopItems();
            return this.showAllDashboardRemediationItems ? items : items.slice(0, 6);
        },

        dashboardRemediationTotalCount() {
            return this.dashboardRemediationRawItems().length;
        },

        dashboardRemediationFilteredCount() {
            return this.remediationLoopItems().length;
        },

        dashboardRemediationHiddenCount() {
            return Math.max(
                this.dashboardRemediationFilteredCount() - this.visibleDashboardRemediationItems().length,
                0
            );
        },

        dashboardRemediationFilterLabel() {
            const match = this.dashboardRemediationFilterOptions.find(
                option => option.value === this.dashboardRemediationFilter
            );
            return match?.label || 'All';
        },

        dashboardRemediationFilterCounts() {
            const items = this.dashboardRemediationRawItems();
            if (this.dashboardRemediationFilterCountCache?.items === items) {
                return this.dashboardRemediationFilterCountCache.counts;
            }
            const counts = Object.fromEntries(
                this.dashboardRemediationFilterOptions.map(option => [option.value, 0])
            );
            items.forEach(item => {
                this.dashboardRemediationFilterOptions.forEach(option => {
                    if (this.dashboardRemediationFilterMatches(item, option.value)) {
                        counts[option.value] += 1;
                    }
                });
            });
            this.dashboardRemediationFilterCountCache = { items, counts };
            return counts;
        },

        dashboardRemediationFilterCount(filter) {
            const counts = this.dashboardRemediationFilterCounts();
            if (Object.prototype.hasOwnProperty.call(counts, filter)) {
                return counts[filter];
            }
            return this.dashboardRemediationRawItems().filter(item =>
                this.dashboardRemediationFilterMatches(item, filter)
            ).length;
        },

        dashboardRemediationFilterClass(filter) {
            if (this.dashboardRemediationFilter === filter) {
                return 'border-[#2f9da5] bg-[#f2fbf9] text-[#1f7c83]';
            }
            if (this.dashboardRemediationFilterCount(filter) === 0 && filter !== 'all') {
                return 'border-[#ece9e7] bg-[#fbfaf9] text-[#9a96a8]';
            }
            return 'border-[#e6e3e1] bg-white text-[#5f5c78] hover:border-[#2f9da5]';
        },

        dashboardRemediationFilterTitle(filter) {
            const label = this.dashboardRemediationFilterOptions.find(
                option => option.value === filter
            )?.label || 'Remediation';
            const count = this.dashboardRemediationFilterCount(filter);
            if (count === 0 && filter !== 'all') {
                return `No ${label.toLowerCase()} remediation cards in the current workspace summary`;
            }
            return `${this.formatLargeNumber(count)} ${label.toLowerCase()} remediation card${count === 1 ? '' : 's'}`;
        },

        dashboardRemediationEmptyStateTitle() {
            const label = this.dashboardRemediationFilterOptions.find(
                option => option.value === this.dashboardRemediationFilter
            )?.label;
            if (!label) return 'No remediation cards';
            return `No ${label.toLowerCase()} remediation cards`;
        },

        dashboardRemediationEmptyStateText() {
            const messages = {
                preview_ready: 'No provider-backed repair preview is ready yet. Check blocked or fresh-evidence work first.',
                fresh_evidence: 'No remediation item currently asks for fresh evidence. Keep importing reports and refresh DNS when new sender or policy data changes.',
                approval_verification: 'No approval verification is pending. Review ready-to-notify or manual work next.',
                provider_apply: 'No provider apply path is ready. Check apply-blocked work or confirm the DNS provider connection first.',
                apply_blocked: 'No provider apply is blocked right now. Provider-backed repairs can continue through preview or approval review.',
                provider_history: 'No provider apply history is attached to the current queue. Apply attempts will appear here after an operator-approved repair flow records them.',
                notify_ready: 'No remediation notification is ready to send. Check dispatch-blocked items or items that still need approval.',
                dispatched: 'No remediation notification has been dispatched for the visible queue yet.',
                follow_up: 'No remediation item is waiting on operator follow-up after dispatch.',
                aging_follow_up: 'No operator follow-up has been waiting longer than 24 hours.',
                dispatch_blocked: 'No remediation notification is blocked by dispatch settings or webhook routing.',
                stuck: 'No stuck remediation work is visible. Provider values, apply prerequisites, and verification blockers are clear for this view.',
                sender_review: 'No sender-classification review is pending in the current workspace summary.',
                report_evidence: 'No item currently needs report evidence. Import or poll DMARC reports when sender activity changes.',
                stale_evidence: 'No stale evidence warning is active for this dashboard filter.',
                blocked: 'No remediation card is blocked by prerequisites in this view.',
                waiting_operator: 'No manual operator decision is waiting in this view.',
                manual: 'No manual repair card is visible in this filter.',
                reputation: 'No source reputation remediation cards are visible in the current workspace summary.'
            };
            return messages[this.dashboardRemediationFilter] ||
                'Choose another queue view or refresh after new evidence is available.';
        },

        resetDashboardRemediationFilter() {
            this.dashboardRemediationFilter = 'all';
            this.dashboardRemediationFilterCountCache = null;
            this.showAllDashboardRemediationItems = false;
        },

        dashboardRemediationEmptyStateMeta() {
            const total = this.dashboardRemediationTotalCount();
            const label = this.dashboardRemediationFilterLabel();
            const verb = total === 1 ? 'exists' : 'exist';
            return `${this.formatLargeNumber(total)} remediation card${total === 1 ? '' : 's'} ${verb} outside the ${label} view.`;
        },

        dashboardRemediationFilterMatches(item, filterValue) {
            if (!item || !filterValue || filterValue === 'all') return true;
            const progression = item?.repair_progression || {};
            const readinessLevel = String(progression.readiness_level || '');
            const stage = String(progression.stage || '');
            const track = String(item?.remediation_track || '');
            const refresh = item?.evidence_refresh || {};
            const refreshKey = String(refresh.refresh_key || '');
            const verificationStatus = String(item?.verification_plan?.status || '');
            if (filterValue === 'preview_ready') {
                return readinessLevel === 'ready_for_preview' || stage === 'preview_ready';
            }
            if (filterValue === 'fresh_evidence') {
                return Boolean(refresh.required) ||
                    Boolean(progression.verification_required) ||
                    Boolean(item?.action_plan?.requires_fresh_evidence);
            }
            if (filterValue === 'approval_verification') {
                return verificationStatus === 'pending_operator_approval' ||
                    (!verificationStatus &&
                        ['approval_ready', 'needs_approval'].includes(String(item?.state || '')));
            }
            if (filterValue === 'provider_apply') {
                return Boolean(progression.provider_apply_after_approval) ||
                    Boolean(progression.provider_preview_available);
            }
            if (filterValue === 'apply_blocked') {
                return Boolean(progression.provider_apply_blocked);
            }
            if (filterValue === 'provider_history') {
                return Number(progression.provider_apply_history || 0) > 0 ||
                    Number(progression.provider_apply_verified || 0) > 0;
            }
            if (filterValue === 'notify_ready') {
                const dispatch = item?.notification?.dispatch;
                const hasDispatchPreview = dispatch && typeof dispatch === 'object';
                if (hasDispatchPreview) return Boolean(dispatch.eligible);
                return ['approval_required', 'action_required', 'investigation_required'].includes(
                    String(item?.notification?.state || '')
                );
            }
            if (filterValue === 'dispatched') {
                const activity = this.dashboardRemediationActivity(item);
                return Number(activity.dispatch_enqueued || 0) > 0 ||
                    Boolean(item?.notification?.dispatch?.delivery_enqueued);
            }
            if (filterValue === 'follow_up') {
                const activity = this.dashboardRemediationActivity(item);
                const dispatch = item?.notification?.dispatch || {};
                return Boolean(activity.needs_operator_follow_up) ||
                    Boolean(dispatch.requires_lifecycle_acknowledgement) ||
                    Boolean(dispatch.operator_hold);
            }
            if (filterValue === 'aging_follow_up') {
                return this.dashboardRemediationFollowUpAgeDays(item) >= 1;
            }
            if (filterValue === 'dispatch_blocked') {
                const dispatch = item?.notification?.dispatch || {};
                return Boolean(dispatch.enabled && !dispatch.eligible) ||
                    (dispatch.blocked_reasons || []).length > 0;
            }
            if (filterValue === 'stuck') {
                return Boolean(this.dashboardRemediationStuckText(item));
            }
            if (filterValue === 'sender_review') {
                return verificationStatus === 'pending_sender_review';
            }
            if (filterValue === 'report_evidence') {
                return verificationStatus === 'pending_report_evidence';
            }
            if (filterValue === 'stale_evidence') {
                return Boolean(this.remediationStaleEvidenceText(item));
            }
            if (filterValue === 'blocked') {
                return readinessLevel === 'blocked' ||
                    stage === 'blocked' ||
                    refresh.safe_to_run === false ||
                    refreshKey === 'provider_value' ||
                    (progression.blocked_by || []).length > 0;
            }
            if (filterValue === 'waiting_operator') {
                return ['manual_action', 'investigate'].includes(String(item?.state || '')) ||
                    readinessLevel === 'needs_operator_review' ||
                    stage === 'operator_review';
            }
            if (filterValue === 'manual') {
                return track === 'manual_dns' ||
                    readinessLevel === 'manual_repair' ||
                    stage === 'manual_repair';
            }
            if (filterValue === 'reputation') {
                return track === 'reputation_review' ||
                    readinessLevel === 'needs_reputation_review' ||
                    stage === 'reputation_review' ||
                    refreshKey === 'source_reputation';
            }
            return true;
        },

        dashboardRemediationActivity(item) {
            const domainName = typeof item === 'string' ? item : item?.domain;
            if (!domainName) return {};
            const domain = this.domains.find(
                entry => entry.domain_name === domainName || entry.id === domainName
            );
            return domain?.remediation || {};
        },

        dashboardRemediationDispatchRank(item) {
            const activity = this.dashboardRemediationActivity(item);
            const dispatch = item?.notification?.dispatch || {};
            if (Boolean(activity.needs_operator_follow_up) || Boolean(dispatch.operator_hold)) return 0;
            if (Number(activity.dispatch_enqueued || 0) > 0 || dispatch.delivery_enqueued) return 1;
            if (dispatch.enabled && !dispatch.eligible) return 2;
            if (dispatch.eligible) return 3;
            return 4;
        },

        dashboardRemediationFollowUpActivity(item) {
            const activity = item?.latest_at
                ? item
                : this.dashboardRemediationActivity(item);
            const dispatch = item?.notification?.dispatch || {};
            const requiresFollowUp = Boolean(activity.needs_operator_follow_up) ||
                Boolean(dispatch.requires_lifecycle_acknowledgement) ||
                Boolean(dispatch.operator_hold);
            return { activity, requiresFollowUp };
        },

        dashboardRemediationFollowUpAgeMs(item, nowMs = Date.now()) {
            const { activity, requiresFollowUp } = this.dashboardRemediationFollowUpActivity(item);
            if (!requiresFollowUp || !activity.latest_at) return 0;
            const timestamp = new Date(activity.latest_at).getTime();
            if (!Number.isFinite(timestamp)) return 0;
            const diffMs = nowMs - timestamp;
            return diffMs > 0 ? diffMs : 0;
        },

        dashboardRemediationDispatchText(item) {
            const activity = this.dashboardRemediationActivity(item);
            const dispatch = item?.notification?.dispatch || {};
            const parts = [];
            const dispatched = Number(activity.dispatch_enqueued || 0);
            if (dispatched) {
                parts.push(`${this.formatLargeNumber(dispatched)} notification${dispatched === 1 ? '' : 's'} dispatched`);
            }
            if (activity.needs_operator_follow_up || dispatch.requires_lifecycle_acknowledgement) {
                parts.push('operator follow-up needed');
            }
            if (dispatch.eligible) {
                parts.push('ready to notify');
            } else if (dispatch.enabled && (dispatch.blocked_reasons || []).length) {
                parts.push('dispatch blocked');
            } else if (['approval_required', 'action_required', 'investigation_required'].includes(
                String(item?.notification?.state || '')
            )) {
                parts.push('notification profile ready');
            }
            return parts.join(' · ');
        },

        relativeAgeText(value) {
            if (!value) return '';
            const timestamp = new Date(value).getTime();
            if (!Number.isFinite(timestamp)) return '';
            const diffMs = Date.now() - timestamp;
            if (diffMs < 0) return '';
            const minutes = Math.floor(diffMs / 60000);
            if (minutes < 1) return 'just now';
            if (minutes < 60) return `${minutes} minute${minutes === 1 ? '' : 's'} ago`;
            const hours = Math.floor(minutes / 60);
            if (hours < 24) return `${hours} hour${hours === 1 ? '' : 's'} ago`;
            const days = Math.floor(hours / 24);
            if (days < 30) return `${days} day${days === 1 ? '' : 's'} ago`;
            const months = Math.floor(days / 30);
            if (months < 12) return `${months} month${months === 1 ? '' : 's'} ago`;
            const years = Math.floor(months / 12);
            return `${years} year${years === 1 ? '' : 's'} ago`;
        },

        ageDays(value) {
            if (!value) return -1;
            const timestamp = new Date(value).getTime();
            if (!Number.isFinite(timestamp)) return -1;
            const diffMs = Date.now() - timestamp;
            if (diffMs < 0) return -1;
            return Math.floor(diffMs / (24 * 60 * 60 * 1000));
        },

        dashboardRemediationFollowUpAgeText(item) {
            const { activity, requiresFollowUp } = this.dashboardRemediationFollowUpActivity(item);
            if (!requiresFollowUp) return '';
            const age = this.relativeAgeText(activity.latest_at);
            return age ? `Follow-up waiting since ${age}` : 'Follow-up is waiting for operator review';
        },

        dashboardRemediationFollowUpAgeDays(item) {
            const { activity, requiresFollowUp } = this.dashboardRemediationFollowUpActivity(item);
            return requiresFollowUp ? this.ageDays(activity.latest_at) : -1;
        },

        dashboardRemediationFollowUpAgeClass(item) {
            const days = this.dashboardRemediationFollowUpAgeDays(item);
            if (days >= 7) return 'border-[#ffcfbd] bg-[#fff2ec] text-[#8a2d0d]';
            return 'border-[#f5dfbd] bg-[#fff8ed] text-[#7a4a00]';
        },

        dashboardRemediationNextActionText(item) {
            if (!item) return 'Open the remediation queue to review the next safe action.';
            const refresh = item.evidence_refresh || {};
            const progression = item.repair_progression || {};
            const verification = item.verification_plan || {};
            if (refresh.safe_to_run === false || refresh.refresh_key === 'provider_value') {
                return refresh.recommended_action || 'Add the missing provider value before this repair can continue.';
            }
            if (refresh.required) {
                return refresh.recommended_action || this.evidenceRefreshLabel(refresh);
            }
            if (progression.next_safe_action) return progression.next_safe_action;
            if (progression.next_step) return progression.next_step;
            if (verification.next_check) return verification.next_check;
            return item.next_step || 'Open the remediation queue to review the next safe action.';
        },

        dashboardRemediationStuckText(item) {
            if (!item) return '';
            const refresh = item.evidence_refresh || {};
            const dispatch = item.notification?.dispatch || {};
            const progression = item.repair_progression || {};
            const verificationStatus = String(item.verification_plan?.status || '');
            const blockers = progression.blocked_by || [];
            if (refresh.safe_to_run === false || refresh.refresh_key === 'provider_value') {
                return 'Waiting on a provider value before DMARQ can refresh or prepare the repair.';
            }
            if (Boolean(progression.provider_apply_blocked)) {
                return 'Provider apply is blocked until prerequisites are complete.';
            }
            if (dispatch.enabled && !dispatch.eligible) {
                return 'Notification dispatch is blocked by settings, acknowledgement, or route availability.';
            }
            if ((dispatch.blocked_reasons || []).length) {
                return `Dispatch blocked: ${dispatch.blocked_reasons.slice(0, 2).join(', ')}.`;
            }
            if (blockers.length) {
                return `Repair blocked by ${blockers.slice(0, 2).map(value => this.formatDemoLabel(value)).join(', ')}.`;
            }
            if (verificationStatus === 'blocked_by_prerequisite') {
                return 'Verification is blocked by a missing prerequisite.';
            }
            return '';
        },

        remediationLoopItemRank(item) {
            const progression = item?.repair_progression || {};
            const readinessLevel = String(progression.readiness_level || '');
            const stage = String(progression.stage || '');
            const state = String(item?.state || '');
            const track = String(item?.remediation_track || '');
            if (readinessLevel === 'ready_for_preview' || stage === 'preview_ready') return 0;
            if (state === 'approval_ready' || state === 'needs_approval') return 1;
            if (readinessLevel === 'blocked' || stage === 'blocked') return 2;
            if (readinessLevel === 'needs_reputation_review' || track === 'reputation_review') return 3;
            if (state === 'investigate') return 4;
            if (readinessLevel === 'manual_repair' || track === 'manual_dns' || state === 'manual_action') return 5;
            return 6;
        },

        dashboardRemediationEvidenceRank(item) {
            const refresh = item?.evidence_refresh || {};
            const key = String(refresh.refresh_key || '');
            if (refresh.safe_to_run === false || key === 'provider_value') return 0;
            if (refresh.required && key === 'dns') return 1;
            if (refresh.required && key === 'source_reputation') return 2;
            if (refresh.required) return 3;
            return 4;
        },

        remediationSeverityWeight(severity) {
            return {
                critical: 5,
                high: 4,
                error: 4,
                medium: 3,
                warning: 3,
                low: 2,
                info: 1
            }[String(severity || '').toLowerCase()] || 0;
        },

        remediationStaleEvidenceText(item) {
            return item?.evidence_refresh?.stale_warning ||
                item?.verification_plan?.stale_evidence_warning ||
                '';
        },

        verificationPlanStatusLabel(plan) {
            const status = typeof plan === 'string' ? plan : plan?.status;
            return {
                pending_operator_approval: 'Needs approval',
                pending_sender_review: 'Sender review',
                pending_reputation_review: 'Reputation review',
                pending_report_evidence: 'Fresh evidence',
                blocked_by_prerequisite: 'Blocked'
            }[String(status || '')] || 'Verification needed';
        },

        verificationPlanStatusClass(plan) {
            const status = typeof plan === 'string' ? plan : plan?.status;
            return {
                pending_operator_approval: 'bg-[#edf7f7] text-[#247982]',
                pending_sender_review: 'bg-blue-100 text-blue-700',
                pending_reputation_review: 'bg-purple-100 text-purple-700',
                pending_report_evidence: 'bg-yellow-100 text-yellow-800',
                blocked_by_prerequisite: 'bg-red-100 text-red-700'
            }[String(status || '')] || 'bg-[#f8f7f6] text-[#5f5c78]';
        },

        verificationPlanFailureMode(plan) {
            return plan?.failure_mode || 'Keep this open until fresh evidence confirms the finding is gone.';
        },

        verificationPlanEvidenceNeededText(plan) {
            const evidence = plan?.evidence_needed || [];
            if (Array.isArray(evidence) && evidence.length) {
                return evidence.slice(0, 3).join(' · ');
            }
            return 'Fresh DNS, report, or source evidence.';
        },

        remediationLoopStatusLabel(status) {
            return {
                clear: 'Clear',
                needs_attention: 'Needs attention',
                approval_required: 'Approval required',
                manual_action_required: 'Manual action required',
                investigation_required: 'Investigation required'
            }[String(status || '')] || 'Review';
        },

        remediationLoopStatusClass(status) {
            return {
                clear: 'bg-green-100 text-green-700',
                needs_attention: 'bg-yellow-100 text-yellow-800',
                approval_required: 'bg-[#edf7f7] text-[#247982]',
                manual_action_required: 'bg-[#fff7df] text-[#8a6418]',
                investigation_required: 'bg-[#fff1ea] text-[#b8431d]'
            }[String(status || '')] || 'bg-[#f8f7f6] text-[#5f5c78]';
        },

        remediationCompletionLabel(completion) {
            if (!completion) return 'Completion unknown';
            if (completion.ready_to_close_parent_issue) return 'Completion gates ready';
            const remaining = Number(completion.remaining_slices || 0);
            return `${remaining} completion gate${remaining === 1 ? '' : 's'} open`;
        },

        remediationCompletionClass(completion) {
            if (completion?.ready_to_close_parent_issue) return 'bg-green-100 text-green-700';
            return 'bg-[#fff7df] text-[#8a6418]';
        },

        remediationLoopEffectiveStatus(loop) {
            if (!loop) return '';
            const status = String(loop.status || '');
            const loopStatus = String(loop.loop_status || '');
            return status === 'needs_attention' && loopStatus ? loopStatus : (status || loopStatus);
        },

        remediationIncidentLabel(value) {
            return this.formatDemoLabel(value || 'none');
        },

        remediationLoopStateLabel(state) {
            return {
                approval_ready: 'Needs approval',
                needs_approval: 'Needs approval',
                manual_action: 'Manual action',
                investigate: 'Investigate'
            }[String(state || '')] || 'Review';
        },

        remediationLoopStateClass(state) {
            return {
                approval_ready: 'bg-[#edf7f7] text-[#247982]',
                needs_approval: 'bg-[#edf7f7] text-[#247982]',
                manual_action: 'bg-[#fff7df] text-[#8a6418]',
                investigate: 'bg-[#fff1ea] text-[#b8431d]'
            }[String(state || '')] || 'bg-[#f8f7f6] text-[#5f5c78]';
        },

        remediationRiskClass(risk) {
            return {
                high: 'bg-red-100 text-red-700',
                medium: 'bg-yellow-100 text-yellow-800',
                low: 'bg-green-100 text-green-700'
            }[String(risk || '').toLowerCase()] || 'bg-[#f8f7f6] text-[#5f5c78]';
        },

        remediationTrackLabel(track) {
            return {
                provider_preview: 'Provider preview',
                manual_dns: 'Manual DNS',
                sender_investigation: 'Sender investigation',
                reputation_review: 'Reputation review',
                self_hosted_or_provider: 'Provider or self-hosted'
            }[String(track || '')] || 'Manual review';
        },

        repairProgressionClass(progression) {
            const stage = String(progression?.stage || '');
            if (stage === 'preview_ready') return 'bg-green-100 text-green-700';
            if (stage === 'blocked') return 'bg-red-100 text-red-700';
            if (stage === 'classification_required') return 'bg-blue-100 text-blue-700';
            if (stage === 'manual_repair') return 'bg-yellow-100 text-yellow-800';
            if (stage === 'reputation_review') return 'bg-purple-100 text-purple-700';
            return 'bg-[#f8f7f6] text-[#5f5c78]';
        },

        repairProgressionLabel(progression) {
            if (!progression) return 'Operator review';
            return progression.label || this.formatDemoLabel(progression.stage || 'operator_review');
        },

        repairProgressionNextStep(progression) {
            if (!progression) return 'Open the remediation queue to review the next safe gate.';
            return progression.next_step || progression.summary || 'Open the remediation queue to review the next safe gate.';
        },

        repairProgressionNextSafeAction(progression) {
            if (!progression) return 'Open the remediation queue to review the next safe action.';
            return progression.next_safe_action || this.repairProgressionNextStep(progression);
        },

        repairReadinessReason(progression) {
            const reasons = progression?.readiness_reasons || [];
            return reasons[0] || 'Review the current remediation evidence before opening, dispatching, or closing this item.';
        },

        repairReadinessBlockedText(progression) {
            const blockedBy = progression?.blocked_by || [];
            if (!blockedBy.length) return '';
            const labels = blockedBy.slice(0, 3).map(value => this.formatDemoLabel(value));
            return `Blocked by ${labels.join(', ')}.`;
        },

        repairReadinessClass(progression) {
            const level = String(progression?.readiness_level || '');
            if (level === 'ready_for_preview') return 'bg-green-100 text-green-700';
            if (level === 'blocked') return 'bg-red-100 text-red-700';
            if (level === 'needs_classification') return 'bg-blue-100 text-blue-700';
            if (level === 'needs_reputation_review') return 'bg-purple-100 text-purple-700';
            if (level === 'manual_repair') return 'bg-yellow-100 text-yellow-800';
            return 'bg-[#f8f7f6] text-[#5f5c78]';
        },

        repairReadinessLabel(progression) {
            if (!progression) return 'Needs operator review';
            return progression.readiness_label || this.formatDemoLabel(progression.readiness_level || 'needs_operator_review');
        },

        repairReadinessScore(progression) {
            const score = Number(progression?.readiness_score || 0);
            return Number.isFinite(score) ? Math.max(0, Math.min(100, Math.round(score))) : 0;
        },

        evidenceRefreshLabel(refresh) {
            const key = String(refresh?.refresh_key || refresh?.source || '');
            return {
                dns: 'Refresh DNS evidence',
                reports: 'Refresh report evidence',
                reports_and_sources: 'Refresh report and source evidence',
                source_reputation: 'Refresh source reputation',
                provider_value: 'Provider value required'
            }[key] || 'Refresh evidence';
        },

        evidenceRefreshClass(refresh) {
            const key = String(refresh?.refresh_key || '');
            if (refresh?.safe_to_run === false || key === 'provider_value') return 'bg-red-100 text-red-700';
            if (key === 'dns') return 'bg-blue-100 text-blue-700';
            if (key === 'source_reputation') return 'bg-purple-100 text-purple-700';
            if (key === 'reports_and_sources') return 'bg-green-100 text-green-700';
            return 'bg-white text-[#5f5c78]';
        },

        domainActionHref(action) {
            return action && action.domain
                ? `/domains/${encodeURIComponent(action.domain)}#remediation-queue`
                : '/domains';
        },

        domainRemediationHref(domainName) {
            return domainName
                ? `/domains/${encodeURIComponent(domainName)}#remediation-queue`
                : '/domains';
        },

        domainEvidenceHref(item) {
            const domainName = item?.domain || '';
            const rawAnchor = String(item?.evidence_refresh?.ui_anchor || '#remediation-queue');
            const anchor = rawAnchor.startsWith('#') ? rawAnchor : '#remediation-queue';
            return domainName
                ? `/domains/${encodeURIComponent(domainName)}${anchor}`
                : '/domains';
        },

        domainHealthHref(domainHealth) {
            return domainHealth && domainHealth.domain
                ? `/domains/${encodeURIComponent(domainHealth.domain)}`
                : '/domains';
        },

        domainRemediation(domainName) {
            return this.domainByName(domainName)?.remediation || {};
        },

        domainRemediationStatus(domainName) {
            return this.domainRemediation(domainName).status || 'none';
        },

        hasDomainRemediation(domainName) {
            return this.domainRemediationStatus(domainName) !== 'none';
        },

        remediationStatusLabel(status) {
            return {
                resolved: 'Resolved',
                dispatched: 'Dispatched',
                reviewed: 'Reviewed',
                operator_hold: 'Operator hold',
                activity: 'Activity',
                none: 'No activity'
            }[String(status || 'none')] || 'Activity';
        },

        remediationStatusClass(status) {
            return {
                resolved: 'text-[#247982]',
                dispatched: 'text-[#8a6418]',
                reviewed: 'text-[#272a5f]',
                operator_hold: 'text-[#b8431d]',
                activity: 'text-[#5f5c78]',
                none: 'text-[#5f5c78]'
            }[String(status || 'none')] || 'text-[#5f5c78]';
        },

        gradeClass(grade) {
            const value = String(grade || 'F');
            if (value.startsWith('A')) return 'bg-[#dff3e8] text-[#1f6f45]';
            if (value.startsWith('B')) return 'bg-[#edf7f7] text-[#247982]';
            if (value.startsWith('C')) return 'bg-[#fff7df] text-[#8a6418]';
            if (value.startsWith('D')) return 'bg-[#fff1ea] text-[#b8431d]';
            return 'bg-[#ffe8e8] text-[#9f2525]';
        },

        severityClass(severity) {
            const value = String(severity || '').toLowerCase();
            if (value === 'critical') return 'text-[#9f2525]';
            if (value === 'high') return 'text-[#b8431d]';
            if (value === 'medium') return 'text-[#8a6418]';
            return 'text-[#247982]';
        },

        severityDotClass(severity) {
            const value = String(severity || '').toLowerCase();
            if (value === 'critical') return 'bg-[#9f2525]';
            if (value === 'high') return 'bg-[#b8431d]';
            if (value === 'medium') return 'bg-[#c28a18]';
            return 'bg-[#2f9da5]';
        },

        demoOrganizations() {
            return this.demoDeployment?.organizations || [];
        },

        visibleDemoOrganizations() {
            const scenario = this.selectedDemoScenario();
            const visible = scenario?.visible_organizations || [];
            if (!visible.length) return this.demoOrganizations();
            return this.demoOrganizations().filter(organization => visible.includes(organization.slug));
        },

        demoScenarios() {
            return this.demoDeployment?.viewer_scenarios || [];
        },

        demoZoomLevels() {
            return this.demoDeployment?.zoom_levels || [];
        },

        demoDomainShowcase() {
            return this.demoDeployment?.domain_showcase || [];
        },

        demoJourneySteps() {
            return this.demoDeployment?.journey_steps || [];
        },

        selectedDemoScenario() {
            const scenarios = this.demoScenarios();
            return scenarios.find(scenario => (scenario.id || scenario.label) === this.selectedDemoScenarioId)
                || scenarios[0]
                || null;
        },

        selectedDemoScenarioDescription() {
            const scenario = this.selectedDemoScenario();
            const level = this.demoZoomLevels().find(item => item.level === this.selectedDemoZoomLevel);
            if (!scenario && !level) return 'Explore generated DMARQ demo data.';
            const scope = level?.description || '';
            const workspace = scenario?.default_workspace
                ? ` Default workspace: ${this.formatDemoLabel(scenario.default_workspace)}.`
                : '';
            return `${scope}${workspace}`.trim();
        },

        demoSessionLabel() {
            const organization = this.selectedDemoOrganization();
            const workspace = this.selectedDemoWorkspace();
            const parts = [
                organization?.name,
                workspace?.name,
                this.formatDemoLabel(this.selectedDemoZoomLevel)
            ].filter(Boolean);
            return parts.join(' / ') || 'Demo scope';
        },

        demoImpersonationNotice() {
            const user = this.selectedDemoUser();
            if (!user) return '';
            const auditLabel = this.demoDeployment?.impersonation_policy?.audit_label
                || 'audit log entry';
            return `Viewing as ${user.name}; demo impersonation creates an ${auditLabel} in production.`;
        },

        selectDemoZoomLevel(level) {
            this.selectedDemoZoomLevel = level || 'workspace';
            if (level === 'provider') {
                const providerScenario = this.demoScenarios().find(scenario => scenario.zoom_level === 'provider');
                if (providerScenario) {
                    this.selectedDemoScenarioId = providerScenario.id || providerScenario.label;
                    this.applyDemoScenario();
                }
            }
        },

        selectDemoJourneyStep(step) {
            if (!step) return;
            this.selectedDemoScenarioId = step.scenario_id || this.selectedDemoScenarioId;
            this.selectedDemoZoomLevel = step.zoom_level || this.selectedDemoZoomLevel || 'workspace';
            this.applyDemoScenario();
            if (step.organization_slug) {
                this.selectDemoOrganization(step.organization_slug, { preserveUser: true });
            }
            const scenario = this.selectedDemoScenario();
            const user = this.selectedDemoOrganizationUsers()
                .find(candidate => candidate.email === scenario?.email)
                || this.selectedDemoOrganizationUsers()[0];
            this.selectedDemoUserEmail = user?.email || '';
            if (step.workspace_slug) {
                this.selectDemoWorkspace(step.workspace_slug);
            }
            if (step.domain && this.domains.some(domain => domain.domain_name === step.domain)) {
                this.selectedDnsDomain = step.domain;
                this.updateDnsHealth();
            }
        },

        applyDemoScenario() {
            const scenario = this.selectedDemoScenario();
            if (!scenario) {
                this.selectedDemoOrganizationSlug = this.demoOrganizations()[0]?.slug || '';
                this.selectedDemoUserEmail = '';
                return;
            }
            this.selectedDemoZoomLevel = scenario.zoom_level || this.selectedDemoZoomLevel || 'workspace';
            const organizationSlug = scenario.visible_organizations?.[0] || this.demoOrganizations()[0]?.slug || '';
            this.selectDemoOrganization(organizationSlug, { preserveUser: true });
            const user = this.selectedDemoOrganizationUsers()
                .find(candidate => candidate.email === scenario.email)
                || this.selectedDemoOrganizationUsers()[0];
            this.selectedDemoUserEmail = user?.email || '';
            if (scenario.default_workspace) {
                this.selectDemoWorkspace(scenario.default_workspace);
            }
            if (scenario.default_domain && this.domains.some(domain => domain.domain_name === scenario.default_domain)) {
                this.selectedDnsDomain = scenario.default_domain;
                this.updateDnsHealth();
            }
        },

        selectDemoOrganization(slug, options = {}) {
            this.selectedDemoOrganizationSlug = slug || this.visibleDemoOrganizations()[0]?.slug || '';
            const users = this.selectedDemoOrganizationUsers();
            if (!options.preserveUser || !users.some(user => user.email === this.selectedDemoUserEmail)) {
                this.selectedDemoUserEmail = users[0]?.email || '';
            }
            const visibleWorkspaces = this.selectedDemoVisibleWorkspaces();
            if (!visibleWorkspaces.some(workspace => workspace.slug === this.selectedDemoWorkspaceSlug)) {
                this.selectedDemoWorkspaceSlug = visibleWorkspaces[0]?.slug || '';
            }
        },

        selectDemoWorkspace(slug) {
            const workspaces = this.selectedDemoVisibleWorkspaces();
            const workspace = workspaces.find(item => item.slug === slug) || workspaces[0] || null;
            this.selectedDemoWorkspaceSlug = workspace?.slug || '';
            const firstDomain = workspace?.domains?.[0];
            if (firstDomain && this.hasLiveDomain(firstDomain)) {
                this.selectedDnsDomain = firstDomain;
                this.updateDnsHealth();
                return;
            }
            this.selectedDnsDomain = '';
        },

        selectedDemoOrganization() {
            return this.demoOrganizations().find(
                organization => organization.slug === this.selectedDemoOrganizationSlug
            ) || this.visibleDemoOrganizations()[0] || null;
        },

        selectedDemoOrganizationUsers() {
            return this.selectedDemoOrganization()?.users || [];
        },

        selectedDemoUser() {
            return this.selectedDemoOrganizationUsers().find(user => user.email === this.selectedDemoUserEmail)
                || this.selectedDemoOrganizationUsers()[0]
                || null;
        },

        selectedDemoVisibleWorkspaces() {
            const organization = this.selectedDemoOrganization();
            const user = this.selectedDemoUser();
            if (!organization) return [];
            const workspaces = organization.workspaces || [];
            const userWorkspaces = user?.workspaces || [];
            if (!user || !userWorkspaces.length) return workspaces;
            return workspaces.filter(workspace => userWorkspaces.includes(workspace.slug));
        },

        selectedDemoWorkspace() {
            const visible = this.selectedDemoVisibleWorkspaces();
            return visible.find(workspace => workspace.slug === this.selectedDemoWorkspaceSlug)
                || visible[0]
                || null;
        },

        selectedDemoWorkspaceDomains() {
            return this.selectedDemoWorkspace()?.domains || [];
        },

        selectedDemoWorkspaceFindings() {
            return this.selectedDemoWorkspace()?.primary_findings || [];
        },

        domainByName(domainName) {
            return this.domains.find(domain => domain.domain_name === domainName) || null;
        },

        hasLiveDomain(domainName) {
            return Boolean(this.domainByName(domainName));
        },

        domainHrefByName(domainName) {
            const domain = this.domainByName(domainName);
            return domain ? this.domainHref(domain) : '#';
        },

        applyDemoUserSelection() {
            const user = this.selectedDemoUser();
            const firstWorkspace = this.selectedDemoVisibleWorkspaces()[0];
            this.selectDemoWorkspace(firstWorkspace?.slug);
            if (user?.demo_persona) {
                const matchingScenario = this.demoScenarios().find(
                    scenario => scenario.email === user.email || scenario.id === user.demo_persona
                );
                if (matchingScenario) {
                    this.selectedDemoScenarioId = matchingScenario.id || matchingScenario.label;
                    this.selectedDemoZoomLevel = matchingScenario.zoom_level || this.selectedDemoZoomLevel;
                }
            }
        },

        impersonateFirstDemoUser(slug) {
            this.selectDemoOrganization(slug);
            this.selectedDemoUserEmail = this.selectedDemoOrganizationUsers()[0]?.email || '';
            this.applyDemoUserSelection();
        },

        selectDemoProviderCustomer(customer) {
            const organization = this.selectedDemoOrganization();
            if (!organization || !customer) return;
            const workspace = (organization.workspaces || []).find(
                item => item.slug === customer.workspace_slug
            );
            const customerUser = (organization.users || []).find(user =>
                (user.workspaces || []).includes(customer.workspace_slug)
            );
            if (customerUser) {
                this.selectedDemoUserEmail = customerUser.email;
            }
            this.selectDemoWorkspace(workspace?.slug);
        },

        demoWorkspaceTotal() {
            return this.visibleDemoOrganizations().reduce(
                (total, organization) => total + (organization.workspaces?.length || 0),
                0
            );
        },

        demoUserTotal() {
            return this.visibleDemoOrganizations().reduce(
                (total, organization) => total + (organization.users?.length || 0),
                0
            );
        },

        demoMonthlyTotal() {
            return this.visibleDemoOrganizations().reduce(
                (total, organization) => total + (organization.billing?.current_period_total_cents || 0),
                0
            );
        },

        demoRoleSummary(organization) {
            const roles = new Set();
            (organization.users || []).forEach(user => {
                (user.roles || []).forEach(role => roles.add(role));
            });
            return Array.from(roles).sort();
        },

        formatDemoUsage(organization, usage) {
            const entitlement = organization.entitlements?.[usage.metric];
            const used = this.formatLargeNumber(usage.quantity || 0);
            const limit = entitlement?.included !== undefined && entitlement?.included !== null
                ? ` / ${this.formatLargeNumber(entitlement.included)}`
                : '';
            return `${this.formatDemoLabel(usage.metric)} ${used}${limit} ${usage.unit || ''}`.trim();
        },

        startDemoTour() {
            this.demoTourActive = true;
            this.demoTourStepIndex = 0;
            this.activateDemoTourStep();
        },

        closeDemoTour() {
            this.demoTourActive = false;
            this.clearDemoTourTarget();
        },

        currentDemoTourStep() {
            return this.demoTourSteps[this.demoTourStepIndex] || this.demoTourSteps[0] || null;
        },

        nextDemoTourStep() {
            if (this.demoTourStepIndex + 1 >= this.demoTourSteps.length) {
                this.closeDemoTour();
                return;
            }
            this.demoTourStepIndex += 1;
            this.activateDemoTourStep();
        },

        previousDemoTourStep() {
            if (this.demoTourStepIndex === 0) return;
            this.demoTourStepIndex -= 1;
            this.activateDemoTourStep();
        },

        activateDemoTourStep() {
            this.clearDemoTourTarget();
            const step = this.currentDemoTourStep();
            if (!step?.selector) return;
            this.ensureTourTargetVisible(step.selector);
            this.$nextTick(() => {
                const target = document.querySelector(step.selector);
                if (!target) return;
                target.classList.add('dmarq-tour-target');
                target.style.position = target.style.position || 'relative';
                target.style.zIndex = '60';
                target.style.boxShadow = '0 0 0 4px rgba(47, 157, 165, 0.35)';
            });
        },

        clearDemoTourTarget() {
            document.querySelectorAll('.dmarq-tour-target').forEach(target => {
                target.classList.remove('dmarq-tour-target');
                target.style.zIndex = '';
                target.style.boxShadow = '';
            });
        },

        ensureTourTargetVisible(selector) {
            this.$nextTick(() => {
                const target = document.querySelector(selector);
                if (!target) return;
                target.scrollIntoView({ behavior: 'smooth', block: 'center' });
            });
        },

        domainHref(domain) {
            const value = domain?.id ?? domain?.domain_name ?? domain;
            return value ? `/domains/${encodeURIComponent(String(value))}` : '/domains';
        },

        changeHref(change) {
            if (change?.domain) return `/domains/${encodeURIComponent(String(change.domain))}`;
            return '/reports';
        },

        populateChangeSummary(changes) {
            const list = document.getElementById('change-summary-list');
            if (!list) return;

            list.textContent = '';

            if (!changes || !changes.length) {
                const empty = document.createElement('p');
                empty.className = 'text-sm text-muted-foreground';
                empty.textContent = 'No major sender or compliance changes detected.';
                list.appendChild(empty);
                return;
            }

            changes.forEach(change => {
                const item = document.createElement('a');
                item.href = this.changeHref(change);
                item.className = 'block rounded-md border border-[#e6e3e1] bg-white p-3 transition hover:border-[#2f9da5] hover:shadow-sm';

                const header = document.createElement('div');
                header.className = 'flex items-start gap-2';

                const dot = document.createElement('span');
                dot.className = `mt-1 inline-flex h-2.5 w-2.5 flex-none rounded-full ${this.changeSeverityClass(change.severity)}`;
                header.appendChild(dot);

                const content = document.createElement('div');
                content.className = 'min-w-0';

                const title = document.createElement('p');
                title.className = 'text-sm font-semibold text-[#07071f]';
                title.textContent = change.title || 'Change detected';
                content.appendChild(title);

                const detail = document.createElement('p');
                detail.className = 'mt-1 text-sm text-[#5f5c78]';
                detail.textContent = change.detail || '';
                content.appendChild(detail);

                const action = document.createElement('p');
                action.className = 'mt-2 text-sm font-semibold text-[#2f9da5]';
                action.textContent = change.action || '';
                content.appendChild(action);

                header.appendChild(content);
                item.appendChild(header);
                list.appendChild(item);
            });
        },

        changeSeverityClass(severity) {
            if (severity === 'error') return 'bg-red-500';
            if (severity === 'warning') return 'bg-yellow-500';
            return 'bg-blue-500';
        },

        populateTopSources(sources) {
            const tableBody = document.getElementById('top-sources-table-body');
            const sourceList = document.getElementById('top-sources-list');

            if (sourceList) {
                this.populateTopSourcesList(sourceList, sources || []);
            }

            if (!tableBody) return;

            tableBody.textContent = '';

            if (!sources || !sources.length) {
                const emptyRow = document.createElement('tr');
                emptyRow.className = 'table-row';
                const emptyCell = document.createElement('td');
                emptyCell.className = 'table-cell text-muted-foreground';
                emptyCell.colSpan = 5;
                emptyCell.textContent = 'No sending source data available';
                emptyRow.appendChild(emptyCell);
                tableBody.appendChild(emptyRow);
                return;
            }

            sources.forEach(source => {
                const row = document.createElement('tr');
                row.className = 'table-row';

                row.appendChild(this.createTextCell(source.ip || 'Unknown', 'font-mono text-sm'));
                row.appendChild(this.createTextCell(this.formatLargeNumber(source.count || 0)));
                row.appendChild(this.createAuthCell(
                    source.dmarc,
                    source.dmarc_pass_count || 0,
                    source.dmarc_fail_count || 0
                ));
                row.appendChild(this.createAuthCell(
                    source.spf,
                    source.spf_pass_count || 0,
                    source.spf_fail_count || 0
                ));
                row.appendChild(this.createAuthCell(
                    source.dkim,
                    source.dkim_pass_count || 0,
                    source.dkim_fail_count || 0
                ));

                tableBody.appendChild(row);
            });
        },

        populateTopSourcesList(sourceList, sources) {
            sourceList.textContent = '';

            if (!sources.length) {
                const empty = document.createElement('p');
                empty.className = 'text-lg text-[#5f5c78]';
                empty.textContent = 'No sending source data available';
                sourceList.appendChild(empty);
                return;
            }

            const total = sources.reduce((sum, source) => sum + (source.count || 0), 0) || 1;
            const colors = ['#2f9da5', '#ff6f3c', '#2f9da5', '#272a5f'];

            sources.slice(0, 4).forEach((source, index) => {
                const percentage = Math.max(1, Math.round(((source.count || 0) / total) * 100));
                const item = document.createElement('a');
                item.href = '/reports';
                item.className = 'block space-y-2 rounded-md border border-transparent p-2 -mx-2 transition hover:border-[#e6e3e1] hover:bg-[#f4f3f2]';

                const row = document.createElement('div');
                row.className = 'flex items-center justify-between gap-3 text-lg';

                const label = document.createElement('span');
                label.className = 'min-w-0 truncate';
                label.textContent = source.ip || 'Unknown';
                row.appendChild(label);

                const value = document.createElement('span');
                value.className = 'font-semibold';
                value.textContent = `${percentage}%`;
                row.appendChild(value);

                const track = document.createElement('div');
                track.className = 'h-3 overflow-hidden rounded bg-[#e6e6e8]';
                const bar = document.createElement('div');
                bar.className = 'h-full rounded';
                bar.style.width = `${percentage}%`;
                bar.style.backgroundColor = colors[index % colors.length];
                track.appendChild(bar);

                item.appendChild(row);
                item.appendChild(track);
                sourceList.appendChild(item);
            });
        },

        createTextCell(value, innerClass = '') {
            const cell = document.createElement('td');
            cell.className = 'table-cell';
            const content = document.createElement('span');
            if (innerClass) content.className = innerClass;
            content.textContent = value;
            cell.appendChild(content);
            return cell;
        },

        createAuthCell(status, passCount, failCount) {
            const cell = document.createElement('td');
            cell.className = 'table-cell';

            const wrapper = document.createElement('div');
            wrapper.className = 'flex flex-col gap-1';
            wrapper.appendChild(this.createStatusBadge(status));

            const counts = document.createElement('span');
            counts.className = 'text-xs text-muted-foreground whitespace-nowrap';
            counts.textContent = `${this.formatLargeNumber(passCount)} pass / ${this.formatLargeNumber(failCount)} fail`;
            wrapper.appendChild(counts);

            cell.appendChild(wrapper);
            return cell;
        },

        createStatusBadge(status) {
            const normalized = status || 'none';
            const badge = document.createElement('span');
            const styles = {
                pass: 'bg-green-50 dark:bg-green-900/20 text-green-700 dark:text-green-300',
                fail: 'bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-300',
                mixed: 'bg-amber-50 dark:bg-amber-900/20 text-amber-700 dark:text-amber-300',
                none: 'bg-muted text-muted-foreground'
            };
            badge.className = `inline-flex w-fit items-center rounded-md px-2 py-1 text-xs font-medium ${styles[normalized] || styles.none}`;
            badge.textContent = normalized.charAt(0).toUpperCase() + normalized.slice(1);
            return badge;
        },
        
        populateDomainsTable(domains) {
            if (!domains || !domains.length) return;
            
            const tableBody = document.getElementById('domains-table-body');
            if (!tableBody) return;
            
            tableBody.textContent = '';
            
            domains.forEach(domain => {
                const row = document.createElement('tr');
                row.className = 'table-row';

                row.appendChild(this.createDomainNameCell(domain.domain_name));
                row.appendChild(this.createTextCell(this.formatLargeNumber(domain.total_emails || 0)));
                row.appendChild(this.createGradeCell(domain.health));
                row.appendChild(this.createRemediationCell(domain.remediation, domain.remediation_workload));
                row.appendChild(this.createPassRateCell(domain.pass_rate || 0));
                row.appendChild(this.createDetailsCell(domain));

                tableBody.appendChild(row);
            });
        },

        createDomainNameCell(domainName) {
            const cell = document.createElement('td');
            cell.className = 'table-cell';

            const content = document.createElement('div');
            content.className = 'font-medium';
            content.textContent = domainName || 'Unknown';
            cell.appendChild(content);

            return cell;
        },

        createGradeCell(health) {
            const cell = document.createElement('td');
            cell.className = 'table-cell';

            const wrapper = document.createElement('div');
            wrapper.className = 'flex flex-col gap-1';

            const badge = document.createElement('span');
            badge.className = `inline-flex w-fit min-w-10 justify-center rounded-md px-2 py-1 text-xs font-bold ${this.gradeClass(health?.grade)}`;
            badge.textContent = health?.grade || 'F';
            wrapper.appendChild(badge);

            const score = document.createElement('span');
            score.className = 'text-xs text-muted-foreground whitespace-nowrap';
            score.textContent = `${health?.score ?? 0}/100`;
            wrapper.appendChild(score);

            cell.appendChild(wrapper);
            return cell;
        },

        createRemediationCell(remediation, workload) {
            const cell = document.createElement('td');
            cell.className = 'table-cell';

            const wrapper = document.createElement('div');
            wrapper.className = 'flex flex-col gap-1';

            const openCount = Number(workload?.total_open || 0);
            const status = openCount > 0 ? 'activity' : (remediation?.status || 'none');
            const badge = document.createElement('span');
            badge.className = `inline-flex w-fit rounded-md bg-[#f8f7f6] px-2 py-1 text-xs font-semibold ${this.remediationStatusClass(status)}`;
            badge.textContent = openCount > 0
                ? `${this.formatLargeNumber(openCount)} open`
                : this.remediationStatusLabel(status);
            wrapper.appendChild(badge);

            const summary = document.createElement('span');
            summary.className = 'max-w-52 truncate text-xs text-muted-foreground';
            summary.title = workload?.primary?.title || '';
            summary.textContent = workload?.primary?.title
                || (remediation?.latest_at ? this.remediationActivityText(remediation) : 'No operator action');
            wrapper.appendChild(summary);

            cell.appendChild(wrapper);
            return cell;
        },

        appendCountBadge(wrapper, entries, className) {
            const parts = entries
                .filter(([count]) => count)
                .map(([count, label]) => `${this.formatLargeNumber(count)} ${label}`);
            if (!parts.length) return;
            const badge = document.createElement('span');
            badge.className = className;
            badge.textContent = parts.join(' · ');
            wrapper.appendChild(badge);
        },

        remediationActivityText(remediation) {
            if (!remediation || !remediation.latest_at) return '';
            const label = remediation.latest_label || this.remediationStatusLabel(remediation.status);
            const timestamp = new Date(remediation.latest_at).toLocaleString();
            return `${label} · ${timestamp}`;
        },

        createPassRateCell(passRate) {
            const cell = document.createElement('td');
            cell.className = 'table-cell';

            const badge = document.createElement('span');
            badge.className = 'inline-flex items-center rounded-md bg-green-50 dark:bg-green-900/20 px-2 py-1 text-xs font-medium text-green-700 dark:text-green-300';
            badge.textContent = `${passRate}%`;
            cell.appendChild(badge);

            return cell;
        },

        createDetailsCell(domain) {
            const cell = document.createElement('td');
            cell.className = 'table-cell text-right';

            const link = document.createElement('a');
            link.className = 'btn btn-outline btn-sm';
            const domainId = String(domain.id ?? domain.domain_name ?? '');
            link.href = `/domains/${encodeURIComponent(domainId)}`;
            link.appendChild(this.createDetailsIcon());
            link.appendChild(document.createTextNode('Details'));
            cell.appendChild(link);

            return cell;
        },

        createDetailsIcon() {
            const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
            svg.setAttribute('width', '14');
            svg.setAttribute('height', '14');
            svg.setAttribute('viewBox', '0 0 24 24');
            svg.setAttribute('fill', 'none');
            svg.setAttribute('stroke', 'currentColor');
            svg.setAttribute('stroke-width', '2');
            svg.setAttribute('stroke-linecap', 'round');
            svg.setAttribute('stroke-linejoin', 'round');
            svg.setAttribute('class', 'mr-1');

            const axis = document.createElementNS('http://www.w3.org/2000/svg', 'path');
            axis.setAttribute('d', 'M3 3v18h18');
            svg.appendChild(axis);

            const trend = document.createElementNS('http://www.w3.org/2000/svg', 'path');
            trend.setAttribute('d', 'm19 9-5 5-4-4-3 3');
            svg.appendChild(trend);

            return svg;
        }
    }
}

if (typeof document !== 'undefined') {
    document.addEventListener('alpine:init', () => {
        Alpine.data('dashboardApp', dashboardApp);
    });
}
