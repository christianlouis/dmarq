function dashboardApp() {
    return {
        hasDomainData: false,
        volumeTrendChart: null,
        complianceTrendChart: null,
        healthTrendChart: null,
        domains: [],
        healthSummary: null,
        healthHistory: null,
        dashboardLoading: true,
        dashboardError: '',
        selectedDnsDomain: '',
        triggerPollRunning: false,
        triggerPollStatus: '',
        triggerPollMessage: '',
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
        
        init() {
            // Fetch domain summary on page load
            this.fetchDomainSummary();
            
            // Check IMAP status
            this.getImapStatus();
            this.fetchForensicSummary();
        },
        
        async getImapStatus() {
            try {
                const response = await fetch('/api/v1/poll-status');
                if (!response.ok) {
                    console.error('Error checking IMAP status:', response.status);
                    return;
                }
                const data = await response.json();
                
                const statusIcon = document.getElementById('imap-status-icon');
                const statusText = document.getElementById('imap-status-text');
                const lastCheck = document.getElementById('imap-last-check');
                
                if (data.is_running) {
                    statusIcon.classList.remove('bg-red-500');
                    statusIcon.classList.add('bg-green-500');
                    statusText.textContent = 'Running';
                } else {
                    statusIcon.classList.remove('bg-green-500');
                    statusIcon.classList.add('bg-red-500');
                    statusText.textContent = 'Stopped';
                }
                
                if (data.last_check) {
                    lastCheck.textContent = new Date(data.last_check).toLocaleString();
                } else {
                    lastCheck.textContent = 'Never';
                }
            } catch (error) {
                console.error('Error checking IMAP status:', error);
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
                const count = data.sources_polled || 0;
                this.triggerPollStatus = 'success';
                this.triggerPollMessage = count
                    ? `Polling finished for ${count} source${count === 1 ? '' : 's'}.`
                    : (data.message || 'No enabled mail sources configured.');
                await this.getImapStatus();
                await this.fetchDomainSummary();
            } catch (error) {
                this.triggerPollStatus = 'error';
                this.triggerPollMessage = error.message || 'Could not trigger polling.';
            } finally {
                this.triggerPollRunning = false;
            }
        },
        
        async fetchDomainSummary() {
            this.dashboardLoading = true;
            this.dashboardError = '';
            try {
                const response = await fetch('/api/v1/domains/summary');
                if (!response.ok) {
                    throw new Error('Dashboard data could not be loaded. Check the API service and try again.');
                }
                const data = await response.json();
                
                if (data && data.domains && data.domains.length > 0) {
                    this.domains = data.domains || [];
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
                    this.clearDashboardCharts();
                    this.populateChangeSummary([]);
                    this.populateTopSources([]);
                }
            } catch (error) {
                console.error('Error fetching domain summary:', error);
                this.dashboardError = error.message || 'Dashboard data could not be loaded.';
                this.domains = [];
                this.healthSummary = null;
                this.healthHistory = null;
                this.selectedDnsDomain = '';
                this.hasDomainData = false;
                this.clearDashboardCharts();
                this.populateChangeSummary([]);
                this.populateTopSources([]);
            } finally {
                this.dashboardLoading = false;
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
            return new Intl.NumberFormat(undefined, { notation: 'compact' }).format(value);
        },

        formatScoreDelta(value) {
            if (value === null || value === undefined) return 'No prior score';
            const number = Number(value) || 0;
            if (number === 0) return 'No change';
            return `${number > 0 ? '+' : ''}${number} pts`;
        },

        formatMoney(cents, currency = 'EUR') {
            return new Intl.NumberFormat(undefined, {
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
                row.appendChild(this.createPassRateCell(domain.pass_rate || 0));
                row.appendChild(this.createTextCell(this.formatLargeNumber(domain.failed_count || 0)));
                row.appendChild(this.createTextCell(this.formatLargeNumber(domain.report_count || 0)));
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
