function reportsApp() {
    return {
        filters: {
            domain: '',
            dateRange: '30',
        },
        domains: [],
        reports: [],
        loading: true,
        error: '',
        warning: '',

        init() {
            this.bindPageControls();
            this.fetchReports();
        },

        bindPageControls() {
            const root = this.$root || document;
            if (root.dataset?.reportControlsBound === 'true') {
                return;
            }
            if (root.dataset) {
                root.dataset.reportControlsBound = 'true';
            }
            root.addEventListener('click', (event) => {
                if (!(event.target instanceof Element)) {
                    return;
                }
                const resetButton = event.target.closest('[data-report-reset-filters]');
                if (resetButton && root.contains(resetButton)) {
                    this.resetFilters();
                    return;
                }

                const retryButton = event.target.closest('[data-report-retry-load]');
                if (retryButton && root.contains(retryButton)) {
                    this.fetchReports({ preserveOnFailure: true });
                    return;
                }

                const refreshButton = event.target.closest('[data-report-refresh]');
                if (refreshButton && root.contains(refreshButton)) {
                    this.fetchReports({ preserveOnFailure: true });
                    return;
                }

                const button = event.target.closest('[data-report-delete]');
                if (!button || !root.contains(button)) {
                    return;
                }
                const domain = button.dataset.reportDomain || '';
                const reportId = button.dataset.reportId || '';
                if (domain && reportId) {
                    this.deleteReport(domain, reportId);
                }
            });
        },

        get showLoading() {
            return this.loading;
        },

        get showError() {
            return !this.loading && Boolean(this.error);
        },

        get showWarning() {
            return !this.loading && Boolean(this.warning);
        },

        get showReportCount() {
            return !this.loading && !this.error;
        },

        get showEmpty() {
            return !this.loading && !this.error && this.filteredReports.length === 0;
        },

        get filteredReportCount() {
            return this.filteredReports.length;
        },

        get visibleReports() {
            if (this.loading || this.error) {
                return [];
            }
            return this.filteredReports;
        },

        get failingReports() {
            return this.visibleReports.filter((report) => Number(report.pass_rate || 0) < 100);
        },

        get primaryReportCtaHref() {
            const report = this.failingReports[0] || this.visibleReports[0];
            return report?.detail_url || '/mail-sources';
        },

        get primaryReportCtaLabel() {
            if (this.failingReports.length) return 'Open first failing report';
            if (this.visibleReports.length) return 'Open latest report';
            return 'Connect report mailbox';
        },

        get emptyStateTitle() {
            if (this.reports.length > 0) return 'No reports match this filter';
            return 'No DMARC reports imported yet';
        },

        get emptyStateText() {
            if (this.reports.length > 0) {
                return 'Change the filters or reset them to get back to imported reports.';
            }
            return 'Connect Gmail, IMAP, or another report source so DMARQ can import aggregate XML reports.';
        },

        get filteredReports() {
            return this.reports.filter((report) => {
                if (this.filters.domain && report.domain !== this.filters.domain) {
                    return false;
                }

                if (this.filters.dateRange !== 'all') {
                    const days = parseInt(this.filters.dateRange, 10);
                    const now = new Date();
                    const cutoff = new Date(Date.UTC(
                        now.getUTCFullYear(),
                        now.getUTCMonth(),
                        now.getUTCDate() - (days - 1)
                    ));

                    const reportDate = new Date(report.end_date);
                    if (reportDate < cutoff) {
                        return false;
                    }
                }

                return true;
            });
        },

        formatDate(dateStr) {
            if (!dateStr) {
                return '';
            }
            const date = new Date(dateStr);
            if (Number.isNaN(date.getTime())) {
                return '';
            }
            return date.toLocaleDateString();
        },

        normalizeReport(report) {
            const passRate = Number(report.pass_rate || 0);
            const reportId = String(report.report_id || '');

            return {
                ...report,
                pass_rate: passRate,
                pass_rate_class: this.getPassRateColor(passRate),
                pass_rate_label: `${passRate}%`,
                end_date_label: this.formatDate(report.end_date),
                detail_url: `/reports/${encodeURIComponent(reportId)}`,
            };
        },

        resetFilters() {
            this.filters = {
                domain: '',
                dateRange: '30',
            };
        },

        getPassRateColor(rate) {
            if (rate >= 90) return 'bg-green-100 text-green-800';
            if (rate >= 50) return 'bg-yellow-100 text-yellow-800';
            return 'bg-red-100 text-red-800';
        },

        async fetchReports(options = {}) {
            const preserveOnFailure = Boolean(options.preserveOnFailure);
            const hadReports = this.reports.length > 0;
            this.loading = true;
            this.error = '';
            this.warning = '';
            try {
                const response = await fetch('/api/v1/reports');
                if (!response.ok) {
                    throw new Error('Reports could not be loaded. Refresh the page or check the import service.');
                }
                const reports = await response.json();
                this.reports = reports.map((report) => this.normalizeReport(report));
                this.domains = [...new Set(this.reports.map((report) => report.domain))].sort();
            } catch (error) {
                const message = error.message || 'Reports could not be loaded.';
                if (preserveOnFailure && hadReports) {
                    const separator = /[.!?]$/.test(message.trim()) ? ' ' : '. ';
                    this.warning = `${message}${separator}Showing the last loaded reports.`;
                } else {
                    this.reports = [];
                    this.domains = [];
                    this.error = message;
                }
                console.error('Error fetching reports:', error);
            } finally {
                this.loading = false;
            }
        },

        async deleteReport(domain, reportId) {
            if (
                !confirm(
                    `Delete report "${reportId}" for domain "${domain}"?\n\nThis will remove the report from the system. You can re-import it afterwards.`
                )
            ) {
                return;
            }

            try {
                const response = await fetch(
                    `/api/v1/reports/domain/${encodeURIComponent(domain)}/reports/${encodeURIComponent(reportId)}`,
                    { method: 'DELETE' }
                );

                if (response.ok) {
                    this.reports = this.reports.filter(
                        (report) => !(report.domain === domain && report.report_id === reportId)
                    );
                    if (!this.reports.some((report) => report.domain === domain)) {
                        this.domains = this.domains.filter((knownDomain) => knownDomain !== domain);
                    }
                } else {
                    const data = await response.json().catch(() => ({}));
                    alert(`Failed to delete report: ${data.detail || response.statusText}`);
                }
            } catch (error) {
                console.error('Error deleting report:', error);
                alert('Network error — could not delete report.');
            }
        },
    };
}

document.addEventListener('alpine:init', () => {
    Alpine.data('reportsApp', reportsApp);
});
