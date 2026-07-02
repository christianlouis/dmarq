function reportsApp() {
    return {
        filters: {
            domain: '',
            dateRange: '30',
        },
        domains: [],
        reports: [],
        loading: false,

        init() {
            this.fetchReports();
        },

        get filteredReports() {
            return this.reports.filter((report) => {
                if (this.filters.domain && report.domain !== this.filters.domain) {
                    return false;
                }

                if (this.filters.dateRange !== 'all') {
                    const days = parseInt(this.filters.dateRange, 10);
                    const cutoff = new Date();
                    cutoff.setDate(cutoff.getDate() - days);

                    const reportDate = new Date(report.end_date);
                    if (reportDate < cutoff) {
                        return false;
                    }
                }

                return true;
            });
        },

        formatDate(dateStr) {
            const date = new Date(dateStr);
            return date.toLocaleDateString();
        },

        getPassRateColor(rate) {
            if (rate >= 90) return 'bg-green-100 text-green-800';
            if (rate >= 50) return 'bg-yellow-100 text-yellow-800';
            return 'bg-red-100 text-red-800';
        },

        async fetchReports() {
            this.loading = true;
            try {
                const response = await fetch('/api/v1/reports');
                this.reports = await response.json();
                this.domains = [...new Set(this.reports.map((report) => report.domain))].sort();
            } catch (error) {
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
                alert('Network error - could not delete report.');
            }
        },
    };
}
