function tlsReportsApp() {
    let domainRefreshTimer = null;
    const emptySummary = {
        totals: { reports: 0, successful_sessions: 0, failed_sessions: 0, failure_rate: 0 },
        trends: [],
        top_failures: [],
        affected_domains: [],
        privacy: { retention: '', stored_fields: [], not_stored: [] },
    };
    return {
        loading: false,
        uploading: false,
        error: '',
        uploadMessage: '',
        uploadError: false,
        selectedFile: null,
        filters: { domain: '', days: '30' },
        summary: emptySummary,
        init() {
            this.bindControls();
            this.refresh();
        },
        get showError() {
            return !this.loading && Boolean(this.error);
        },
        get showEmptyTrends() {
            return !this.loading && !this.error && this.summary.trends.length === 0;
        },
        get showTrends() {
            return !this.loading && !this.error && this.summary.trends.length > 0;
        },
        get uploadIdle() {
            return !this.uploading;
        },
        get uploadDisabled() {
            return this.uploading || !this.selectedFile;
        },
        get uploadMessageClass() {
            return this.uploadError ? 'text-error' : 'text-success';
        },
        get showNoTopFailures() {
            return (
                !this.loading
                && !this.error
                && this.summary.top_failures.length === 0
            );
        },
        get showNoAffectedDomains() {
            return (
                !this.loading
                && !this.error
                && this.summary.affected_domains.length === 0
            );
        },
        bindControls() {
            const root = this.$root || document;
            if (root.dataset?.tlsControlsBound === 'true') {
                return;
            }
            if (root.dataset) {
                root.dataset.tlsControlsBound = 'true';
            }

            root.addEventListener('click', (event) => {
                if (!(event.target instanceof Element)) {
                    return;
                }
                const refreshButton = event.target.closest('[data-tls-refresh]');
                if (refreshButton && root.contains(refreshButton)) {
                    this.refresh();
                }
            });
            root.addEventListener('change', (event) => {
                if (!(event.target instanceof Element)) {
                    return;
                }
                const daysFilter = event.target.closest('[data-tls-days-filter]');
                if (daysFilter && root.contains(daysFilter)) {
                    this.filters.days = daysFilter.value;
                    this.refresh();
                    return;
                }
                const uploadFile = event.target.closest('[data-tls-upload-file]');
                if (uploadFile && root.contains(uploadFile)) {
                    this.selectedFile = uploadFile.files?.[0] || null;
                }
            });
            root.addEventListener('input', (event) => {
                if (!(event.target instanceof Element)) {
                    return;
                }
                const domainFilter = event.target.closest('[data-tls-domain-filter]');
                if (domainFilter && root.contains(domainFilter)) {
                    this.filters.domain = domainFilter.value;
                    clearTimeout(domainRefreshTimer);
                    domainRefreshTimer = setTimeout(() => this.refresh(), 250);
                }
            });
            root.addEventListener('submit', (event) => {
                if (!(event.target instanceof Element)) {
                    return;
                }
                const form = event.target.closest('[data-tls-upload-form]');
                if (form && root.contains(form)) {
                    event.preventDefault();
                    this.uploadReport();
                }
            });
        },
        async refresh() {
            this.loading = true;
            this.error = '';
            const params = new URLSearchParams({ days: this.filters.days, limit: '10' });
            if (this.filters.domain.trim()) params.set('domain', this.filters.domain.trim());
            try {
                const response = await fetch(`/api/v1/tls-reports/summary?${params.toString()}`);
                if (!response.ok) throw new Error('Unable to load TLS report summary');
                this.summary = this.normalizeSummary(await response.json());
            } catch (err) {
                this.error = err.message || 'Unable to load TLS report summary';
            } finally {
                this.loading = false;
            }
        },
        async uploadReport() {
            if (!this.selectedFile) return;
            this.uploading = true;
            this.uploadMessage = '';
            this.uploadError = false;
            const payload = new FormData();
            payload.append('file', this.selectedFile);
            try {
                const response = await fetch('/api/v1/tls-reports/upload', {
                    method: 'POST',
                    body: payload,
                });
                const data = await response.json().catch(() => ({}));
                if (!response.ok) throw new Error(data.detail || 'Upload failed');
                this.uploadMessage = data.message || 'TLS report imported.';
                this.selectedFile = null;
                await this.refresh();
            } catch (err) {
                this.uploadError = true;
                this.uploadMessage = err.message || 'Upload failed';
            } finally {
                this.uploading = false;
            }
        },
        formatNumber(value) {
            return Number(value || 0).toLocaleString();
        },
        formatPercent(value) {
            return `${(Number(value || 0) * 100).toFixed(1)}%`;
        },
        trendTotal(day) {
            return Math.max(Number(day.successful_sessions || 0) + Number(day.failed_sessions || 0), 1);
        },
        trendSuccessWidth(day) {
            return Math.round((Number(day.successful_sessions || 0) / this.trendTotal(day)) * 100);
        },
        trendFailureWidth(day) {
            return Math.round((Number(day.failed_sessions || 0) / this.trendTotal(day)) * 100);
        },
        normalizeSummary(payload) {
            const summary = payload || emptySummary;
            const trends = (summary.trends || []).map((day) => ({
                ...day,
                success_width: this.trendSuccessWidth(day),
                failure_width: this.trendFailureWidth(day),
                failed_label: `${this.formatNumber(day.failed_sessions)} failed`,
            }));
            const topFailures = (summary.top_failures || []).map((failure) => ({
                ...failure,
                affected_domains_label: this.joinValues(failure.affected_domains),
                receiving_mx_hostnames_label: this.joinValues(failure.receiving_mx_hostnames),
            }));
            const affectedDomains = (summary.affected_domains || []).map((item) => ({
                ...item,
                domain_url: `/domains/${encodeURIComponent(item.domain || '')}`,
            }));
            return {
                totals: { ...emptySummary.totals, ...(summary.totals || {}) },
                trends,
                top_failures: topFailures,
                affected_domains: affectedDomains,
                privacy: { ...emptySummary.privacy, ...(summary.privacy || {}) },
            };
        },
        joinValues(values) {
            const joined = (values || []).filter(Boolean).join(', ');
            return joined || '-';
        },
    };
}

document.addEventListener('alpine:init', () => {
    Alpine.data('tlsReportsApp', tlsReportsApp);
});
