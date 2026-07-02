function tlsReportsApp() {
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
            this.refresh();
        },
        async refresh() {
            this.loading = true;
            this.error = '';
            const params = new URLSearchParams({ days: this.filters.days, limit: '10' });
            if (this.filters.domain.trim()) params.set('domain', this.filters.domain.trim());
            try {
                const response = await fetch(`/api/v1/tls-reports/summary?${params.toString()}`);
                if (!response.ok) throw new Error('Unable to load TLS report summary');
                this.summary = await response.json();
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
    };
}
