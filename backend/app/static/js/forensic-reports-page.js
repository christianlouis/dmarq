function forensicReportsApp() {
    return {
        loading: false,
        uploading: false,
        error: '',
        uploadMessage: '',
        uploadError: false,
        selectedFile: null,
        reports: [],
        analysis: { groups: [], priority_counts: {}, failure_counts: {}, result_counts: {}, samples: [] },
        domainOptions: [],
        total: 0,
        filters: {
            domain: '',
            authFailure: '',
            deliveryResult: '',
            search: '',
        },
        init() {
            this.fetchReports();
        },
        get domains() {
            return this.domainOptions;
        },
        get filteredReports() {
            const search = this.filters.search.trim().toLowerCase();
            if (!search) return this.reports;
            return this.reports.filter((report) =>
                [
                    report.source_ip,
                    report.original_from,
                    report.original_mail_from,
                    report.original_subject,
                    report.authentication_results,
                    report.report_id,
                ].some((value) => String(value || '').toLowerCase().includes(search))
            );
        },
        get summary() {
            return {
                total: this.total,
                dkim: this.reports.filter((report) => report.auth_failure === 'dkim').length,
                spf: this.reports.filter((report) => report.auth_failure === 'spf').length,
                rejected: this.reports.filter((report) => report.delivery_result === 'reject').length,
            };
        },
        async fetchReports() {
            this.loading = true;
            this.error = '';
            const params = new URLSearchParams({ page_size: '200' });
            if (this.filters.domain) params.set('domain', this.filters.domain);
            if (this.filters.authFailure) params.set('auth_failure', this.filters.authFailure);
            if (this.filters.deliveryResult) params.set('delivery_result', this.filters.deliveryResult);
            try {
                const response = await fetch(`/api/v1/forensics?${params.toString()}`);
                if (!response.ok) throw new Error('Unable to load forensic reports');
                const data = await response.json();
                this.reports = data.reports || [];
                this.total = data.total || 0;
                await this.fetchAnalysis(params);
                if (!this.filters.domain) {
                    this.domainOptions = [
                        ...new Set(
                            this.reports
                                .map((report) => report.domain || report.reported_domain)
                                .filter(Boolean)
                        ),
                    ].sort();
                }
            } catch (err) {
                this.error = err.message || 'Unable to load forensic reports';
            } finally {
                this.loading = false;
            }
        },
        async fetchAnalysis(params) {
            const response = await fetch(`/api/v1/forensics/analysis?${params.toString()}`);
            if (!response.ok) throw new Error('Unable to analyze forensic reports');
            this.analysis = await response.json();
        },
        async uploadReport() {
            if (!this.selectedFile) return;
            this.uploading = true;
            this.uploadMessage = '';
            this.uploadError = false;
            const payload = new FormData();
            payload.append('file', this.selectedFile);
            try {
                const response = await fetch('/api/v1/forensics/upload', {
                    method: 'POST',
                    body: payload,
                });
                const data = await response.json().catch(() => ({}));
                if (!response.ok) throw new Error(data.detail || 'Upload failed');
                this.uploadMessage = data.message || 'Forensic report imported.';
                this.selectedFile = null;
                await this.fetchReports();
            } catch (err) {
                this.uploadError = true;
                this.uploadMessage = err.message || 'Upload failed';
            } finally {
                this.uploading = false;
            }
        },
        resetFilters() {
            this.filters = { domain: '', authFailure: '', deliveryResult: '', search: '' };
            this.fetchReports();
        },
        formatDate(value) {
            if (!value) return '-';
            const date = new Date(value);
            return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
        },
        priorityClass(priority) {
            if (priority === 'high') return 'badge-error';
            if (priority === 'medium') return 'badge-warning';
            return 'badge-ghost';
        },
    };
}
