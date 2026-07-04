function forensicReportDetailApp() {
    return {
        reportId: '',
        report: null,
        loading: false,
        error: '',
        async init() {
            this.reportId = this.$el?.dataset?.reportId || '';
            await this.fetchReport();
        },
        get showError() {
            return !this.loading && Boolean(this.error);
        },
        get showReport() {
            return !this.loading && !this.error && Boolean(this.report);
        },
        get reportExternalId() {
            return this.report?.report_id || this.reportId;
        },
        get reportDomain() {
            return this.report?.domain || this.report?.reported_domain || 'unknown domain';
        },
        get domainUrl() {
            const domain = this.report?.domain || this.report?.reported_domain || '';
            return `/domains/${encodeURIComponent(domain)}`;
        },
        get authFailureLabel() {
            return this.report?.auth_failure || 'unknown';
        },
        get deliveryResultLabel() {
            return this.report?.delivery_result || 'unknown';
        },
        get sourceIpLabel() {
            return this.report?.source_ip || '-';
        },
        get arrivalLabel() {
            return this.formatDate(this.report?.arrival_date || this.report?.processed_at);
        },
        get analysis() {
            return this.report?.analysis || {};
        },
        get priorityLabel() {
            return this.analysis.priority || 'unknown';
        },
        get priorityBadgeClass() {
            return this.priorityClass(this.analysis.priority);
        },
        get diagnosisLabel() {
            return this.analysis.diagnosis || 'No analysis is available for this sample.';
        },
        get recommendations() {
            return this.analysis.recommendations || [];
        },
        get signals() {
            return this.analysis.signals || [];
        },
        get privacyNote() {
            return this.analysis.privacy_note || '';
        },
        get authenticationResultsLabel() {
            return (
                this.report?.authentication_results ||
                'No Authentication-Results header was included.'
            );
        },
        get identityFields() {
            if (!this.report) return [];
            return [
                { label: 'Reported Domain', value: this.report.reported_domain || this.report.domain },
                { label: 'Reporter', value: this.report.source_email },
                { label: 'Original Mail From', value: this.report.original_mail_from },
                { label: 'Original From', value: this.report.original_from },
                { label: 'Original To', value: this.report.original_to },
                { label: 'Original Subject', value: this.report.original_subject },
                { label: 'Original Date', value: this.report.original_date },
                { label: 'Message Hash', value: this.report.original_message_id, mono: true },
                { label: 'Feedback Type', value: this.report.feedback_type },
                { label: 'Reporter Agent', value: this.report.user_agent },
            ].map((item) => ({
                ...item,
                css_class: item.mono ? 'font-mono text-sm' : '',
                display_value: item.value || '-',
            }));
        },
        get feedbackHeaderEntries() {
            return Object.entries(this.report?.feedback_headers || {}).map(([key, value]) => ({
                key,
                label: this.labelize(key),
                value: value || '-',
            }));
        },
        get hasNoFeedbackHeaderEntries() {
            return this.feedbackHeaderEntries.length === 0;
        },
        async fetchReport() {
            this.loading = true;
            this.error = '';
            try {
                const response = await fetch(`/api/v1/forensics/${this.reportId}`);
                if (!response.ok) throw new Error('Forensic report not found');
                this.report = await response.json();
            } catch (err) {
                this.error = err.message || 'Unable to load forensic report';
            } finally {
                this.loading = false;
            }
        },
        formatDate(value) {
            if (!value) return '-';
            const date = new Date(value);
            return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
        },
        labelize(value) {
            return String(value || '')
                .replaceAll('_', ' ')
                .replace(/\b\w/g, (char) => char.toUpperCase());
        },
        priorityClass(priority) {
            if (priority === 'high') return 'badge-error';
            if (priority === 'medium') return 'badge-warning';
            return 'badge-ghost';
        },
    };
}

document.addEventListener('alpine:init', () => {
    Alpine.data('forensicReportDetailApp', forensicReportDetailApp);
});
