function forensicReportDetailApp(reportId) {
    return {
        reportId,
        report: null,
        loading: false,
        error: '',
        async init() {
            await this.fetchReport();
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
            ];
        },
        get feedbackHeaderEntries() {
            return Object.entries(this.report?.feedback_headers || {});
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
