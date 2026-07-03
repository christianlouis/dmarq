function reportDetailApp(reportId) {
    return {
        reportId: reportId,
        report: null,
        loading: true,
        error: null,

        async init() {
            this.bindDeleteControls();
            await this.fetchReport();
        },

        bindDeleteControls() {
            const root = this.$root || document;
            if (root.dataset?.reportDeleteBound === 'true') {
                return;
            }
            if (root.dataset) {
                root.dataset.reportDeleteBound = 'true';
            }
            root.addEventListener('click', (event) => {
                if (!(event.target instanceof Element)) {
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

        async fetchReport() {
            this.loading = true;
            this.error = null;
            try {
                const response = await fetch(`/api/v1/reports/${encodeURIComponent(this.reportId)}`);
                if (response.ok) {
                    this.report = await response.json();
                } else if (response.status === 404) {
                    this.report = null;
                    this.error = `Report '${this.reportId}' was not found. It may have been deleted or may not exist.`;
                } else {
                    this.report = null;
                    this.error = 'Failed to load report. Please try again later.';
                }
            } catch (err) {
                this.report = null;
                this.error = 'Network error — could not load report.';
                console.error('Error fetching report:', err);
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
                    window.location.href = '/reports';
                } else {
                    const data = await response.json().catch(() => ({}));
                    alert(`Failed to delete report: ${data.detail || response.statusText}`);
                }
            } catch (error) {
                console.error('Error deleting report:', error);
                alert('Network error — could not delete report.');
            }
        },

        formatDate(timestamp) {
            if (!timestamp) return '—';
            return new Date(timestamp * 1000).toLocaleString();
        },

        passRateClass(rate) {
            if (rate >= 90) return 'text-success';
            if (rate >= 50) return 'text-warning';
            return 'text-error';
        },

        resultClass(result) {
            if (result === 'pass') return 'bg-green-100 text-green-800';
            if (result === 'fail') return 'bg-red-100 text-red-800';
            return 'bg-gray-100 text-gray-800';
        },

        dispositionClass(disposition) {
            if (disposition === 'none') return 'bg-green-100 text-green-800';
            if (disposition === 'quarantine') return 'bg-yellow-100 text-yellow-800';
            if (disposition === 'reject') return 'bg-red-100 text-red-800';
            return 'bg-gray-100 text-gray-800';
        },

        reviewStatusClass(status) {
            if (status === 'needs_review') return 'bg-yellow-100 text-yellow-800';
            return 'bg-green-100 text-green-800';
        },

        reviewStatusLabel(status) {
            if (status === 'needs_review') return 'Needs review';
            return 'Pass';
        },

        sourceLocation(record) {
            const details = record.source_details || {};
            const country = details.country || 'Unknown country';
            const region = details.region || 'Unknown region';
            const code = details.country_code && details.country_code !== 'ZZ' ? ` (${details.country_code})` : '';
            const network = [details.asn, details.network, details.bgp_prefix].filter(Boolean).join(' · ');
            return [region, `${country}${code}`, network].filter(Boolean).join(' · ');
        },

        reputationClass(status) {
            if (status === 'listed' || status === 'critical') return 'bg-red-100 text-red-800';
            if (status === 'suspicious') return 'bg-yellow-100 text-yellow-800';
            if (status === 'clean') return 'bg-green-100 text-green-800';
            return 'bg-gray-100 text-gray-800';
        },

        reputationFeedClass(status) {
            if (status === 'listed') return 'bg-red-50 text-red-800';
            if (status === 'error') return 'bg-yellow-50 text-yellow-800';
            if (status === 'checked') return 'bg-green-50 text-green-800';
            return 'bg-base-200 text-base-content/70';
        },

        reputationLabel(reputation) {
            return reputation?.status_label || reputation?.status || 'Reputation unavailable';
        },

        reputationCheckedLabel(reputation) {
            if (!reputation?.checked_at) return 'not checked yet';
            const date = new Date(reputation.checked_at);
            if (Number.isNaN(date.getTime())) return reputation.checked_at;
            return `checked ${date.toLocaleString()}`;
        },

        reputationEvidencePreview(reputation) {
            return (reputation?.evidence || []).slice(0, 3);
        },
    };
}
