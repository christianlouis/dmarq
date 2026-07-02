function domainsApp() {
    return {
        domains: [],
        openCreate: false,
        saving: false,
        createError: '',
        newDomain: {
            name: '',
            description: '',
            dkim_selectors: '',
        },

        init() {
            this.fetchDomains();
        },

        async fetchDomains() {
            try {
                const response = await fetch('/api/v1/domains/summary');
                if (response.ok) {
                    const data = await response.json();

                    this.domains = data.domains.map((domain) => ({
                        name: domain.domain_name,
                        dmarc_status: domain.dmarc_status ?? false,
                        dmarc_policy: domain.dmarc_policy || 'Not configured',
                        spf_status: domain.spf_status ?? false,
                        dkim_status: domain.dkim_status ?? false,
                        reports_count: domain.report_count,
                        emails_count: domain.total_emails,
                        compliance_rate: domain.pass_rate,
                    }));
                } else {
                    console.error('Error fetching domains:', response.status);
                }
            } catch (error) {
                console.error('Error fetching domains:', error);
            }
        },

        closeCreate() {
            this.openCreate = false;
            this.createError = '';
            this.newDomain = { name: '', description: '', dkim_selectors: '' };
        },

        async createDomain() {
            this.saving = true;
            this.createError = '';
            try {
                const selectors = this.newDomain.dkim_selectors
                    .split(',')
                    .map((selector) => selector.trim())
                    .filter(Boolean);
                const response = await fetch('/api/v1/domains/domains', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        name: this.newDomain.name,
                        description: this.newDomain.description || null,
                        dkim_selectors: selectors,
                    }),
                });
                if (!response.ok) {
                    const data = await response.json().catch(() => ({}));
                    const detail =
                        typeof data.detail === 'string'
                            ? data.detail
                            : Object.values(data.detail || {}).join(', ');
                    throw new Error(detail || 'Domain could not be added.');
                }
                this.closeCreate();
                await this.fetchDomains();
            } catch (error) {
                this.createError = error.message || 'Domain could not be added.';
            } finally {
                this.saving = false;
            }
        },
    };
}
