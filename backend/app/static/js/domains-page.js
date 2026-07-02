function domainsApp() {
    return {
        domains: [],
        openCreate: false,
        openEdit: false,
        loading: true,
        loadError: '',
        saving: false,
        createError: '',
        editError: '',
        newDomain: {
            name: '',
            description: '',
            dkim_selectors: '',
        },
        editDomain: {
            name: '',
            description: '',
            dkim_selectors: '',
        },

        init() {
            this.fetchDomains();
        },

        async fetchDomains() {
            this.loading = true;
            this.loadError = '';
            try {
                const response = await fetch('/api/v1/domains/summary');
                if (!response.ok) {
                    throw new Error('Domains could not be loaded. Refresh the page or check the API service.');
                }
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
                    description: domain.description || '',
                    dkim_selectors: Array.isArray(domain.dkim_selectors)
                        ? domain.dkim_selectors
                        : [],
                }));
            } catch (error) {
                this.domains = [];
                this.loadError = error.message || 'Domains could not be loaded.';
                console.error('Error fetching domains:', error);
            } finally {
                this.loading = false;
            }
        },

        closeCreate() {
            this.openCreate = false;
            this.createError = '';
            this.newDomain = { name: '', description: '', dkim_selectors: '' };
        },

        openEditDialog(domain) {
            this.editError = '';
            this.editDomain = {
                name: domain.name,
                description: domain.description || '',
                dkim_selectors: Array.isArray(domain.dkim_selectors)
                    ? domain.dkim_selectors.join(', ')
                    : '',
            };
            this.openEdit = true;
        },

        closeEdit() {
            this.openEdit = false;
            this.editError = '';
            this.editDomain = { name: '', description: '', dkim_selectors: '' };
        },

        apiErrorDetail(data, fallback) {
            const detail = data?.detail;
            if (typeof detail === 'string') {
                return detail;
            }
            if (Array.isArray(detail)) {
                return (
                    detail
                        .map((item) => item?.msg || item?.message || item?.detail || '')
                        .filter(Boolean)
                        .join(', ') || fallback
                );
            }
            if (detail && typeof detail === 'object') {
                return Object.values(detail)
                    .map((value) =>
                        typeof value === 'string' ? value : value?.msg || value?.message || ''
                    )
                    .filter(Boolean)
                    .join(', ');
            }
            return fallback;
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
                    const detail = this.apiErrorDetail(data, 'Domain could not be added.');
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

        async updateDomain() {
            this.saving = true;
            this.editError = '';
            try {
                const selectors = this.editDomain.dkim_selectors
                    .split(',')
                    .map((selector) => selector.trim())
                    .filter(Boolean);
                const response = await fetch(
                    `/api/v1/domains/domains/${encodeURIComponent(this.editDomain.name)}`,
                    {
                        method: 'PATCH',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            description: this.editDomain.description || null,
                            dkim_selectors: selectors,
                        }),
                    }
                );
                if (!response.ok) {
                    const data = await response.json().catch(() => ({}));
                    const detail = this.apiErrorDetail(data, 'Domain could not be updated.');
                    throw new Error(detail || 'Domain could not be updated.');
                }
                this.closeEdit();
                await this.fetchDomains();
            } catch (error) {
                this.editError = error.message || 'Domain could not be updated.';
            } finally {
                this.saving = false;
            }
        },
    };
}
