function domainsApp() {
    return {
        domains: [],
        emptyDomainsCount: 0,
        emptyDomainsHidden: 0,
        openCreate: false,
        openEdit: false,
        loading: true,
        refreshing: false,
        loadError: '',
        showEmptyDomains: false,
        saving: false,
        createError: '',
        editError: '',
        newDomain: {
            name: '',
            description: '',
            dkim_selectors: '',
            dmarc_report_mailbox: '',
        },
        editDomain: {
            name: '',
            description: '',
            dkim_selectors: '',
            dmarc_report_mailbox: '',
        },
        editDmarcReportMailboxLoaded: false,

        init() {
            this.bindPageControls();
            this.fetchDomains();
        },

        bindPageControls() {
            const root = this.$root || document;
            if (root.dataset?.domainControlsBound === 'true') {
                return;
            }
            if (root.dataset) {
                root.dataset.domainControlsBound = 'true';
            }

            root.addEventListener('click', (event) => {
                if (!(event.target instanceof Element)) {
                    return;
                }

                const refreshButton = event.target.closest('[data-domain-refresh]');
                if (refreshButton && root.contains(refreshButton)) {
                    this.fetchDomains({ refresh: true });
                    return;
                }

                const createButton = event.target.closest('[data-domain-create-open]');
                if (createButton && root.contains(createButton)) {
                    this.openCreate = true;
                    return;
                }

                const retryButton = event.target.closest('[data-domain-retry-load]');
                if (retryButton && root.contains(retryButton)) {
                    this.fetchDomains();
                    return;
                }

                const emptyToggle = event.target.closest('[data-domain-toggle-empty]');
                if (emptyToggle && root.contains(emptyToggle)) {
                    this.setShowEmptyDomains(!this.showEmptyDomains);
                    return;
                }

                const editButton = event.target.closest('[data-domain-edit]');
                if (!editButton || !root.contains(editButton)) {
                    return;
                }
                const domainIndex = Number.parseInt(editButton.dataset.domainIndex || '', 10);
                const visibleDomains = this.visibleDomains();
                const domain = Number.isInteger(domainIndex) ? visibleDomains[domainIndex] : null;
                if (domain) {
                    this.openEditDialog(domain);
                }
            });

            root.querySelectorAll('[data-domain-create-close]').forEach((button) => {
                button.addEventListener('click', () => {
                    this.closeCreate();
                });
            });
            root.querySelectorAll('[data-domain-edit-close]').forEach((button) => {
                button.addEventListener('click', () => {
                    this.closeEdit();
                });
            });
            root.querySelector('[data-domain-create-form]')?.addEventListener('submit', (event) => {
                event.preventDefault();
                this.createDomain();
            });
            root.querySelector('[data-domain-edit-form]')?.addEventListener('submit', (event) => {
                event.preventDefault();
                this.updateDomain();
            });
            root.querySelector('[data-domain-edit-mailbox]')?.addEventListener('input', () => {
                this.editDmarcReportMailboxLoaded = true;
            });
        },

        async fetchDomains(options = {}) {
            const refresh = Boolean(options.refresh);
            const includeEmpty =
                options.includeEmpty === undefined ? this.showEmptyDomains : Boolean(options.includeEmpty);
            this.loading = !refresh;
            this.refreshing = refresh;
            this.loadError = '';
            try {
                const params = new URLSearchParams();
                params.set('include_empty', includeEmpty ? 'true' : 'false');
                if (refresh) {
                    params.set('refresh', 'true');
                }
                const response = await fetch(`/api/v1/domains/summary?${params.toString()}`);
                if (!response.ok) {
                    throw new Error('Domains could not be loaded. Refresh the page or check the API service.');
                }
                const data = await response.json();

                this.domains = data.domains.map((domain) => this.normalizeDomain(domain));
                this.emptyDomainsCount = Number(data.empty_domains_count || 0);
                this.emptyDomainsHidden = Number(data.empty_domains_hidden || 0);
            } catch (error) {
                this.domains = [];
                this.emptyDomainsCount = 0;
                this.emptyDomainsHidden = 0;
                this.loadError = error.message || 'Domains could not be loaded.';
                console.error('Error fetching domains:', error);
            } finally {
                this.loading = false;
                this.refreshing = false;
            }
        },

        async setShowEmptyDomains(show) {
            this.showEmptyDomains = Boolean(show);
            if (this.showEmptyDomains && this.emptyDomainsHidden > 0) {
                await this.fetchDomains({ includeEmpty: true });
            }
        },

        closeCreate() {
            this.openCreate = false;
            this.createError = '';
            this.newDomain = {
                name: '',
                description: '',
                dkim_selectors: '',
                dmarc_report_mailbox: '',
            };
        },

        openEditDialog(domain) {
            this.editError = '';
            this.editDmarcReportMailboxLoaded = Object.prototype.hasOwnProperty.call(
                domain,
                'dmarc_report_mailbox'
            );
            this.editDomain = {
                name: domain.name,
                description: domain.description || '',
                dkim_selectors: Array.isArray(domain.dkim_selectors)
                    ? domain.dkim_selectors.join(', ')
                    : '',
                dmarc_report_mailbox: domain.dmarc_report_mailbox || '',
            };
            this.openEdit = true;
        },

        closeEdit() {
            this.openEdit = false;
            this.editError = '';
            this.editDomain = {
                name: '',
                description: '',
                dkim_selectors: '',
                dmarc_report_mailbox: '',
            };
            this.editDmarcReportMailboxLoaded = false;
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
                        dmarc_report_mailbox: this.newDomain.dmarc_report_mailbox || null,
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
                const payload = {
                    description: this.editDomain.description || null,
                    dkim_selectors: selectors,
                };
                if (this.editDmarcReportMailboxLoaded) {
                    payload.dmarc_report_mailbox = this.editDomain.dmarc_report_mailbox || null;
                }
                const response = await fetch(
                    `/api/v1/domains/domains/${encodeURIComponent(this.editDomain.name)}`,
                    {
                        method: 'PATCH',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(payload),
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

        normalizeDomain(domain) {
            const normalized = {
                name: domain.domain_name,
                dmarc_status: domain.dmarc_status ?? false,
                dmarc_policy: domain.dmarc_policy || 'Not configured',
                spf_status: domain.spf_status ?? false,
                dkim_status: domain.dkim_status ?? false,
                dns_pending: Boolean(domain.dns_pending),
                dns_cached: Boolean(domain.dns_cached),
                dns_checked_at: domain.dns_checked_at || null,
                reports_count: domain.report_count,
                emails_count: domain.total_emails,
                compliance_rate: domain.pass_rate,
                description: domain.description || '',
                dkim_selectors: Array.isArray(domain.dkim_selectors) ? domain.dkim_selectors : [],
            };
            if (Object.prototype.hasOwnProperty.call(domain, 'dmarc_report_mailbox')) {
                normalized.dmarc_report_mailbox = domain.dmarc_report_mailbox || '';
            }
            normalized.has_activity =
                Number(normalized.reports_count || 0) > 0 ||
                Number(normalized.emails_count || 0) > 0;

            return {
                ...normalized,
                detail_url: `/domains/${encodeURIComponent(normalized.name)}`,
                dmarc_status_class: this.dnsStatusClass(normalized, 'dmarc_status'),
                spf_status_class: this.dnsStatusClass(normalized, 'spf_status'),
                dkim_status_class: this.dnsStatusClass(normalized, 'dkim_status'),
            };
        },

        dnsStatusClass(domain, key) {
            if (domain.dns_pending) return 'bg-gray-400';
            return domain[key] ? 'bg-green-500' : 'bg-red-500';
        },

        dmarcStatusText(domain) {
            if (domain.dns_pending) return 'Pending DNS refresh';
            return domain.dmarc_policy || 'Not configured';
        },

        visibleDomains() {
            if (this.showEmptyDomains) {
                return this.domains;
            }
            return this.domains.filter((domain) => domain.has_activity);
        },

        hiddenEmptyDomainCount() {
            if (!this.showEmptyDomains && this.emptyDomainsHidden > 0) {
                return this.emptyDomainsHidden;
            }
            const localEmptyCount = this.domains.filter((domain) => !domain.has_activity).length;
            return Math.max(localEmptyCount, this.emptyDomainsCount || 0);
        },

        activeDomainCount() {
            return this.visibleDomains().length;
        },

        formatCount(value, noun) {
            const count = Number(value || 0);
            return `${count} ${noun}${count === 1 ? '' : 's'}`;
        },

        showEmptyDomainHint() {
            return (
                !this.loading &&
                !this.loadError &&
                this.hiddenEmptyDomainCount() > 0 &&
                this.activeDomainCount() === 0
            );
        },

        genericDnsStatusText(domain, key) {
            if (domain.dns_pending) return 'Pending';
            return domain[key] ? 'Configured' : 'Missing';
        },
    };
}

document.addEventListener('alpine:init', () => {
    Alpine.data('domainsApp', domainsApp);
});
