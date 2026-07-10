function providerDemo() {
    return {
        loading: true,
        error: '',
        expressionError: '',
        consoleData: null,
        accounts: [],
        plans: [],
        accountSearch: '',
        accountFilter: 'all',
        accountSort: 'risk',
        selectedAccountSlug: '',
        viewMode: 'provider',
        accountTab: 'overview',
        createAccountDialogOpen: false,
        userDialogOpen: false,
        impersonationDialogOpen: false,
        startingSupportSession: false,
        supportSession: null,
        supportSessionError: '',
        statusMessage: '',
        billingSavedAt: '',
        storageKey: 'dmarq-provider-console-v3',
        toastTimer: null,
        accountDraftError: '',
        userDraftError: '',
        accountDraft: {
            name: '',
            domain: '',
            plan_code: 'protect',
        },
        userDraft: {
            name: '',
            email: '',
            role: 'workspace_admin',
        },
        billingDraft: {},
        supportDraft: {
            target_user_id: '',
            target_user_email: '',
            reason: 'Kundensupport und Konfigurationsprüfung',
        },
        accountFilters: [
            {id: 'all', label: 'Alle'},
            {id: 'needs_attention', label: 'Handlungsbedarf'},
            {id: 'onboarding', label: 'Onboarding'},
            {id: 'billing', label: 'Billing offen'},
            {id: 'healthy', label: 'Stabil'},
        ],
        accountTabs: [
            {id: 'overview', label: 'Übersicht'},
            {id: 'domains', label: 'Domains'},
            {id: 'users', label: 'Benutzer'},
            {id: 'billing', label: 'Billing & Limits'},
            {id: 'activity', label: 'Aktivität'},
        ],

        init() {
            this.bindControls();
            this.installDemoExpressionErrorRibbon();
            this.load();
        },

        bindControls() {
            const root = this.$root || this.$el;
            if (!root) return;
            root.addEventListener('click', event => {
                if (!(event.target instanceof Element)) return;
                const target = event.target;

                if (target.closest('[data-provider-retry]')) {
                    this.load();
                    return;
                }
                if (target.closest('[data-provider-create-open]')) {
                    this.openCreateAccountDialog();
                    return;
                }
                if (target.closest('[data-provider-create-close]')) {
                    this.closeCreateAccountDialog();
                    return;
                }
                if (target.closest('[data-provider-user-open]')) {
                    this.openUserDialog();
                    return;
                }
                if (target.closest('[data-provider-user-close]')) {
                    this.closeUserDialog();
                    return;
                }
                if (target.closest('[data-provider-impersonation-open]')) {
                    this.openImpersonationDialog();
                    return;
                }
                if (target.closest('[data-provider-impersonation-close]')) {
                    this.closeImpersonationDialog();
                    return;
                }
                if (target.closest('[data-provider-back]')) {
                    this.returnToProvider();
                    return;
                }

                const filterButton = target.closest('[data-provider-account-filter]');
                if (filterButton) {
                    this.accountFilter = filterButton.dataset.providerAccountFilter || 'all';
                    return;
                }
                const accountButton = target.closest('[data-provider-account-open]');
                if (accountButton) {
                    this.openAccount(accountButton.dataset.providerAccountOpen);
                    return;
                }
                const accountTabButton = target.closest('[data-provider-account-tab]');
                if (accountTabButton) {
                    this.accountTab = accountTabButton.dataset.providerAccountTab || 'overview';
                    return;
                }
            });

            root.addEventListener('submit', event => {
                if (!(event.target instanceof HTMLFormElement)) return;
                if (event.target.matches('[data-provider-create-form]')) {
                    event.preventDefault();
                    this.createAccount();
                    return;
                }
                if (event.target.matches('[data-provider-user-form]')) {
                    event.preventDefault();
                    this.addUser();
                    return;
                }
                if (event.target.matches('[data-provider-billing-form]')) {
                    event.preventDefault();
                    this.saveBilling();
                    return;
                }
                if (event.target.matches('[data-provider-impersonation-form]')) {
                    event.preventDefault();
                    this.startSupportSession();
                }
            });

            document.addEventListener('keydown', event => {
                if (event.key !== 'Escape') return;
                this.closeCreateAccountDialog();
                this.closeUserDialog();
                this.closeImpersonationDialog();
            });
            window.addEventListener('hashchange', () => this.applyHash());
        },

        installDemoExpressionErrorRibbon() {
            if (document.documentElement.dataset.demoMode !== 'true') return;
            const originalError = console.error.bind(console);
            console.error = (...args) => {
                const message = args.map(value => String(value || '')).join(' ');
                if (message.includes('Alpine Expression Error')) {
                    this.expressionError = 'Die Provider-Oberfläche konnte einen Ausdruck nicht auswerten.';
                }
                originalError(...args);
            };
        },

        async load() {
            this.loading = true;
            this.error = '';
            try {
                const payload = await this.fetchProviderConsoleData();
                this.consoleData = payload.provider_console || {};
                this.accounts = this.clone(this.consoleData.accounts || []);
                this.plans = this.clone(this.consoleData.plans || []);
                const restored = this.restoreState();
                if (!restored || !this.selectedAccountSlug) {
                    this.selectedAccountSlug = this.accounts[0]?.slug || '';
                }
                this.ensureSelectedAccount();
                this.resetBillingDraft();
                this.applyHash();
            } catch (error) {
                this.consoleData = null;
                this.accounts = [];
                this.error = error.name === 'AbortError'
                    ? 'Der Provider-Datensatz hat zu lange gebraucht.'
                    : error.message || 'Provider-Daten sind nicht verfügbar.';
            } finally {
                this.loading = false;
            }
        },

        async fetchProviderConsoleData() {
            const controller = new AbortController();
            const timeout = setTimeout(() => controller.abort(), 10000);
            try {
                const response = await fetch('/api/v1/operator/provider-console', {
                    headers: {Accept: 'application/json'},
                    signal: controller.signal,
                });
                if (!response.ok) {
                    throw new Error('Provider-Console-Daten fehlen in diesem Deployment.');
                }
                return response.json();
            } finally {
                clearTimeout(timeout);
            }
        },

        get ready() {
            return Boolean(this.consoleData) && !this.loading && !this.error;
        },

        get demoMode() {
            return Boolean(this.consoleData?.demo_mode);
        },

        get providerIdentityLabel() {
            return `${this.consoleData?.provider?.name || 'DMARQ Provider'} · Site Manager`;
        },

        get revenueContextLabel() {
            return this.demoMode ? 'simulierte Provider-Abrechnung' : 'aktive Vertragswerte';
        },

        get accountCreateContextLabel() {
            return this.demoMode
                ? 'Die Demo erstellt einen vollständigen Account für diese Browser-Sitzung.'
                : 'Organisation, Workspace, Domain, Subscription und Billing-Profil werden dauerhaft angelegt.';
        },

        get userInviteActionLabel() {
            return this.demoMode ? 'Einladung simulieren' : 'Benutzer einladen';
        },

        get showProviderView() {
            return this.viewMode === 'provider';
        },

        get showAccountView() {
            return this.viewMode === 'account';
        },

        get showCreateAccountDialog() {
            return this.createAccountDialogOpen;
        },

        get showUserDialog() {
            return this.userDialogOpen;
        },

        get showImpersonationDialog() {
            return this.impersonationDialogOpen;
        },

        get selectedAccount() {
            return this.accounts.find(account => account.slug === this.selectedAccountSlug)
                || this.accounts[0]
                || this.emptyAccount();
        },

        get filteredAccounts() {
            const needle = this.accountSearch.trim().toLowerCase();
            const filtered = this.accounts.filter(account => {
                if (!this.accountMatchesFilter(account)) return false;
                if (!needle) return true;
                const domainNames = (account.domains || []).map(domain => domain.name).join(' ');
                return [
                    account.name,
                    account.short_name,
                    account.customer_number,
                    account.plan_label,
                    account.status,
                    account.health,
                    domainNames,
                ].some(value => String(value || '').toLowerCase().includes(needle));
            });
            return filtered.sort((left, right) => this.compareAccounts(left, right));
        },

        get showNoAccounts() {
            return this.filteredAccounts.length === 0;
        },

        get accountCount() {
            return this.accounts.length;
        },

        get activeAccountCount() {
            return this.accounts.filter(account => account.status === 'active').length;
        },

        get activeAccountCountLabel() {
            return `${this.activeAccountCount} aktiv`;
        },

        get atRiskAccountCount() {
            return this.accounts.filter(account => ['critical', 'warning', 'attention'].includes(account.health)).length;
        },

        get messageVolume() {
            return this.accounts.reduce((sum, account) => sum + Number(account.usage?.messages_30d || 0), 0);
        },

        get messageVolumeLabel() {
            return this.compactNumber(this.messageVolume);
        },

        get domainCount() {
            return this.accounts.reduce((sum, account) => sum + (account.domains || []).length, 0);
        },

        get domainCountLabel() {
            return `${this.domainCount} überwachte Domains`;
        },

        get providerComplianceLabel() {
            const weighted = this.accounts.reduce((sum, account) => {
                return sum + Number(account.usage?.messages_30d || 0) * Number(account.usage?.compliance_rate || 0);
            }, 0);
            const rate = this.messageVolume ? weighted / this.messageVolume : 0;
            return `${rate.toLocaleString('de-DE', {minimumFractionDigits: 1, maximumFractionDigits: 1})} %`;
        },

        get providerRevenueLabel() {
            const cents = this.accounts.reduce((sum, account) => {
                if (account.billing?.status === 'trial') return sum;
                return sum + Number(account.billing?.monthly_charge_cents || 0);
            }, 0);
            return this.formatMoney(cents);
        },

        get showAccountOverview() {
            return this.accountTab === 'overview';
        },

        get showAccountDomains() {
            return this.accountTab === 'domains';
        },

        get showAccountUsers() {
            return this.accountTab === 'users';
        },

        get showAccountBilling() {
            return this.accountTab === 'billing';
        },

        get showAccountActivity() {
            return this.accountTab === 'activity';
        },

        get selectedAccountMessageLabel() {
            return this.formatNumber(this.selectedAccount.usage?.messages_30d || 0);
        },

        get selectedAccountComplianceLabel() {
            return this.accountComplianceLabel(this.selectedAccount);
        },

        get selectedAccountResourceLabel() {
            return `${this.accountDomainCount(this.selectedAccount)} / ${this.accountUserCount(this.selectedAccount)}`;
        },

        get selectedAccountRevenueLabel() {
            return this.formatMoney(this.selectedAccount.billing?.monthly_charge_cents || 0);
        },

        get selectedAccountOnboardingLabel() {
            const onboarding = this.selectedAccount.onboarding || {};
            return `${onboarding.completed_steps || 0} von ${onboarding.total_steps || 0} Schritten`;
        },

        get selectedAccountUserLimitLabel() {
            const users = this.selectedAccount.entitlements?.users || {};
            return `${users.used || 0} von ${users.included || 0} Plätzen belegt.`;
        },

        get billingSavedLabel() {
            if (this.billingSavedAt) {
                return `${this.demoMode ? 'Lokal gespeichert' : 'Gespeichert'} · ${this.billingSavedAt}`;
            }
            return this.demoMode
                ? 'Demo-Änderungen bleiben in dieser Sitzung.'
                : 'Plan- und Billing-Änderungen werden dauerhaft gespeichert.';
        },

        get impersonationUsers() {
            return (this.selectedAccount.users || []).filter(user => user.can_impersonate);
        },

        get supportSafeguards() {
            return this.consoleData?.support_access_demo?.safeguards || [];
        },

        accountMatchesFilter(account) {
            if (this.accountFilter === 'all') return true;
            if (this.accountFilter === 'needs_attention') {
                return ['critical', 'warning', 'attention'].includes(account.health);
            }
            if (this.accountFilter === 'onboarding') return account.status === 'onboarding';
            if (this.accountFilter === 'billing') {
                return ['past_due', 'grace_period'].includes(account.billing?.status);
            }
            if (this.accountFilter === 'healthy') return account.health === 'healthy';
            return true;
        },

        applyHash() {
            const hash = window.location.hash.replace('#', '');
            if (!hash) return;
            this.viewMode = 'provider';
            this.supportSession = null;
            this.accountFilter = hash === 'billing' ? 'billing' : 'all';
            this.persistState();
            if (hash === 'accounts' || hash === 'billing') {
                requestAnimationFrame(() => document.getElementById('accounts')?.scrollIntoView({block: 'start'}));
            }
        },

        compareAccounts(left, right) {
            if (this.accountSort === 'name') return left.name.localeCompare(right.name, 'de');
            if (this.accountSort === 'volume') return Number(right.usage?.messages_30d || 0) - Number(left.usage?.messages_30d || 0);
            if (this.accountSort === 'revenue') return Number(right.billing?.monthly_charge_cents || 0) - Number(left.billing?.monthly_charge_cents || 0);
            const rank = {critical: 0, warning: 1, attention: 2, monitoring: 3, healthy: 4};
            return (rank[left.health] ?? 9) - (rank[right.health] ?? 9) || left.name.localeCompare(right.name, 'de');
        },

        accountFilterClass(filter) {
            return this.accountFilter === filter.id
                ? 'btn-primary'
                : 'btn-ghost border border-base-300';
        },

        accountTabClass(tab) {
            return this.accountTab === tab.id
                ? 'border-[#272a5f] text-[#272a5f]'
                : 'border-transparent text-base-content/55 hover:text-base-content';
        },

        openAccount(slug) {
            if (!this.accounts.some(account => account.slug === slug)) return;
            if (window.location.hash) {
                window.history.replaceState(
                    null,
                    '',
                    `${window.location.pathname}${window.location.search}`
                );
            }
            this.selectedAccountSlug = slug;
            this.viewMode = 'account';
            this.accountTab = 'overview';
            this.supportSession = null;
            this.resetBillingDraft();
            this.persistState();
            window.scrollTo({top: 0, behavior: 'smooth'});
        },

        returnToProvider() {
            this.viewMode = 'provider';
            this.supportSession = null;
            this.persistState();
            window.scrollTo({top: 0, behavior: 'smooth'});
        },

        openCreateAccountDialog() {
            this.accountDraftError = '';
            this.createAccountDialogOpen = true;
        },

        closeCreateAccountDialog() {
            this.createAccountDialogOpen = false;
            this.accountDraftError = '';
        },

        openUserDialog() {
            this.userDraftError = '';
            this.userDialogOpen = true;
        },

        closeUserDialog() {
            this.userDialogOpen = false;
            this.userDraftError = '';
        },

        openImpersonationDialog() {
            this.supportSessionError = '';
            const firstUser = this.impersonationUsers[0];
            if (!firstUser) {
                this.showStatus('Für diesen Account ist kein impersonierbarer Benutzer vorhanden.');
                return;
            }
            this.supportDraft = {
                target_user_id: String(firstUser.id),
                target_user_email: firstUser.email,
                reason: 'Kundensupport und Konfigurationsprüfung',
            };
            this.impersonationDialogOpen = true;
        },

        closeImpersonationDialog() {
            if (this.startingSupportSession) return;
            this.impersonationDialogOpen = false;
            this.supportSessionError = '';
        },

        async createAccount() {
            this.accountDraftError = '';
            const name = this.accountDraft.name.trim();
            const domain = this.normalizeDomain(this.accountDraft.domain);
            if (!name || !domain || !this.isValidDomain(domain)) {
                this.accountDraftError = 'Bitte Firmenname und eine gültige Domain eintragen.';
                return;
            }
            if (this.accounts.some(account => (account.domains || []).some(item => item.name === domain))) {
                this.accountDraftError = 'Diese Domain gehört bereits zu einem Kundenkonto.';
                return;
            }
            const plan = this.plans.find(item => item.code === this.accountDraft.plan_code) || this.plans[0] || {};
            const slug = this.uniqueSlug(name);
            if (!this.demoMode) {
                try {
                    const now = Date.now();
                    const customerNumber = `DM-${now}`;
                    const response = await fetch('/api/v1/provider/customers', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json', Accept: 'application/json'},
                        body: JSON.stringify({
                            provider_id: this.consoleData.provider?.slug || 'dmarq-provider',
                            external_customer_id: customerNumber,
                            external_subscription_id: `sub-${slug}-${now}`,
                            organization_slug: slug,
                            organization_name: name,
                            workspace_slug: slug,
                            workspace_name: `${name} Mail Security`,
                            plan_code: plan.code || 'starter',
                            external_product_code: plan.code || 'starter',
                            external_event_id: `console-create-${slug}-${now}`,
                            payload_summary: 'Created through the DMARQ provider console',
                            primary_domain: domain,
                            dmarc_report_mailbox: `dmarc@${domain}`,
                            invoice_reference: customerNumber,
                            invoice_delivery_mode: 'provider_invoice',
                            billing_contact_email: `billing@${domain}`,
                            monthly_price_cents: Number(plan.monthly_charge_cents || 0),
                        }),
                    });
                    if (!response.ok) {
                        const payload = await response.json().catch(() => ({}));
                        throw new Error(this.apiErrorMessage(payload, 'Kundenkonto konnte nicht angelegt werden.'));
                    }
                    sessionStorage.removeItem(this.storageKey);
                    await this.load();
                    this.openAccount(slug);
                    this.closeCreateAccountDialog();
                    this.showStatus('Kundenkonto wurde angelegt.');
                } catch (error) {
                    this.accountDraftError = error.message || 'Kundenkonto konnte nicht angelegt werden.';
                }
                return;
            }
            const now = new Date().toISOString();
            const account = {
                id: `acct-${slug}`,
                slug,
                customer_number: `NS-DEMO-${String(this.accounts.length + 1).padStart(3, '0')}`,
                name,
                short_name: name,
                status: 'onboarding',
                health: 'monitoring',
                plan_code: plan.code || 'monitor',
                plan_label: plan.label || 'DMARQ Monitor',
                created_at: now,
                last_activity_at: now,
                primary_contact: {name: 'Account Admin', email: `admin@${domain}`, phone: ''},
                billing: {
                    status: 'trial',
                    invoice_owner: 'Northstar ISP',
                    billing_contact: `billing@${domain}`,
                    collection_model: 'provider_pass_through',
                    payment_rail: 'isp_monthly_invoice',
                    invoice_reference: `NS-DEMO-${this.accounts.length + 1}`,
                    monthly_charge_cents: 0,
                    next_invoice_at: this.daysFromNow(30),
                },
                usage: {messages_30d: 0, reports_30d: 0, compliance_rate: 0, change_percent: 0},
                entitlements: {
                    domains: {used: 1, included: Number(plan.domains || 5)},
                    users: {used: 1, included: Number(plan.users || 10)},
                    messages: {used: 0, included: Number(plan.messages || 500000)},
                    retention_days: {used: 0, included: Number(plan.retention_days || 90)},
                },
                onboarding: {completed_steps: 1, total_steps: 5, next_step: 'Ersten DMARC-Report importieren und DNS-Besitz bestätigen.'},
                recommended_action: 'Reporting-Ziel und DNS-Besitz bestätigen, bevor eine Policy empfohlen wird.',
                domains: [{
                    name: domain,
                    health: 'monitoring',
                    policy: 'none',
                    compliance_rate: 0,
                    messages_30d: 0,
                    reports_30d: 0,
                    source_count: 0,
                    spf_alignment: 0,
                    dkim_alignment: 0,
                    last_report_at: null,
                    open_findings: ['Noch keine Aggregate-Reports eingegangen.'],
                }],
                users: [{
                    id: `usr-${slug}-admin`,
                    name: 'Account Admin',
                    email: `admin@${domain}`,
                    role: 'organization_owner',
                    status: 'invited',
                    last_active_at: null,
                    mfa_enabled: false,
                    can_impersonate: true,
                }],
                reports: [],
                activity: [{id: `${slug}-created`, occurred_at: now, actor: 'Sofia Weber', action: 'account.created', summary: 'Kundenkonto in der Demo angelegt.'}],
                settings: {report_mailbox: `dmarc@${domain}`, timezone: 'Europe/Berlin', weekly_digest: true, ai_redaction: 'strict'},
            };
            this.accounts.unshift(account);
            this.accountDraft = {name: '', domain: '', plan_code: 'protect'};
            this.closeCreateAccountDialog();
            this.openAccount(slug);
            this.showStatus('Kundenkonto wurde in der Demo angelegt.');
        },

        async addUser() {
            this.userDraftError = '';
            const name = this.userDraft.name.trim();
            const email = this.userDraft.email.trim().toLowerCase();
            if (!name || !this.isValidEmail(email)) {
                this.userDraftError = 'Bitte Name und eine gültige E-Mail-Adresse eintragen.';
                return;
            }
            if ((this.selectedAccount.users || []).some(user => user.email.toLowerCase() === email)) {
                this.userDraftError = 'Diese E-Mail existiert bereits in diesem Kundenkonto.';
                return;
            }
            const limit = Number(this.selectedAccount.entitlements?.users?.included || 0);
            if (limit && this.selectedAccount.users.length >= limit) {
                this.userDraftError = `Das Benutzerlimit von ${limit} Plätzen ist erreicht.`;
                return;
            }
            if (!this.demoMode) {
                const workspaceRole = {
                    organization_owner: 'workspace_owner',
                    workspace_admin: 'workspace_owner',
                    security_analyst: 'analyst',
                    billing_admin: 'auditor',
                }[this.userDraft.role] || this.userDraft.role;
                try {
                    const workspaceResponse = await fetch(
                        `/api/v1/memberships/workspaces/${this.selectedAccount.workspace_id}/invites`,
                        {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json', Accept: 'application/json'},
                            body: JSON.stringify({email, full_name: name, role: workspaceRole}),
                        }
                    );
                    if (!workspaceResponse.ok) {
                        const payload = await workspaceResponse.json().catch(() => ({}));
                        throw new Error(this.apiErrorMessage(payload, 'Benutzer konnte nicht eingeladen werden.'));
                    }
                    if (['organization_owner', 'billing_admin'].includes(this.userDraft.role)) {
                        const organizationResponse = await fetch(
                            `/api/v1/memberships/organizations/${this.selectedAccount.organization_id}/invites`,
                            {
                                method: 'POST',
                                headers: {'Content-Type': 'application/json', Accept: 'application/json'},
                                body: JSON.stringify({email, full_name: name, role: this.userDraft.role}),
                            }
                        );
                        if (!organizationResponse.ok) {
                            const payload = await organizationResponse.json().catch(() => ({}));
                            throw new Error(this.apiErrorMessage(payload, 'Organisationsrolle konnte nicht gesetzt werden.'));
                        }
                    }
                    sessionStorage.removeItem(this.storageKey);
                    const accountSlug = this.selectedAccount.slug;
                    await this.load();
                    this.openAccount(accountSlug);
                    this.accountTab = 'users';
                    this.closeUserDialog();
                    this.showStatus('Benutzer wurde eingeladen.');
                } catch (error) {
                    this.userDraftError = error.message || 'Benutzer konnte nicht eingeladen werden.';
                }
                return;
            }
            this.selectedAccount.users.push({
                id: `usr-${this.selectedAccount.slug}-${Date.now()}`,
                name,
                email,
                role: this.userDraft.role,
                status: 'invited',
                last_active_at: null,
                mfa_enabled: false,
                can_impersonate: ['organization_owner', 'workspace_admin', 'security_analyst'].includes(this.userDraft.role),
            });
            this.selectedAccount.entitlements.users.used = this.selectedAccount.users.length;
            this.selectedAccount.activity.unshift({
                id: `${this.selectedAccount.slug}-invite-${Date.now()}`,
                occurred_at: new Date().toISOString(),
                actor: 'Sofia Weber',
                action: 'user.invited',
                summary: `${email} wurde als ${this.roleLabel(this.userDraft.role)} eingeladen.`,
            });
            this.userDraft = {name: '', email: '', role: 'workspace_admin'};
            this.closeUserDialog();
            this.persistState();
            this.showStatus('Benutzereinladung wurde lokal simuliert.');
        },

        resetBillingDraft() {
            const billing = this.selectedAccount.billing || {};
            this.billingDraft = {
                plan_code: this.selectedAccount.plan_code || this.plans[0]?.code || 'monitor',
                status: billing.status || 'current',
                monthly_euros: Math.round(Number(billing.monthly_charge_cents || 0) / 100),
                billing_contact: billing.billing_contact || '',
                invoice_reference: billing.invoice_reference || '',
                collection_model: billing.collection_model || 'provider_pass_through',
            };
            this.billingSavedAt = '';
        },

        async saveBilling() {
            const account = this.selectedAccount;
            const plan = this.plans.find(item => item.code === this.billingDraft.plan_code) || {};
            if (!this.demoMode) {
                try {
                    const now = Date.now();
                    const response = await fetch('/api/v1/provider/customers', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json', Accept: 'application/json'},
                        body: JSON.stringify({
                            provider_id: account.billing.provider_id || this.consoleData.provider?.slug || 'dmarq-provider',
                            external_customer_id: account.customer_number,
                            external_subscription_id: account.billing.external_subscription_id,
                            organization_slug: account.slug,
                            organization_name: account.name,
                            workspace_slug: account.slug,
                            workspace_name: `${account.short_name || account.name} Mail Security`,
                            plan_code: this.billingDraft.plan_code,
                            external_product_code: this.billingDraft.plan_code,
                            external_event_id: `console-billing-${account.slug}-${now}`,
                            payload_summary: 'Updated through the DMARQ provider console',
                            invoice_reference: this.billingDraft.invoice_reference.trim(),
                            invoice_delivery_mode: 'provider_invoice',
                            billing_contact_email: this.billingDraft.billing_contact.trim(),
                            monthly_price_cents: Number(this.billingDraft.monthly_euros || 0) * 100,
                        }),
                    });
                    if (!response.ok) {
                        const payload = await response.json().catch(() => ({}));
                        throw new Error(this.apiErrorMessage(payload, 'Billing konnte nicht gespeichert werden.'));
                    }
                    const statusValue = {
                        current: 'active',
                        trial: 'trialing',
                        grace_period: 'past_due_provider_reported',
                        past_due: 'past_due_provider_reported',
                    }[this.billingDraft.status] || 'active';
                    const statusResponse = await fetch(
                        `/api/v1/provider/subscriptions/${encodeURIComponent(account.billing.external_subscription_id)}/state`,
                        {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json', Accept: 'application/json'},
                            body: JSON.stringify({
                                status: statusValue,
                                provider_id: account.billing.provider_id || this.consoleData.provider?.slug,
                                external_event_id: `console-status-${account.slug}-${now}`,
                                payload_summary: 'Updated through the DMARQ provider console',
                            }),
                        }
                    );
                    if (!statusResponse.ok) {
                        const payload = await statusResponse.json().catch(() => ({}));
                        throw new Error(this.apiErrorMessage(payload, 'Billing-Status konnte nicht gespeichert werden.'));
                    }
                    sessionStorage.removeItem(this.storageKey);
                    const accountSlug = account.slug;
                    await this.load();
                    this.openAccount(accountSlug);
                    this.accountTab = 'billing';
                    this.billingSavedAt = new Date().toLocaleTimeString('de-DE', {hour: '2-digit', minute: '2-digit'});
                    this.showStatus('Billing und Planlimits wurden gespeichert.');
                } catch (error) {
                    this.showStatus(error.message || 'Billing konnte nicht gespeichert werden.');
                }
                return;
            }
            account.plan_code = this.billingDraft.plan_code;
            account.plan_label = plan.label || account.plan_label;
            account.billing.status = this.billingDraft.status;
            account.billing.monthly_charge_cents = Number(this.billingDraft.monthly_euros || 0) * 100;
            account.billing.billing_contact = this.billingDraft.billing_contact.trim();
            account.billing.invoice_reference = this.billingDraft.invoice_reference.trim();
            account.billing.collection_model = this.billingDraft.collection_model;
            if (plan.domains) account.entitlements.domains.included = Number(plan.domains);
            if (plan.users) account.entitlements.users.included = Number(plan.users);
            if (plan.messages) account.entitlements.messages.included = Number(plan.messages);
            if (plan.retention_days) account.entitlements.retention_days.included = Number(plan.retention_days);
            account.activity.unshift({
                id: `${account.slug}-billing-${Date.now()}`,
                occurred_at: new Date().toISOString(),
                actor: 'Sofia Weber',
                action: 'billing.updated',
                summary: `${account.plan_label}, ${this.billingStatusLabel(account.billing.status)}, ${this.formatMoney(account.billing.monthly_charge_cents)} monatlich.`,
            });
            this.billingSavedAt = new Date().toLocaleTimeString('de-DE', {hour: '2-digit', minute: '2-digit'});
            this.persistState();
            this.showStatus('Billing und Planlimits wurden lokal aktualisiert.');
        },

        async startSupportSession() {
            this.supportSessionError = '';
            const reason = this.supportDraft.reason.trim();
            const targetUser = this.impersonationUsers.find(
                user => String(user.id) === String(this.supportDraft.target_user_id)
                    || user.email === this.supportDraft.target_user_email
            );
            if (!reason || !targetUser || !this.selectedAccount.workspace_id) {
                this.supportSessionError = 'Zielbenutzer und Grund sind erforderlich.';
                return;
            }
            this.startingSupportSession = true;
            try {
                const response = await fetch('/api/v1/operator/support-session', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json', Accept: 'application/json'},
                    body: JSON.stringify({
                        workspace_id: Number(this.selectedAccount.workspace_id),
                        target_user_id: Number(targetUser.id),
                        reason,
                        access_mode: this.demoMode ? 'read_only' : 'role_scoped',
                    }),
                });
                if (!response.ok) {
                    const payload = await response.json().catch(() => ({}));
                    throw new Error(payload.detail || 'Support-Sitzung konnte nicht gestartet werden.');
                }
                const payload = await response.json();
                this.supportSession = payload.session;
                this.impersonationDialogOpen = false;
                this.persistState();
                localStorage.setItem('dmarq.selectedWorkspaceId', String(this.selectedAccount.workspace_id));
                window.location.assign('/dashboard');
            } catch (error) {
                this.supportSessionError = error.message || 'Support-Sitzung konnte nicht gestartet werden.';
            } finally {
                this.startingSupportSession = false;
            }
        },

        persistState() {
            try {
                sessionStorage.setItem(this.storageKey, JSON.stringify({
                    accounts: this.demoMode ? this.accounts : undefined,
                    selectedAccountSlug: this.selectedAccountSlug,
                    viewMode: this.viewMode,
                    accountTab: this.accountTab,
                    supportSession: this.supportSession,
                }));
            } catch (error) {
                console.warn('Provider demo state could not be saved', error);
            }
        },

        restoreState() {
            try {
                const raw = sessionStorage.getItem(this.storageKey);
                if (!raw) return false;
                const state = JSON.parse(raw);
                if (this.demoMode && Array.isArray(state.accounts) && state.accounts.length) {
                    this.accounts = state.accounts;
                }
                this.selectedAccountSlug = state.selectedAccountSlug || this.accounts[0]?.slug || '';
                this.viewMode = ['provider', 'account'].includes(state.viewMode) ? state.viewMode : 'provider';
                this.accountTab = state.accountTab || 'overview';
                this.supportSession = state.supportSession || null;
                return true;
            } catch (error) {
                sessionStorage.removeItem(this.storageKey);
                return false;
            }
        },

        ensureSelectedAccount() {
            if (!this.accounts.some(account => account.slug === this.selectedAccountSlug)) {
                this.selectedAccountSlug = this.accounts[0]?.slug || '';
                this.viewMode = 'provider';
                this.supportSession = null;
            }
        },

        showStatus(message) {
            this.statusMessage = message;
            if (this.toastTimer) clearTimeout(this.toastTimer);
            this.toastTimer = setTimeout(() => {
                this.statusMessage = '';
            }, 4200);
        },

        accountIdentityLabel(account) {
            const domain = account.domains?.[0]?.name || 'keine Domain';
            return `${account.customer_number} · ${domain}`;
        },

        accountDomainCount(account) {
            const count = (account.domains || []).length;
            return `${count} ${count === 1 ? 'Domain' : 'Domains'}`;
        },

        accountUserCount(account) {
            const count = (account.users || []).length;
            return `${count} ${count === 1 ? 'Benutzer' : 'Benutzer'}`;
        },

        accountMessageLabel(account) {
            return this.compactNumber(account.usage?.messages_30d || 0);
        },

        accountComplianceLabel(account) {
            return `${Number(account.usage?.compliance_rate || 0).toLocaleString('de-DE', {minimumFractionDigits: 1, maximumFractionDigits: 1})} %`;
        },

        domainComplianceLabel(domain) {
            return `${Number(domain.compliance_rate || 0).toLocaleString('de-DE', {minimumFractionDigits: 1, maximumFractionDigits: 1})} %`;
        },

        domainMessageLabel(domain) {
            return this.formatNumber(domain.messages_30d || 0);
        },

        domainFindingsLabel(domain) {
            const findings = domain.open_findings || [];
            return findings.length ? findings.join(' · ') : 'Keine offenen Hinweise';
        },

        spfLabel(domain) {
            return `${Number(domain.spf_alignment || 0).toLocaleString('de-DE', {minimumFractionDigits: 1, maximumFractionDigits: 1})} %`;
        },

        dkimLabel(domain) {
            return `${Number(domain.dkim_alignment || 0).toLocaleString('de-DE', {minimumFractionDigits: 1, maximumFractionDigits: 1})} %`;
        },

        healthLabel(value) {
            return {
                healthy: 'Stabil',
                monitoring: 'Monitoring',
                warning: 'Auffällig',
                attention: 'Prüfen',
                critical: 'Kritisch',
            }[value] || 'Unbekannt';
        },

        healthClass(value) {
            return {
                healthy: 'bg-[#e6f6ef] text-[#0f6b4d]',
                monitoring: 'bg-[#e7f4f6] text-[#256c74]',
                warning: 'bg-[#fff0db] text-[#8a5200]',
                attention: 'bg-[#fff0db] text-[#8a5200]',
                critical: 'bg-[#ffe9e2] text-[#9b3210]',
            }[value] || 'bg-base-200 text-base-content/70';
        },

        billingStatusLabel(value) {
            return {
                current: 'Aktuell',
                trial: 'Testphase',
                grace_period: 'Grace Period',
                past_due: 'Überfällig',
            }[value] || 'Unbekannt';
        },

        billingStatusClass(value) {
            return {
                current: 'bg-[#e6f6ef] text-[#0f6b4d]',
                trial: 'bg-[#e7f4f6] text-[#256c74]',
                grace_period: 'bg-[#fff0db] text-[#8a5200]',
                past_due: 'bg-[#ffe9e2] text-[#9b3210]',
            }[value] || 'bg-base-200 text-base-content/70';
        },

        accountStatusLabel(value) {
            return {active: 'Aktiv', onboarding: 'Onboarding', suspended: 'Pausiert'}[value] || value;
        },

        policyLabel(value) {
            return {none: 'p=none', quarantine: 'p=quarantine', reject: 'p=reject'}[value] || value;
        },

        roleLabel(value) {
            return {
                organization_owner: 'Organisationsinhaber',
                organization_admin: 'Organisations-Admin',
                workspace_owner: 'Workspace-Inhaber',
                workspace_admin: 'Workspace-Admin',
                security_analyst: 'Security-Analyst',
                domain_admin: 'Domain-Admin',
                analyst: 'Analyst',
                operator: 'Operator',
                auditor: 'Auditor',
                billing_admin: 'Billing-Admin',
                site_manager: 'Site Manager',
            }[value] || value;
        },

        userStatusLabel(value) {
            return {active: 'Aktiv', invited: 'Eingeladen', disabled: 'Deaktiviert'}[value] || value;
        },

        mfaLabel(user) {
            return user.mfa_enabled ? 'Aktiv' : 'Nicht aktiv';
        },

        impersonationAccessLabel(user) {
            return user.can_impersonate ? 'Erlaubt' : 'Nicht erlaubt';
        },

        impersonationUserOptionLabel(user) {
            const supportRole = user.support_role || user.role;
            return `${user.name} · ${this.roleLabel(supportRole)} · ${user.email}`;
        },

        dateLabel(value) {
            if (!value) return 'Noch nie';
            const dateValue = new Date(value);
            if (Number.isNaN(dateValue.getTime())) return String(value);
            return dateValue.toLocaleDateString('de-DE', {day: '2-digit', month: '2-digit', year: 'numeric'});
        },

        dateTimeLabel(value) {
            if (!value) return 'Noch nie';
            const dateValue = new Date(value);
            if (Number.isNaN(dateValue.getTime())) return String(value);
            return dateValue.toLocaleString('de-DE', {day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit'});
        },

        formatNumber(value) {
            return Number(value || 0).toLocaleString('de-DE');
        },

        compactNumber(value) {
            return new Intl.NumberFormat('de-DE', {notation: 'compact', maximumFractionDigits: 1}).format(Number(value || 0));
        },

        formatMoney(cents) {
            return new Intl.NumberFormat('de-DE', {style: 'currency', currency: 'EUR', maximumFractionDigits: 0}).format(Number(cents || 0) / 100);
        },

        normalizeDomain(value) {
            return String(value || '').trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/$/, '');
        },

        isValidDomain(value) {
            return /^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(value);
        },

        isValidEmail(value) {
            return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
        },

        apiErrorMessage(payload, fallback) {
            const detail = payload?.detail;
            if (typeof detail === 'string' && detail.trim()) return detail;
            if (Array.isArray(detail) && detail.length) {
                return detail.map(item => item.msg || String(item)).join(' · ');
            }
            if (detail && typeof detail === 'object') return detail.message || fallback;
            return fallback;
        },

        uniqueSlug(name) {
            const base = String(name || '')
                .normalize('NFKD')
                .replace(/[\u0300-\u036f]/g, '')
                .toLowerCase()
                .replace(/[^a-z0-9]+/g, '-')
                .replace(/^-|-$/g, '') || 'customer';
            let slug = base;
            let suffix = 2;
            while (this.accounts.some(account => account.slug === slug)) {
                slug = `${base}-${suffix}`;
                suffix += 1;
            }
            return slug;
        },

        daysFromNow(days) {
            const value = new Date();
            value.setDate(value.getDate() + days);
            return value.toISOString().slice(0, 10);
        },

        clone(value) {
            return JSON.parse(JSON.stringify(value));
        },

        emptyAccount() {
            return {
                slug: '',
                name: '',
                customer_number: '',
                status: 'unknown',
                health: 'monitoring',
                plan_label: '',
                primary_contact: {},
                billing: {},
                usage: {},
                entitlements: {users: {}, retention_days: {}},
                onboarding: {},
                domains: [],
                users: [],
                reports: [],
                activity: [],
                settings: {},
            };
        },
    };
}

document.addEventListener('alpine:init', () => {
    Alpine.data('providerDemo', providerDemo);
});
