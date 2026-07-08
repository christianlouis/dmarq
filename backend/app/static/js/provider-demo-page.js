function providerDemo() {
    return {
        loading: false,
        error: '',
        deployment: null,
        tenants: [],
        tenantSearch: '',
        storageKey: 'dmarq-provider-demo-state-v1',
        hasLocalChanges: false,
        statusMessage: '',
        selectedTenantSlug: '',
        selectedWorkspaceSlug: '',
        drillInActive: false,
        activeTab: 'account',
        billingDraft: {},
        billingSavedAt: '',
        startingSupportSession: false,
        supportSessionResult: null,
        supportSessionError: '',
        tenantDraft: {
            name: '',
            domain: '',
            plan_tier: 'Business',
            collection_model: 'provider_pass_through',
        },
        userDraft: {
            name: '',
            email: '',
            role: 'workspace_admin',
        },
        userError: '',
        tabs: [
            {id: 'account', label: 'Account'},
            {id: 'billing', label: 'Billing'},
            {id: 'users', label: 'User'},
            {id: 'provider', label: 'Provider-Billing'},
        ],

        init() {
            this.bindControls();
            this.load();
        },

        bindControls() {
            const root = this.$root || this.$el;
            if (!root) return;
            root.addEventListener('click', event => {
                const refresh = event.target.closest('[data-provider-demo-refresh]');
                if (refresh) {
                    this.load({force: true});
                    return;
                }

                const createFocus = event.target.closest('[data-provider-demo-create-focus]');
                if (createFocus) {
                    this.focusCreateTenant();
                    return;
                }

                const tenantButton = event.target.closest('[data-provider-demo-tenant]');
                if (tenantButton) {
                    this.selectTenant(tenantButton.dataset.providerDemoTenant);
                    return;
                }

                const tabButton = event.target.closest('[data-provider-demo-tab]');
                if (tabButton) {
                    this.activeTab = tabButton.dataset.providerDemoTab;
                    return;
                }

                const workspaceButton = event.target.closest('[data-provider-demo-workspace]');
                if (workspaceButton) {
                    this.selectWorkspace(workspaceButton.dataset.providerDemoWorkspace);
                    if (workspaceButton.closest('[data-provider-demo-drill-workspace]')) {
                        this.enterTenantAccount();
                    }
                    return;
                }

                const drillButton = event.target.closest('[data-provider-demo-drill-account]');
                if (drillButton) {
                    this.enterTenantAccount();
                    return;
                }

                const providerButton = event.target.closest('[data-provider-demo-provider-console]');
                if (providerButton) {
                    this.drillInActive = false;
                    this.activeTab = 'provider';
                    return;
                }

                const usersButton = event.target.closest('[data-provider-demo-open-users]');
                if (usersButton) {
                    this.activeTab = 'users';
                    return;
                }

                const addWorkspaceButton = event.target.closest('[data-provider-demo-add-workspace]');
                if (addWorkspaceButton) {
                    this.addWorkspace();
                    return;
                }

                const supportButton = event.target.closest('[data-provider-demo-support-session]');
                if (supportButton) {
                    this.startSupportSession();
                }
            });
        },

        async load(options = {}) {
            const force = Boolean(options.force);
            if (force && this.hasLocalChanges && !window.confirm('Lokale Demo-Aenderungen verwerfen und Demo-Daten neu laden?')) {
                return;
            }
            this.loading = true;
            this.error = '';
            try {
                if (force) {
                    this.clearLocalState();
                }
                const controller = new AbortController();
                const timeout = setTimeout(() => controller.abort(), 10000);
                const response = await fetch('/api/v1/operator/demo/multi-user', {
                    headers: {Accept: 'application/json'},
                    signal: controller.signal,
                }).finally(() => clearTimeout(timeout));
                if (!response.ok) {
                    throw new Error('Provider console data is not available in this deployment.');
                }
                const payload = await response.json();
                this.deployment = payload.deployment || {};
                this.tenants = this.buildTenants(this.deployment.organizations || []);
                const restored = !force && this.restoreLocalState();
                if (!restored) {
                    const providerCustomer = this.tenants.find(tenant => tenant.billing_mode === 'provider_resale');
                    this.selectTenant(providerCustomer?.slug || this.tenants[0]?.slug || '');
                }
            } catch (error) {
                this.error = error.name === 'AbortError'
                    ? 'Provider console data request timed out.'
                    : error.message || 'Provider console could not be loaded.';
                this.deployment = null;
                this.tenants = [];
            } finally {
                this.loading = false;
            }
        },

        buildTenants(organizations) {
            return organizations.map(organization => {
                const providerCustomer = (organization.provider_customers || [])[0] || {};
                const billingProfile = organization.billing_profile || {};
                const entitlements = organization.entitlements || {};
                const tenant = {
                    ...this.clone(organization),
                    plan_tier: organization.plan_tier || providerCustomer.subscription_tier || 'Business',
                    billing_status: providerCustomer.billing_status || organization.billing_status || 'active',
                    monthly_charge_cents: Number(providerCustomer.monthly_charge_cents || 0),
                    billing_profile: {
                        invoice_owner: billingProfile.invoice_owner || 'Provider',
                        collection_model: billingProfile.collection_model || organization.billing_mode || 'provider_pass_through',
                        payment_rail: billingProfile.payment_rail || 'bank_transfer',
                        invoice_reference: billingProfile.invoice_reference || organization.slug || '',
                    },
                    entitlements: {
                        ...entitlements,
                        users: entitlements.users || {
                            used: (organization.users || []).length,
                            included: 25,
                        },
                        aggregate_messages: entitlements.aggregate_messages || {
                            used: this.aggregateMessages(organization),
                            included: 1_000_000,
                        },
                    },
                    users: this.clone(organization.users || []),
                    workspaces: this.clone(organization.workspaces || []),
                };
                this.syncProviderCustomer(tenant);
                return tenant;
            });
        },

        get ready() {
            return Boolean(this.deployment) && !this.loading;
        },

        get filteredTenants() {
            const needle = this.tenantSearch.trim().toLowerCase();
            if (!needle) return this.tenants;
            return this.tenants.filter(tenant => {
                return [
                    tenant.name,
                    tenant.slug,
                    tenant.plan_tier,
                    tenant.billing_status,
                    tenant.billing_mode,
                    tenant.billing_profile?.invoice_owner,
                ].some(value => String(value || '').toLowerCase().includes(needle));
            });
        },

        get selectedTenant() {
            return this.tenants.find(tenant => tenant.slug === this.selectedTenantSlug)
                || this.tenants[0]
                || this.emptyTenant();
        },

        get selectedWorkspace() {
            return (this.selectedTenant.workspaces || []).find(
                workspace => workspace.slug === this.selectedWorkspaceSlug,
            ) || (this.selectedTenant.workspaces || [])[0] || this.emptyWorkspace();
        },

        get selectedWorkspacePrimaryDomain() {
            return (this.selectedWorkspace.domains || [])[0] || '';
        },

        get selectedWorkspaceDomainHref() {
            return this.selectedWorkspacePrimaryDomain
                ? this.contextualHref(`/domains/${this.selectedWorkspacePrimaryDomain}`)
                : this.contextualHref('/domains');
        },

        get selectedWorkspaceReportsHref() {
            return this.contextualHref('/reports');
        },

        get providerCustomers() {
            return this.tenants
                .filter(tenant => this.isProviderBilledTenant(tenant))
                .map(tenant => this.providerCustomerFromTenant(tenant));
        },

        get supportAccessDemo() {
            return this.deployment?.support_access_demo || {};
        },

        get tenantCount() {
            return this.tenants.length;
        },

        get providerCustomerCount() {
            return this.providerCustomers.length;
        },

        get providerCustomerCountLabel() {
            return `${this.providerCustomerCount} Provider-Kunden`;
        },

        get workspaceCount() {
            return this.tenants.reduce((total, tenant) => total + (tenant.workspaces || []).length, 0);
        },

        get messageVolumeLabel() {
            const total = this.tenants.reduce((sum, tenant) => sum + this.aggregateMessages(tenant), 0);
            return this.compactNumber(total);
        },

        get providerRevenueLabel() {
            const cents = this.providerCustomers.reduce(
                (sum, customer) => sum + Number(customer.monthly_charge_cents || 0),
                0,
            );
            return this.formatMoney(cents);
        },

        get selectedTenantDomainCount() {
            const count = (this.selectedTenant.workspaces || []).reduce(
                (total, workspace) => total + (workspace.domains || []).length,
                0,
            );
            return `${count} Domains`;
        },

        get selectedTenantUserCountLabel() {
            return this.tenantUserLabel(this.selectedTenant);
        },

        get selectedTenantAction() {
            const health = this.selectedWorkspace.health || 'monitoring';
            return {
                healthy: 'Policy-Erhoehung planen oder woechentliches Monitoring bestaetigen.',
                monitoring: 'Unbekannte Sender pruefen, bevor ein strengerer DMARC-Policy-Schritt gesetzt wird.',
                warning: 'Sender-Remediation oeffnen und Frist im Mandantenplan setzen.',
                attention: 'Den staerksten Sender-Drift reparieren, bevor Billing- oder Policy-Aenderungen passieren.',
                critical: 'Nicht erzwingen. Erst DKIM/SPF-Ausrichtung und DNS-Lookups stabilisieren.',
            }[health] || 'Mandanten-Workspace pruefen, bevor die naechste Aktion ausgefuehrt wird.';
        },

        get drillInContextLabel() {
            if (!this.drillInActive) return '';
            return `${this.selectedTenant.name} / ${this.selectedWorkspace.name}`;
        },

        get billingSavedLabel() {
            return this.billingSavedAt ? `Gespeichert ${this.billingSavedAt}` : 'Demo-Aenderungen lokal';
        },

        get localChangesLabel() {
            return this.hasLocalChanges
                ? 'Lokale Simulation aktiv - Aenderungen bleiben in diesem Browser erhalten.'
                : '';
        },

        get supportSessionSummary() {
            const event = this.supportSessionResult?.audit_event;
            if (!event) return '';
            return `${event.operator_email} oeffnete ${event.domain} als ${event.target_user_email}; ${event.result}.`;
        },

        selectTenant(slug) {
            if (!slug) return;
            this.selectedTenantSlug = slug;
            this.selectedWorkspaceSlug = (this.selectedTenant.workspaces || [])[0]?.slug || '';
            this.resetBillingDraft();
            this.supportSessionResult = null;
            this.supportSessionError = '';
            this.userError = '';
            this.drillInActive = false;
        },

        selectWorkspace(workspaceSlug) {
            if (!workspaceSlug) return;
            const owningTenant = this.tenants.find(tenant => {
                return (tenant.workspaces || []).some(workspace => workspace.slug === workspaceSlug);
            });
            if (owningTenant) {
                this.selectedTenantSlug = owningTenant.slug;
            }
            this.selectedWorkspaceSlug = workspaceSlug;
            this.activeTab = 'account';
            this.resetBillingDraft();
            this.userError = '';
        },

        enterTenantAccount() {
            this.activeTab = 'account';
            this.drillInActive = true;
            this.statusMessage = `Mandantenkontext aktiv: ${this.selectedTenant.name}.`;
        },

        resetBillingDraft() {
            const tenant = this.selectedTenant;
            const profile = tenant.billing_profile || {};
            const userLimit = tenant.entitlements?.users?.included || tenant.users.length || 1;
            const messageLimit = tenant.entitlements?.aggregate_messages?.included || 0;
            this.billingDraft = {
                plan_tier: tenant.plan_tier || 'Business',
                invoice_owner: profile.invoice_owner || 'Provider',
                collection_model: profile.collection_model || 'provider_pass_through',
                payment_rail: profile.payment_rail || 'bank_transfer',
                invoice_reference: profile.invoice_reference || tenant.slug || '',
                monthly_euros: Math.round(Number(tenant.monthly_charge_cents || 0) / 100),
                user_limit: Number(userLimit),
                message_limit: Number(messageLimit),
            };
            this.billingSavedAt = '';
        },

        saveBilling() {
            const tenant = this.selectedTenant;
            tenant.plan_tier = this.billingDraft.plan_tier;
            tenant.billing_profile = {
                invoice_owner: this.billingDraft.invoice_owner,
                collection_model: this.billingDraft.collection_model,
                payment_rail: this.billingDraft.payment_rail,
                invoice_reference: this.billingDraft.invoice_reference,
            };
            tenant.billing_mode = this.billingModeForCollection(this.billingDraft.collection_model);
            tenant.monthly_charge_cents = Number(this.billingDraft.monthly_euros || 0) * 100;
            tenant.entitlements.users = {
                used: tenant.users.length,
                included: Number(this.billingDraft.user_limit || tenant.users.length || 1),
            };
            tenant.entitlements.aggregate_messages = {
                used: this.aggregateMessages(tenant),
                included: Number(this.billingDraft.message_limit || 0),
            };
            this.billingSavedAt = new Date().toLocaleTimeString('de-DE', {
                hour: '2-digit',
                minute: '2-digit',
            });
            this.syncProviderCustomer(tenant);
            this.persistLocalState('Billing-Settings wurden lokal gespeichert.');
        },

        createTenant() {
            const name = this.tenantDraft.name.trim();
            const domain = this.normalizeDomain(this.tenantDraft.domain);
            if (!name || !domain) return;
            const slug = this.uniqueSlug(name);
            const workspaceSlug = `${slug}-main`;
            const tenant = {
                slug,
                name,
                demo_story: 'Neu angelegter Demo-Mandant fuer Provider-Onboarding, Billing und Benutzerverwaltung.',
                billing_mode: this.tenantDraft.collection_model,
                billing_status: 'draft',
                plan_tier: this.tenantDraft.plan_tier,
                monthly_charge_cents: 0,
                billing_profile: {
                    invoice_owner: 'Provider',
                    collection_model: this.tenantDraft.collection_model,
                    payment_rail: 'bank_transfer',
                    invoice_reference: slug,
                },
                entitlements: {
                    users: {used: 1, included: 25},
                    aggregate_messages: {used: 0, included: 1_000_000},
                },
                usage: [],
                provider_customers: [],
                users: [
                    {
                        name: 'Mandanten Admin',
                        email: `admin@${domain}`,
                        roles: ['organization_owner'],
                        demo_persona: 'customer-admin',
                        can_impersonate: false,
                    },
                ],
                workspaces: [
                    {
                        slug: workspaceSlug,
                        name: 'Primary workspace',
                        health: 'monitoring',
                        domains: [domain],
                        primary_findings: [
                            'DMARC-Policy und Reporting-Ziel pruefen.',
                            'SPF/DKIM-Quellen vor Enforcement bestaetigen.',
                        ],
                    },
                ],
            };
            this.syncProviderCustomer(tenant);
            this.tenants.unshift(tenant);
            this.tenantDraft = {
                name: '',
                domain: '',
                plan_tier: 'Business',
                collection_model: 'provider_pass_through',
            };
            this.selectTenant(slug);
            this.activeTab = 'account';
            this.persistLocalState('Mandant wurde lokal angelegt.');
        },

        addUser() {
            this.userError = '';
            const name = this.userDraft.name.trim();
            const email = this.userDraft.email.trim().toLowerCase();
            if (!name || !email) {
                this.userError = 'Name und E-Mail sind erforderlich.';
                return;
            }
            if (!this.isValidEmail(email)) {
                this.userError = 'Bitte eine gueltige E-Mail-Adresse eintragen.';
                return;
            }
            const tenant = this.selectedTenant;
            if ((tenant.users || []).some(user => String(user.email || '').toLowerCase() === email)) {
                this.userError = 'Diese E-Mail existiert bereits in diesem Mandanten.';
                return;
            }
            const userLimit = Number(tenant.entitlements?.users?.included || 0);
            if (userLimit > 0 && (tenant.users || []).length >= userLimit) {
                this.userError = `User-Limit von ${userLimit} erreicht. Bitte zuerst das Billing-Limit erhoehen.`;
                return;
            }
            tenant.users.push({
                name,
                email,
                roles: [this.userDraft.role],
                demo_persona: this.userDraft.role === 'provider_operator' ? 'isp-operator' : 'customer-admin',
                can_impersonate: this.userDraft.role === 'provider_operator',
            });
            tenant.entitlements.users = {
                ...(tenant.entitlements.users || {}),
                used: tenant.users.length,
            };
            this.userDraft = {
                name: '',
                email: '',
                role: 'workspace_admin',
            };
            this.persistLocalState('User wurde lokal angelegt.');
        },

        addWorkspace() {
            const tenant = this.selectedTenant;
            const index = (tenant.workspaces || []).length + 1;
            const slug = `${tenant.slug}-workspace-${index}`;
            tenant.workspaces.push({
                slug,
                name: `Workspace ${index}`,
                health: 'monitoring',
                domains: [`workspace-${index}.${tenant.slug}.example`],
                primary_findings: [
                    'Neue Domain importieren und DNS-Baseline pruefen.',
                    'Reporting-Adresse und Senderquellen bestaetigen.',
                ],
            });
            this.selectedWorkspaceSlug = slug;
            this.persistLocalState('Workspace wurde lokal angelegt.');
        },

        async startSupportSession() {
            this.startingSupportSession = true;
            this.supportSessionError = '';
            this.supportSessionResult = null;
            const primaryDomain = this.selectedWorkspacePrimaryDomain || 'example.invalid';
            const operator = (this.tenants.flatMap(tenant => tenant.users || [])).find(user => user.can_impersonate)
                || (this.selectedTenant.users || [])[0]
                || {email: 'operator@provider.example'};
            const targetUser = (this.selectedTenant.users || [])[0] || {email: `admin@${primaryDomain}`};
            this.supportSessionResult = {
                result: 'demo_session_ready',
                audit_event: {
                    operator_email: operator.email,
                    target_user_email: targetUser.email,
                    domain: primaryDomain,
                    workspace_slug: this.selectedWorkspace.slug,
                    result: 'demo_session_ready',
                },
            };
            this.startingSupportSession = false;
        },

        focusCreateTenant() {
            this.$nextTick(() => {
                const field = this.$root?.querySelector('[data-provider-demo-create-form] input');
                if (field) field.focus();
            });
        },

        isSelectedTenant(tenant) {
            return tenant.slug === this.selectedTenantSlug;
        },

        isSelectedWorkspace(workspace) {
            return workspace.slug === this.selectedWorkspaceSlug;
        },

        tenantButtonClass(tenant) {
            return this.isSelectedTenant(tenant)
                ? 'border-[#272a5f] bg-[#f3f4ff]'
                : 'border-base-300 bg-white hover:border-[#39a0aa]';
        },

        tabButtonClass(tab) {
            return this.activeTab === tab.id ? 'btn-primary' : 'btn-outline';
        },

        workspaceButtonClass(workspace) {
            return this.isSelectedWorkspace(workspace)
                ? 'border-[#272a5f] bg-[#f3f4ff]'
                : 'border-base-300 bg-white hover:border-[#39a0aa]';
        },

        tenantWorkspaceLabel(tenant) {
            return `${(tenant.workspaces || []).length} Workspaces`;
        },

        tenantUserLabel(tenant) {
            return `${(tenant.users || []).length} User`;
        },

        userRolesLabel(user) {
            return (user.roles || []).map(role => this.humanize(role)).join(', ');
        },

        supportAccessClass(user) {
            return user.can_impersonate
                ? 'bg-[#eefaf6] text-[#0f6b4d]'
                : 'bg-base-200 text-base-content/60';
        },

        supportAccessLabel(user) {
            return user.can_impersonate ? 'erlaubt' : 'aus';
        },

        isProviderBilledTenant(tenant) {
            const collectionModel = tenant.billing_profile?.collection_model || tenant.billing_mode;
            return collectionModel === 'provider_pass_through' || tenant.billing_mode === 'provider_resale';
        },

        providerCustomerFromTenant(tenant) {
            const existing = (tenant.provider_customers || [])[0] || {};
            return {
                external_customer_id: existing.external_customer_id || `demo-${tenant.slug}`,
                workspace_slug: existing.workspace_slug || (tenant.workspaces || [])[0]?.slug || '',
                name: existing.name || tenant.name,
                billing_status: existing.billing_status || tenant.billing_status || 'active',
                subscription_tier: tenant.plan_tier || existing.subscription_tier || 'Business',
                monthly_charge_cents: Number(tenant.monthly_charge_cents || existing.monthly_charge_cents || 0),
                aggregate_messages: this.aggregateMessages(tenant),
            };
        },

        syncProviderCustomer(tenant) {
            if (!tenant) return;
            if (!this.isProviderBilledTenant(tenant)) {
                tenant.provider_customers = [];
                return;
            }
            tenant.provider_customers = [this.providerCustomerFromTenant(tenant)];
        },

        billingModeForCollection(collectionModel) {
            if (collectionModel === 'provider_pass_through') return 'provider_resale';
            if (collectionModel === 'self_service_subscription') return 'direct_stripe';
            if (collectionModel === 'contract_invoice') return 'contract_invoice';
            return collectionModel || 'none';
        },

        isValidEmail(email) {
            return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email || ''));
        },

        contextualHref(path) {
            const tenant = encodeURIComponent(this.selectedTenant.slug || '');
            const workspace = encodeURIComponent(this.selectedWorkspace.slug || '');
            const separator = String(path || '').includes('?') ? '&' : '?';
            return tenant && workspace
                ? `${path}${separator}tenant=${tenant}&workspace=${workspace}`
                : path;
        },

        healthClass(health) {
            return {
                healthy: 'bg-[#eefaf6] text-[#0f6b4d]',
                monitoring: 'bg-[#eef3ff] text-[#272a5f]',
                warning: 'bg-[#fff8e5] text-[#8a5a00]',
                attention: 'bg-[#fff8e5] text-[#8a5a00]',
                critical: 'bg-[#fff2ec] text-[#8a2d0d]',
            }[health] || 'bg-base-200 text-base-content/70';
        },

        statusClass(status) {
            return {
                active: 'bg-[#eefaf6] text-[#0f6b4d]',
                included: 'bg-[#eefaf6] text-[#0f6b4d]',
                billable_addon: 'bg-[#eef3ff] text-[#272a5f]',
                grace_period: 'bg-[#fff8e5] text-[#8a5a00]',
                draft: 'bg-base-200 text-base-content/70',
            }[status] || 'bg-base-200 text-base-content/70';
        },

        humanize(value) {
            return String(value || '')
                .replace(/[_-]+/g, ' ')
                .replace(/\b\w/g, char => char.toUpperCase());
        },

        formatNumber(value) {
            return new Intl.NumberFormat('de-DE').format(Number(value || 0));
        },

        compactNumber(value) {
            return new Intl.NumberFormat('de-DE', {
                notation: 'compact',
                maximumFractionDigits: 1,
            }).format(Number(value || 0));
        },

        formatMoney(cents) {
            return new Intl.NumberFormat('de-DE', {
                style: 'currency',
                currency: 'EUR',
                maximumFractionDigits: 0,
            }).format(Number(cents || 0) / 100);
        },

        aggregateMessages(tenant) {
            return (tenant.usage || [])
                .filter(row => row.metric === 'aggregate_messages')
                .reduce((sum, row) => sum + Number(row.quantity || 0), 0);
        },

        normalizeDomain(value) {
            return String(value || '')
                .trim()
                .toLowerCase()
                .replace(/^https?:\/\//, '')
                .replace(/\/.*$/, '')
                .replace(/[^a-z0-9.-]+/g, '');
        },

        uniqueSlug(name) {
            const base = String(name || 'tenant')
                .trim()
                .toLowerCase()
                .replace(/[^a-z0-9]+/g, '-')
                .replace(/^-+|-+$/g, '') || 'tenant';
            let slug = base;
            let index = 2;
            const existing = new Set(this.tenants.map(tenant => tenant.slug));
            while (existing.has(slug)) {
                slug = `${base}-${index}`;
                index += 1;
            }
            return slug;
        },

        persistLocalState(message) {
            try {
                sessionStorage.setItem(this.storageKey, JSON.stringify({
                    tenants: this.tenants,
                    selectedTenantSlug: this.selectedTenantSlug,
                    selectedWorkspaceSlug: this.selectedWorkspaceSlug,
                    activeTab: this.activeTab,
                }));
                this.hasLocalChanges = true;
                this.statusMessage = message || 'Demo-Aenderung wurde lokal gespeichert.';
            } catch (error) {
                this.statusMessage = 'Demo-Aenderung ist sichtbar, konnte aber nicht im Browser gespeichert werden.';
            }
        },

        restoreLocalState() {
            try {
                const stored = sessionStorage.getItem(this.storageKey);
                if (!stored) return false;
                const state = JSON.parse(stored);
                if (!Array.isArray(state.tenants) || state.tenants.length === 0) return false;
                this.tenants = state.tenants;
                this.selectedTenantSlug = state.selectedTenantSlug || this.tenants[0]?.slug || '';
                this.selectedWorkspaceSlug = state.selectedWorkspaceSlug
                    || (this.selectedTenant.workspaces || [])[0]?.slug
                    || '';
                this.activeTab = state.activeTab || 'account';
                this.hasLocalChanges = true;
                this.statusMessage = 'Lokale Demo-Aenderungen wurden wiederhergestellt.';
                this.resetBillingDraft();
                return true;
            } catch (error) {
                sessionStorage.removeItem(this.storageKey);
                return false;
            }
        },

        clearLocalState() {
            sessionStorage.removeItem(this.storageKey);
            this.hasLocalChanges = false;
            this.statusMessage = '';
        },

        emptyTenant() {
            return {
                slug: '',
                name: 'Kein Mandant',
                demo_story: '',
                billing_mode: 'unknown',
                billing_status: 'unknown',
                plan_tier: 'None',
                monthly_charge_cents: 0,
                billing_profile: {},
                entitlements: {users: {used: 0, included: 0}, aggregate_messages: {used: 0, included: 0}},
                users: [],
                workspaces: [],
                usage: [],
                provider_customers: [],
            };
        },

        emptyWorkspace() {
            return {
                slug: '',
                name: 'Kein Workspace',
                health: 'monitoring',
                domains: [],
                primary_findings: [],
            };
        },

        clone(value) {
            return JSON.parse(JSON.stringify(value || null));
        },
    };
}

document.addEventListener('alpine:init', () => {
    Alpine.data('providerDemo', providerDemo);
});
