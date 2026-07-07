function providerDemo() {
    return {
        loading: false,
        error: '',
        deployment: null,
        selectedStepNumber: 1,
        selectedScenarioId: '',
        selectedWorkspaceSlug: '',

        init() {
            this.bindControls();
            this.load();
        },

        bindControls() {
            const root = document.querySelector('[data-provider-demo]');
            if (!root) return;
            root.addEventListener('click', event => {
                const refresh = event.target.closest('[data-provider-demo-refresh]');
                if (refresh) {
                    this.load();
                    return;
                }

                const stepButton = event.target.closest('[data-provider-demo-step]');
                if (stepButton) {
                    this.selectStep(Number(stepButton.dataset.providerDemoStep));
                    return;
                }

                const workspaceButton = event.target.closest('[data-provider-demo-workspace]');
                if (workspaceButton) {
                    this.selectWorkspace(workspaceButton.dataset.providerDemoWorkspace);
                }
            });
        },

        async load() {
            this.loading = true;
            this.error = '';
            try {
                const response = await fetch('/api/v1/operator/demo/multi-user', {
                    headers: {Accept: 'application/json'},
                });
                if (!response.ok) {
                    throw new Error('Provider demo data is not available in this deployment.');
                }
                const payload = await response.json();
                this.deployment = payload.deployment || {};
                const firstStep = this.journeySteps[0] || {};
                this.selectStep(firstStep.step || 1);
            } catch (error) {
                this.error = error.message || 'Provider demo could not be loaded.';
                this.deployment = null;
            } finally {
                this.loading = false;
            }
        },

        get ready() {
            return Boolean(this.deployment) && !this.loading;
        },

        get organizations() {
            return this.deployment?.organizations || [];
        },

        get journeySteps() {
            return this.deployment?.journey_steps || [];
        },

        get viewerScenarios() {
            return this.deployment?.viewer_scenarios || [];
        },

        get zoomLevels() {
            return this.deployment?.zoom_levels || [];
        },

        get impersonationPolicy() {
            return this.deployment?.impersonation_policy || {};
        },

        get selectedStep() {
            return this.journeySteps.find(step => step.step === this.selectedStepNumber)
                || this.journeySteps[0]
                || {};
        },

        get selectedScenario() {
            return this.viewerScenarios.find(scenario => scenario.id === this.selectedScenarioId)
                || this.viewerScenarios.find(scenario => scenario.id === this.selectedStep.scenario_id)
                || this.viewerScenarios[0]
                || {};
        },

        get selectedOrganization() {
            return this.organizations.find(
                organization => organization.slug === this.selectedStep.organization_slug,
            ) || this.organizations[0] || {};
        },

        get selectedWorkspaces() {
            return this.selectedOrganization.workspaces || [];
        },

        get selectedWorkspace() {
            return this.selectedWorkspaces.find(
                workspace => workspace.slug === this.selectedWorkspaceSlug,
            ) || this.selectedWorkspaces[0] || {};
        },

        get providerOrganization() {
            return this.organizations.find(
                organization => organization.billing_mode === 'provider_resale',
            ) || {};
        },

        get providerCustomers() {
            return this.providerOrganization.provider_customers || [];
        },

        get billingProfile() {
            return this.selectedOrganization.billing_profile || {};
        },

        get organizationCount() {
            return this.organizations.length;
        },

        get workspaceCount() {
            return this.organizations.reduce(
                (total, organization) => total + (organization.workspaces || []).length,
                0,
            );
        },

        get messageVolumeLabel() {
            const total = this.organizations.reduce((sum, organization) => {
                return sum + (organization.usage || [])
                    .filter(row => row.metric === 'aggregate_messages')
                    .reduce((usageSum, row) => usageSum + Number(row.quantity || 0), 0);
            }, 0);
            return this.compactNumber(total);
        },

        get providerRevenueLabel() {
            const cents = this.providerCustomers.reduce(
                (sum, customer) => sum + Number(customer.monthly_charge_cents || 0),
                0,
            );
            return this.formatMoney(cents);
        },

        get selectedScenarioLabel() {
            return this.selectedScenario.label || this.selectedStep.label || 'Demo scenario';
        },

        get selectedStepAction() {
            return this.selectedStep.action || '';
        },

        get selectedStepTakeaway() {
            return this.selectedStep.expected_takeaway || '';
        },

        get selectedStepDomain() {
            return this.selectedStep.domain || this.selectedScenario.default_domain || 'No domain';
        },

        get selectedOrganizationName() {
            return this.selectedOrganization.name || 'Unknown organization';
        },

        get selectedOrganizationStory() {
            return this.selectedOrganization.demo_story || '';
        },

        get selectedOrganizationBilling() {
            return this.humanize(this.selectedOrganization.billing_mode || 'unknown');
        },

        get currentStepZoomLabel() {
            const zoom = this.zoomLevels.find(level => level.level === this.selectedStep.zoom_level);
            return zoom?.label || this.humanize(this.selectedStep.zoom_level || 'workspace');
        },

        get providerCustomerCountLabel() {
            return `${this.providerCustomers.length} customers`;
        },

        get impersonationScope() {
            return this.impersonationPolicy.scope || 'Support access is unavailable.';
        },

        get supportOperatorLabel() {
            const org = this.providerOrganization;
            const user = (org.users || []).find(item => (item.roles || []).includes('provider_operator'));
            return user ? `${user.name} (${user.email})` : 'Provider operator';
        },

        get targetUserLabel() {
            const org = this.providerOrganization;
            const user = (org.users || []).find(item => item.demo_persona === 'customer-admin');
            return user ? `${user.name} (${user.email})` : 'Customer admin';
        },

        selectStep(stepNumber) {
            const step = this.journeySteps.find(item => item.step === stepNumber) || this.journeySteps[0];
            if (!step) return;
            this.selectedStepNumber = step.step;
            this.selectedScenarioId = step.scenario_id;
            this.selectedWorkspaceSlug = step.workspace_slug;
        },

        selectWorkspace(workspaceSlug) {
            if (!workspaceSlug) return;
            const matchingStep = this.journeySteps.find(step => step.workspace_slug === workspaceSlug);
            if (matchingStep) {
                this.selectStep(matchingStep.step);
                return;
            }
            this.selectedWorkspaceSlug = workspaceSlug;
        },

        isSelectedStep(step) {
            return step.step === this.selectedStepNumber;
        },

        isSelectedWorkspace(workspace) {
            return workspace.slug === this.selectedWorkspaceSlug;
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

        humanize(value) {
            return String(value || '')
                .replace(/[_-]+/g, ' ')
                .replace(/\b\w/g, char => char.toUpperCase());
        },

        formatNumber(value) {
            return new Intl.NumberFormat('en-US').format(Number(value || 0));
        },

        compactNumber(value) {
            return new Intl.NumberFormat('en-US', {
                notation: 'compact',
                maximumFractionDigits: 1,
            }).format(Number(value || 0));
        },

        formatMoney(cents) {
            return new Intl.NumberFormat('en-US', {
                style: 'currency',
                currency: 'EUR',
                maximumFractionDigits: 0,
            }).format(Number(cents || 0) / 100);
        },
    };
}
