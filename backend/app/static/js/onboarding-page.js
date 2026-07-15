function workspaceOnboarding(options = {}) {
    return {
        multiWorkspaceUiEnabled: Boolean(options.multiWorkspaceUiEnabled),
        previewing: false,
        applying: false,
        error: '',
        success: '',
        plan: null,
        result: null,
        tasks: [],
        lastPreviewSignature: '',
        initialized: false,
        setupStateLoading: true,
        setupStateError: '',
        setupStateLoaded: false,
        configuring: false,
        draftDirty: false,
        setupState: {
            domains: 0,
            reports: 0,
            sources: 0,
            healthySources: 0,
            dnsProviderConnected: false,
            notificationsConfigured: false,
        },
        form: {
            organizationName: '',
            workspaceName: '',
            workspaceDescription: '',
            domain: '',
            dnsProvider: 'Cloudflare',
            reportMailbox: '',
            mailSourcePath: 'imap',
            imapServer: '',
            imapUsername: '',
            imapPassword: '',
        },
        get saving() {
            return this.previewing || this.applying;
        },
        get singleUserMode() {
            return !this.multiWorkspaceUiEnabled;
        },
        get hasExistingSetup() {
            return this.setupState.domains > 0 || this.setupState.sources > 0 || this.setupState.reports > 0;
        },
        get showSetupStatus() {
            return this.singleUserMode && this.setupStateLoaded && this.hasExistingSetup && !this.configuring;
        },
        get showSetupForm() {
            if (this.multiWorkspaceUiEnabled || this.configuring) return true;
            return this.setupStateLoaded &&
                !this.setupStateLoading &&
                !this.setupStateError &&
                !this.hasExistingSetup;
        },
        get setupStatusItems() {
            const state = this.setupState;
            return [
                {
                    id: 'domain',
                    label: 'Monitored domains',
                    complete: state.domains > 0,
                    detail: state.domains > 0
                        ? `${state.domains} domain${state.domains === 1 ? '' : 's'} configured`
                        : 'Add the first domain you want to monitor.',
                    href: '/domains',
                    action: state.domains > 0 ? 'Review domains' : 'Add a domain',
                },
                {
                    id: 'source',
                    label: 'Report mailbox',
                    complete: state.healthySources > 0,
                    detail: state.sources === 0
                        ? 'No Gmail or IMAP source is connected.'
                        : state.healthySources > 0
                            ? `${state.healthySources} enabled source${state.healthySources === 1 ? '' : 's'} ready`
                            : `${state.sources} source${state.sources === 1 ? '' : 's'} need attention`,
                    href: '/mail-sources',
                    action: state.sources === 0 ? 'Connect mailbox' : 'Review mail sources',
                },
                {
                    id: 'reports',
                    label: 'DMARC evidence',
                    complete: state.reports > 0,
                    detail: state.reports > 0
                        ? `${state.reports} aggregate report${state.reports === 1 ? '' : 's'} imported`
                        : 'Import reports before acting on sender or policy guidance.',
                    href: state.sources > 0 ? '/mail-sources' : '/upload',
                    action: state.sources > 0 ? 'Import reports' : 'Choose import method',
                },
                {
                    id: 'dns',
                    label: 'DNS provider',
                    complete: state.dnsProviderConnected,
                    detail: state.dnsProviderConnected
                        ? 'A provider connection is available for read or repair workflows.'
                        : 'Optional: connect a provider for verified previews and approved changes.',
                    href: '/settings#provider-integrations',
                    action: state.dnsProviderConnected ? 'Review provider' : 'Connect provider',
                    optional: true,
                },
                {
                    id: 'notifications',
                    label: 'Notifications',
                    complete: state.notificationsConfigured,
                    detail: state.notificationsConfigured
                        ? 'Operator notifications are configured.'
                        : 'Optional: add a notification target after report intake works.',
                    href: '/settings#notification-settings',
                    action: state.notificationsConfigured ? 'Review notifications' : 'Configure notifications',
                    optional: true,
                },
            ];
        },
        get firstRequiredSetupAction() {
            return this.setupStatusItems.find(item => !item.complete && !item.optional) || null;
        },
        get setupPrimaryHref() {
            return this.firstRequiredSetupAction?.href || '/';
        },
        get setupPrimaryLabel() {
            return this.firstRequiredSetupAction?.action || 'Open dashboard';
        },
        get setupHeadline() {
            if (this.firstRequiredSetupAction) return 'Continue setup';
            return 'Core monitoring is ready';
        },
        get setupSummary() {
            if (this.firstRequiredSetupAction) {
                return `${this.firstRequiredSetupAction.label} is the next required step.`;
            }
            return 'Domains, report intake, and DMARC evidence are available. Optional integrations can be configured when needed.';
        },
        get hasUnsavedDraft() {
            return this.draftDirty;
        },
        get showWorkspaceSwitchSuccess() {
            return this.multiWorkspaceUiEnabled && Boolean(this.result?.workspace);
        },
        get resultWorkspaceName() {
            return this.result?.workspace?.name || '';
        },
        get showImapFields() {
            return this.form.mailSourcePath === 'imap';
        },
        get showDnsOnlyNotice() {
            return this.form.mailSourcePath === 'dns_only';
        },
        get imapButtonClass() {
            return this.showImapFields ? 'btn-primary' : 'btn-outline';
        },
        get dnsOnlyButtonClass() {
            return this.showDnsOnlyNotice ? 'btn-primary' : 'btn-outline';
        },
        get taskPreviewLabel() {
            return this.tasks.length
                ? `${this.tasks.length} task${this.tasks.length === 1 ? '' : 's'}`
                : 'No preview yet';
        },
        get showNoTasks() {
            return this.tasks.length === 0;
        },
        get currentPreviewSignature() {
            return this.previewSignature();
        },
        get hasCurrentPreview() {
            return Boolean(this.lastPreviewSignature && this.lastPreviewSignature === this.currentPreviewSignature);
        },
        get canApplySetup() {
            return this.hasCurrentPreview && this.tasks.length > 0;
        },
        get applyButtonLabel() {
            if (this.applying) return this.multiWorkspaceUiEnabled ? 'Creating workspace...' : 'Applying setup...';
            if (!this.canApplySetup) return 'Preview first';
            return this.multiWorkspaceUiEnabled ? 'Create workspace' : 'Apply setup';
        },
        get applyDisabledReason() {
            if (this.canApplySetup) return '';
            if (this.lastPreviewSignature) return 'Preview the updated form before applying setup.';
            return 'Preview setup tasks before applying changes.';
        },
        init() {
            if (this.initialized) return;
            this.initialized = true;
            const flag = this.$el?.dataset?.multiWorkspaceUi;
            if (flag === 'true' || flag === 'false') {
                this.multiWorkspaceUiEnabled = flag === 'true';
            }
            this.draftDirty = localStorage.getItem('dmarq.onboarding.draftDirty') === 'true';
            this.draftFields().forEach((field) => {
                const storedValue = localStorage.getItem(`dmarq.onboarding.${field}`);
                if (storedValue !== null) {
                    this.form[field] = storedValue;
                }
                this.$watch(`form.${field}`, () => {
                    this.draftDirty = true;
                    this.persistDraft();
                });
            });
            this.bindControls();
            this.loadSetupState();
        },
        bindControls() {
            const root = this.$root;
            root?.addEventListener('submit', (event) => {
                if (!(event.target instanceof Element)) return;
                if (!event.target.matches('[data-onboarding-form]')) return;
                event.preventDefault();
                this.previewPlan();
            });
            root?.addEventListener('click', (event) => {
                if (!(event.target instanceof Element)) return;
                const previewButton = event.target.closest('[data-onboarding-preview]');
                if (previewButton && root.contains(previewButton)) {
                    this.previewPlan();
                    return;
                }
                const applyButton = event.target.closest('[data-onboarding-apply]');
                if (applyButton && root.contains(applyButton)) {
                    this.applyPlan();
                    return;
                }
                const pathButton = event.target.closest('[data-onboarding-mail-path]');
                if (pathButton) {
                    this.form.mailSourcePath = pathButton.getAttribute('data-onboarding-mail-path') || 'imap';
                    return;
                }
                const reconfigureButton = event.target.closest('[data-onboarding-reconfigure]');
                if (reconfigureButton && root.contains(reconfigureButton)) {
                    this.configuring = true;
                }
            });
        },
        async loadSetupState() {
            if (!this.singleUserMode) {
                this.setupStateLoading = false;
                this.setupStateLoaded = true;
                return;
            }
            this.setupStateLoading = true;
            this.setupStateError = '';
            try {
                const [domainResponse, sourceResponse, providerResponse, notificationResponse] = await Promise.all([
                    fetch('/api/v1/domains/summary?include_empty=true'),
                    fetch('/api/v1/mail-sources'),
                    fetch('/api/v1/domains/dns/providers'),
                    fetch('/api/v1/settings/notifications.apprise_enabled'),
                ]);
                if (!domainResponse.ok || !sourceResponse.ok) {
                    throw new Error('Core setup status could not be loaded.');
                }
                const domains = await domainResponse.json();
                const sources = await sourceResponse.json();
                const providers = providerResponse.ok ? await providerResponse.json() : {};
                const notifications = notificationResponse.ok ? await notificationResponse.json() : {};
                const providerList = Array.isArray(providers.providers) ? providers.providers : [];
                const sourceList = Array.isArray(sources) ? sources : [];
                this.setupState = {
                    domains: Number(domains.total_domains || 0),
                    reports: Number(domains.reports_processed || 0),
                    sources: sourceList.length,
                    healthySources: sourceList.filter(source => (
                        source.enabled && !source.connection_attention && source.connection_status !== 'reauth_required'
                    )).length,
                    dnsProviderConnected: providerList.some(provider => (
                        provider.credentials_configured || provider.connection_status === 'connected'
                    )),
                    notificationsConfigured: ['true', '1', 'yes', 'on'].includes(
                        String(notifications.value || '').trim().toLowerCase()
                    ),
                };
            } catch (error) {
                this.setupStateError = error.message || 'Setup status could not be loaded.';
            } finally {
                this.setupStateLoading = false;
                this.setupStateLoaded = true;
            }
        },
        draftFields() {
            return [
                'organizationName',
                'workspaceName',
                'workspaceDescription',
                'domain',
                'dnsProvider',
                'reportMailbox',
                'mailSourcePath',
                'imapServer',
                'imapUsername',
            ];
        },
        normalizeDomain(value) {
            return value.trim().replace(/^\.+|\.+$/g, '').toLowerCase();
        },
        payload() {
            const domain = this.normalizeDomain(this.form.domain);
            const fallbackName = domain || 'Default workspace';
            const workspaceName = this.singleUserMode
                ? fallbackName
                : this.form.workspaceName.trim() || this.form.organizationName.trim() || fallbackName;
            const organizationName = this.singleUserMode
                ? workspaceName
                : this.form.organizationName.trim() || workspaceName;
            const reportMailbox = this.form.reportMailbox.trim() || (domain ? `dmarc@${domain}` : '');
            const templateId = this.form.mailSourcePath === 'dns_only' ? 'dns_only_assessment' : 'standard_monitoring';
            const variables = {
                domain,
                workspace_name: workspaceName,
                dns_provider: this.form.dnsProvider,
                report_mailbox: reportMailbox,
            };
            if (templateId === 'standard_monitoring') {
                variables.imap_server = this.form.imapServer.trim();
                variables.imap_username = this.form.imapUsername.trim() || reportMailbox;
                variables.imap_password = this.form.imapPassword;
            }
            return {
                template_id: templateId,
                organization: { name: organizationName },
                workspace: {
                    name: workspaceName,
                    description: this.form.workspaceDescription.trim() || null,
                },
                variables,
            };
        },
        previewSignature() {
            return JSON.stringify(this.payload());
        },
        validate() {
            if (!this.normalizeDomain(this.form.domain)) {
                throw new Error('Domain is required.');
            }
            if (
                this.multiWorkspaceUiEnabled &&
                !this.form.workspaceName.trim() &&
                !this.form.organizationName.trim()
            ) {
                throw new Error('Organization or workspace name is required.');
            }
        },
        async previewPlan() {
            await this.submit('/api/v1/onboarding/preview', 'preview');
        },
        async applyPlan() {
            if (!this.canApplySetup) {
                this.error = this.applyDisabledReason;
                return;
            }
            await this.submit('/api/v1/onboarding/apply', 'apply');
        },
        async submit(url, mode) {
            this.error = '';
            this.success = '';
            this.result = null;
            try {
                this.validate();
            } catch (err) {
                this.error = err.message;
                return;
            }
            this.previewing = mode === 'preview';
            this.applying = mode === 'apply';
            try {
                const response = await fetch(url, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(this.payload()),
                });
                const data = await response.json().catch(() => ({}));
                if (!response.ok) {
                    throw new Error(this.errorMessage(data.detail) || 'Onboarding request failed.');
                }
                if (mode === 'preview') {
                    this.plan = data.plan;
                    this.tasks = this.normalizeTasks(data.plan?.tasks);
                    this.lastPreviewSignature = this.currentPreviewSignature;
                    this.success = this.singleUserMode
                        ? 'Preview is ready. Review the task list before applying setup.'
                        : 'Preview is ready. Review the task list before creating the workspace.';
                } else {
                    this.result = data.result;
                    this.tasks = this.normalizeTasks(data.result?.tasks);
                    this.success = this.singleUserMode
                        ? 'Mail health setup was applied.'
                        : 'Workspace onboarding was applied.';
                    this.persistAppliedWorkspace(data.result);
                    this.draftDirty = false;
                    await this.loadSetupState();
                }
                this.persistDraft();
            } catch (err) {
                this.error = err.message || 'Onboarding request failed.';
            } finally {
                this.previewing = false;
                this.applying = false;
            }
        },
        errorMessage(detail) {
            if (Array.isArray(detail)) {
                return detail.join(', ');
            }
            if (detail && typeof detail === 'object') {
                if (detail.errors) return this.errorMessage(detail.errors);
                if (detail.message) return detail.message;
                return JSON.stringify(detail);
            }
            return detail || '';
        },
        normalizeTasks(tasks) {
            return (tasks || []).map((task) => ({
                ...task,
                url: task.href || '#',
            }));
        },
        persistAppliedWorkspace(result) {
            if (!this.multiWorkspaceUiEnabled) return;
            const workspaceId = result?.workspace?.id;
            if (!workspaceId) return;
            localStorage.setItem('dmarq.selectedWorkspaceId', String(workspaceId));
            window.dispatchEvent(new CustomEvent('dmarq:workspace-changed', {
                detail: { workspaceId: String(workspaceId) },
            }));
        },
        persistDraft() {
            this.draftFields().forEach((field) => {
                localStorage.setItem(`dmarq.onboarding.${field}`, this.form[field] || '');
            });
            localStorage.setItem('dmarq.onboarding.draftDirty', String(this.draftDirty));
        },
    };
}

if (typeof document !== 'undefined') {
    document.addEventListener('alpine:init', () => {
        Alpine.data('workspaceOnboarding', workspaceOnboarding);
    });
}
