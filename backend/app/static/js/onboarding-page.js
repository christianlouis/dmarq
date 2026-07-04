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
        initialized: false,
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
            return this.tasks.length ? `${this.tasks.length} tasks` : 'No preview yet';
        },
        get showNoTasks() {
            return this.tasks.length === 0;
        },
        init() {
            if (this.initialized) return;
            this.initialized = true;
            const flag = this.$el?.dataset?.multiWorkspaceUi;
            if (flag === 'true' || flag === 'false') {
                this.multiWorkspaceUiEnabled = flag === 'true';
            }
            this.draftFields().forEach((field) => {
                const storedValue = localStorage.getItem(`dmarq.onboarding.${field}`);
                if (storedValue !== null) {
                    this.form[field] = storedValue;
                }
                this.$watch(`form.${field}`, () => this.persistDraft());
            });
            this.bindControls();
        },
        bindControls() {
            const root = this.$root;
            root?.querySelector('[data-onboarding-preview]')?.addEventListener('click', () => {
                this.previewPlan();
            });
            root?.querySelector('[data-onboarding-apply]')?.addEventListener('click', () => {
                this.applyPlan();
            });
            root?.addEventListener('click', (event) => {
                if (!(event.target instanceof Element)) return;
                const pathButton = event.target.closest('[data-onboarding-mail-path]');
                if (!pathButton) return;
                this.form.mailSourcePath = pathButton.getAttribute('data-onboarding-mail-path') || 'imap';
            });
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
        },
    };
}

document.addEventListener('alpine:init', () => {
    Alpine.data('workspaceOnboarding', workspaceOnboarding);
});
