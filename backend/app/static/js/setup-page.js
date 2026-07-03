function setupWizard() {
    return {
        statusLoading: true,
        saving: false,
        currentStep: 1,
        complete: false,
        error: '',
        message: '',
        totalDomains: 0,
        totalMailSources: 0,
        enabledMailSources: 0,
        mailboxRecoveryHint: null,
        steps: [
            { id: 1, title: 'Admin', detail: 'Contact details' },
            { id: 2, title: 'System', detail: 'Name and URL' },
            { id: 3, title: 'Ready', detail: 'Start using DMARQ' },
        ],
        admin: {
            email: '',
            username: '',
            password: '',
            confirmPassword: '',
        },
        system: {
            app_name: document.querySelector('[data-app-name]')?.dataset.appName || 'DMARQ',
            base_url: window.location.origin,
            cloudflare_enabled: false,
            cloudflare_api_token: '',
            cloudflare_zone_id: '',
        },
        async init() {
            this.bindControls();
            this.applyTheme();
            try {
                const response = await fetch('/api/v1/setup/status');
                if (!response.ok) {
                    throw new Error('Could not load setup status.');
                }
                const status = await response.json();
                this.system.app_name = status.app_name || this.system.app_name;
                this.complete = Boolean(status.is_setup_complete);
                this.currentStep = this.complete ? 3 : 1;
                this.totalDomains = status.total_domains || 0;
                this.totalMailSources = status.total_mail_sources || 0;
                this.enabledMailSources = status.enabled_mail_sources || 0;
                this.mailboxRecoveryHint = status.mailbox_recovery_hint || null;
            } catch (err) {
                this.error = err.message || 'Could not load setup status.';
            } finally {
                this.statusLoading = false;
            }
        },
        bindControls() {
            if (typeof document === 'undefined') return;
            const hasElement = typeof Element !== 'undefined';
            const root = hasElement && this.$root instanceof Element
                ? this.$root
                : document.querySelector('[data-setup-wizard]');
            if (!root || root.dataset.setupControlsBound === 'true') return;
            root.dataset.setupControlsBound = 'true';

            root.addEventListener('submit', (event) => {
                if (!hasElement || !(event.target instanceof Element)) return;
                const adminForm = event.target.closest('[data-setup-admin-form]');
                if (adminForm && root.contains(adminForm)) {
                    event.preventDefault();
                    this.submitAdmin();
                    return;
                }

                const systemForm = event.target.closest('[data-setup-system-form]');
                if (systemForm && root.contains(systemForm)) {
                    event.preventDefault();
                    this.submitSystem();
                }
            });

            root.addEventListener('click', (event) => {
                if (!hasElement || !(event.target instanceof Element)) return;
                const backButton = event.target.closest('[data-setup-back]');
                if (backButton && root.contains(backButton)) {
                    this.currentStep = 1;
                }
            });
        },
        applyTheme() {
            if (localStorage.getItem('darkMode') === 'true') {
                document.documentElement.setAttribute('data-theme', 'dmarqdark');
            }
        },
        stepClass(stepId) {
            if (this.complete && stepId === 3) return 'border-success bg-success/10';
            if (stepId === this.currentStep) return 'border-primary bg-primary/10';
            if (stepId < this.currentStep) return 'border-success bg-success/10';
            return 'border-base-300 bg-base-100';
        },
        stepBadgeClass(stepId) {
            if (this.complete && stepId === 3) return 'bg-success text-success-content';
            if (stepId === this.currentStep) return 'bg-primary text-primary-content';
            if (stepId < this.currentStep) return 'bg-success text-success-content';
            return 'bg-base-200 text-base-content/70';
        },
        async submitAdmin() {
            this.error = '';
            if (this.admin.password !== this.admin.confirmPassword) {
                this.error = 'Passwords do not match.';
                return;
            }
            await this.save('/api/v1/setup/admin', {
                email: this.admin.email,
                username: this.admin.username,
                password: this.admin.password,
            }, () => {
                this.currentStep = 2;
                this.admin.password = '';
                this.admin.confirmPassword = '';
            });
        },
        async submitSystem() {
            this.error = '';
            if (this.system.cloudflare_enabled && !this.system.cloudflare_api_token) {
                this.error = 'Enter a Cloudflare API token or leave Cloudflare disabled for now.';
                return;
            }
            await this.save('/api/v1/setup/system', this.system, () => {
                this.system.cloudflare_api_token = '';
                this.complete = true;
                this.currentStep = 3;
                this.message = this.system.cloudflare_enabled
                    ? 'Your setup settings and Cloudflare connector have been saved.'
                    : 'Your setup settings have been saved.';
            });
        },
        async save(url, payload, onSuccess) {
            this.saving = true;
            try {
                const response = await fetch(url, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload),
                });
                if (!response.ok) {
                    const data = await response.json().catch(() => ({}));
                    throw new Error(data.detail || 'Setup could not be saved.');
                }
                onSuccess();
            } catch (err) {
                this.error = err.message || 'Setup could not be saved.';
            } finally {
                this.saving = false;
            }
        },
    };
}
