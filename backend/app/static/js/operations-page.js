function operationsHealth() {
    return {
        loading: false,
        error: '',
        health: {},

        init() {
            this.bindRefreshControl();
            this.load();
        },

        get hasError() {
            return Boolean(this.error);
        },

        get scheduler() {
            return this.health.scheduler || {};
        },

        get database() {
            return this.health.database || {};
        },

        get imports() {
            return this.health.imports || {};
        },

        get reports() {
            return this.health.reports || {};
        },

        get statusLabel() {
            return this.health.status || 'loading';
        },

        get statusClass() {
            return this.health.status === 'ok' ? 'text-success' : 'text-warning';
        },

        get databaseLabel() {
            return this.database.ok ? 'Connected' : 'Failed';
        },

        get databaseClass() {
            return this.database.ok ? 'text-success' : 'text-error';
        },

        get mailSourcesLabel() {
            return `${this.scheduler.enabled_sources || 0}/${this.scheduler.total_sources || 0}`;
        },

        get reportsCountLabel() {
            return this.reports.count || 0;
        },

        get schedulerStateLabel() {
            return this.scheduler.running ? 'Running' : 'Stopped';
        },

        get lastCycleLabel() {
            return this.formatDate(this.scheduler.last_cycle_started_at);
        },

        get lastSuccessLabel() {
            return this.formatDate(this.scheduler.last_success_at);
        },

        get schedulerLastErrorLabel() {
            return this.scheduler.last_error || 'None';
        },

        get latestImportLabel() {
            return this.formatImport(this.imports.latest);
        },

        get latestSuccessfulImportLabel() {
            return this.formatImport(this.imports.latest_successful);
        },

        get latestReportLabel() {
            return this.formatDate(this.reports.latest_processed_at);
        },

        get databaseDetailLabel() {
            return this.database.detail || 'Unknown';
        },

        get checks() {
            return this.health.checks || [];
        },

        get hasChecks() {
            return this.checks.length > 0;
        },

        get mailboxRecovery() {
            return this.health.mailbox_recovery || [];
        },

        get hasMailboxRecovery() {
            return this.mailboxRecovery.length > 0;
        },

        bindRefreshControl() {
            const root = this.$root || document.querySelector('[data-operations-health]');
            const refreshButton = root?.querySelector('[data-operations-refresh]');
            if (!refreshButton || refreshButton.dataset.operationsRefreshBound === 'true') {
                return;
            }
            refreshButton.dataset.operationsRefreshBound = 'true';
            refreshButton.addEventListener('click', () => {
                this.load();
            });
        },

        async load() {
            this.loading = true;
            this.error = '';
            try {
                const response = await fetch('/api/v1/health/operations');
                if (!response.ok) {
                    throw new Error('Health details could not be loaded.');
                }
                this.health = this.normalizeHealth(await response.json());
            } catch (error) {
                this.error = error.message || 'Health details could not be loaded.';
            } finally {
                this.loading = false;
            }
        },

        formatDate(value) {
            if (!value) return 'Not recorded';
            return new Date(value).toLocaleString();
        },

        formatImport(value) {
            if (!value) return 'Not recorded';
            return `${value.status} (${value.reports_found} reports) at ${this.formatDate(value.finished_at)}`;
        },

        categoryLabel(value) {
            if (!value) return 'Mailbox';
            return value.replaceAll('_', ' ');
        },

        normalizeHealth(payload) {
            const health = payload || {};
            const mailboxRecovery = (health.mailbox_recovery || []).map((item, index) => {
                const recoverySteps = item.recovery_steps || [];
                const summary = item.summary || '';
                const category = item.category || '';

                return {
                    ...item,
                    key: `${category}-${summary}-${index}`,
                    category_label: this.categoryLabel(category),
                    recovery_steps: recoverySteps,
                    has_recovery_steps: recoverySteps.length > 0,
                };
            });

            return {
                ...health,
                checks: health.checks || [],
                mailbox_recovery: mailboxRecovery,
            };
        },
    };
}

document.addEventListener('alpine:init', () => {
    Alpine.data('operationsHealth', operationsHealth);
});
