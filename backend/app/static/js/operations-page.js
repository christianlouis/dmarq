function operationsHealth() {
    return {
        loading: false,
        error: '',
        health: {},

        init() {
            this.bindRefreshControl();
            this.load();
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
                this.health = await response.json();
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
    };
}
