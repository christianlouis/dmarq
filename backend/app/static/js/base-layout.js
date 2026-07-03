document.addEventListener('alpine:init', () => {
    const multiWorkspaceUiEnabled = () =>
        document.documentElement.dataset.multiWorkspaceUi === 'true';

    Alpine.data('userMenu', (options = {}) => {
        const enabled =
            options.multiWorkspaceUiEnabled === undefined
                ? multiWorkspaceUiEnabled()
                : Boolean(options.multiWorkspaceUiEnabled);
        return {
            user: null,
            workspaces: [],
            multiWorkspaceUiEnabled: enabled,
            selectedWorkspaceId: enabled
                ? localStorage.getItem('dmarq.selectedWorkspaceId') || ''
                : '',
            async loadUser() {
                try {
                    const res = await fetch('/api/v1/auth/me');
                    if (res.ok) {
                        this.user = await res.json();
                    }
                } catch (_) {
                    // User identity is optional for public or setup views.
                }
                if (!this.multiWorkspaceUiEnabled) {
                    localStorage.removeItem('dmarq.selectedWorkspaceId');
                    this.workspaces = [];
                    this.selectedWorkspaceId = '';
                    return;
                }
                await this.loadWorkspaces();
            },
            async loadWorkspaces() {
                try {
                    const res = await fetch('/api/v1/workspaces');
                    if (!res.ok) {
                        return;
                    }
                    const data = await res.json();
                    this.workspaces = data.workspaces || [];
                    const saved = String(this.selectedWorkspaceId || '');
                    const selected = this.workspaces.find(
                        (workspace) => String(workspace.id) === saved && workspace.active
                    );
                    const fallback =
                        this.workspaces.find((workspace) => workspace.active) || this.workspaces[0];
                    if (!selected && fallback) {
                        this.selectWorkspace(String(fallback.id));
                    } else if (selected) {
                        this.selectWorkspace(String(selected.id));
                    }
                } catch (_) {
                    // Workspace selection is optional for single-tenant installs.
                }
            },
            selectWorkspace(workspaceId) {
                this.selectedWorkspaceId = workspaceId || '';
                if (this.selectedWorkspaceId) {
                    localStorage.setItem('dmarq.selectedWorkspaceId', this.selectedWorkspaceId);
                } else {
                    localStorage.removeItem('dmarq.selectedWorkspaceId');
                }
                window.dispatchEvent(
                    new CustomEvent('dmarq:workspace-changed', {
                        detail: { workspaceId: this.selectedWorkspaceId },
                    })
                );
            },
            workspaceLabel(workspace) {
                const prefix = workspace.organization ? `${workspace.organization.name} / ` : '';
                const suffix = workspace.active ? '' : ' (inactive)';
                return `${prefix}${workspace.name}${suffix}`;
            },
        };
    });
});

(function attachWorkspaceContextToFetch() {
    const originalFetch = window.fetch;
    const multiWorkspaceUiEnabled = () =>
        document.documentElement.dataset.multiWorkspaceUi === 'true';
    const workspaceHeaderName = 'X-DMARQ-Workspace-ID';
    const normalizeWorkspaceId = (workspaceId) => {
        const trimmed = String(workspaceId || '').trim();
        return /^[1-9]\d*$/.test(trimmed) ? trimmed : '';
    };
    const withoutWorkspaceContext = (input, init) => {
        const headers = new Headers((init && init.headers) || (input && input.headers) || {});
        if (!headers.has(workspaceHeaderName)) {
            return init;
        }
        const nextInit = Object.assign({}, init || {});
        headers.delete(workspaceHeaderName);
        nextInit.headers = headers;
        return nextInit;
    };

    window.fetch = function dmarqWorkspaceFetch(input, init) {
        if (!multiWorkspaceUiEnabled()) {
            return originalFetch(input, withoutWorkspaceContext(input, init));
        }
        const workspaceId = normalizeWorkspaceId(localStorage.getItem('dmarq.selectedWorkspaceId'));
        const url =
            input instanceof URL
                ? input.toString()
                : typeof input === 'string'
                  ? input
                  : (input && input.url) || '';
        const isApiRequest =
            url.startsWith('/api/') || url.startsWith(window.location.origin + '/api/');
        if (!workspaceId || !isApiRequest) {
            return originalFetch(input, init);
        }
        const nextInit = Object.assign({}, init || {});
        const headers = new Headers(nextInit.headers || (input && input.headers) || {});
        if (!headers.has(workspaceHeaderName)) {
            headers.set(workspaceHeaderName, workspaceId);
        }
        nextInit.headers = headers;
        return originalFetch(input, nextInit);
    };
})();

(function restoreThemePreference() {
    const darkMode = localStorage.getItem('darkMode') === 'true';
    if (darkMode) {
        document.documentElement.classList.add('dark');
        document.documentElement.setAttribute('data-theme', 'dmarqdark');
    } else {
        document.documentElement.classList.remove('dark');
        document.documentElement.setAttribute('data-theme', 'dmarqlight');
    }
})();

(function bindReleaseModalTriggers() {
    document.addEventListener('click', (event) => {
        const trigger = event.target.closest('[data-release-modal-trigger]');
        if (!trigger) {
            return;
        }
        const modal = document.getElementById('dmarq-release-modal');
        if (modal && typeof modal.showModal === 'function') {
            modal.showModal();
        }
    });
})();
