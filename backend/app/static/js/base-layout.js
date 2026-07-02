document.addEventListener('alpine:init', () => {
    Alpine.data('userMenu', () => ({
        user: null,
        workspaces: [],
        selectedWorkspaceId: localStorage.getItem('dmarq.selectedWorkspaceId') || '',
        async loadUser() {
            try {
                const res = await fetch('/api/v1/auth/me');
                if (res.ok) {
                    this.user = await res.json();
                }
            } catch (_) {
                // User identity is optional for public or setup views.
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
    }));
});

(function attachWorkspaceContextToFetch() {
    const originalFetch = window.fetch;
    window.fetch = function dmarqWorkspaceFetch(input, init) {
        const workspaceId = localStorage.getItem('dmarq.selectedWorkspaceId');
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
        if (!headers.has('X-DMARQ-Workspace-ID')) {
            headers.set('X-DMARQ-Workspace-ID', workspaceId);
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
