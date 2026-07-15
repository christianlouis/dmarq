if (typeof document !== 'undefined') {
    const multiWorkspaceUiEnabled = () =>
        document.documentElement.dataset.multiWorkspaceUi === 'true';

    const userMenu = () => {
        const enabled = multiWorkspaceUiEnabled();
        return {
            user: null,
            workspaces: [],
            multiWorkspaceUiEnabled: enabled,
            selectedWorkspaceId: enabled
                ? localStorage.getItem('dmarq.selectedWorkspaceId') || ''
                : '',
            init() {
                this.bindControls();
                this.loadUser();
            },
            get showWorkspaceSwitcher() {
                return this.workspaces.length > 1;
            },
            get showSignIn() {
                return !this.user;
            },
            bindControls() {
                if (typeof document === 'undefined') return;
                const hasElement = typeof Element !== 'undefined';
                const root = hasElement && this.$root instanceof Element
                    ? this.$root
                    : document.querySelector('[data-user-menu]');
                if (!root || root.dataset.userMenuControlsBound === 'true') return;
                root.dataset.userMenuControlsBound = 'true';

                root.addEventListener('change', (event) => {
                    if (!hasElement || !(event.target instanceof Element)) return;
                    const switcher = event.target.closest('[data-workspace-switcher]');
                    if (switcher && root.contains(switcher)) {
                        this.selectWorkspace(switcher.value);
                    }
                });
            },
            async loadUser() {
                try {
                    const res = await fetch('/api/v1/auth/me');
                    if (res.ok) {
                        this.user = this.normalizeUser(await res.json());
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
                    this.workspaces = (data.workspaces || []).map((workspace) =>
                        this.normalizeWorkspace(workspace)
                    );
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
            normalizeUser(user) {
                const profile = user || {};
                const fullName = String(profile.full_name || '').trim();
                const email = String(profile.email || '').trim();
                const displayName = fullName || email || 'Unknown user';
                return {
                    ...profile,
                    display_name: displayName,
                    email_label: email,
                    show_email: Boolean(fullName && email),
                    avatar_alt: displayName,
                    initial: displayName.slice(0, 1).toUpperCase() || '?',
                    show_placeholder_avatar: !profile.picture,
                };
            },
            normalizeWorkspace(workspace) {
                return {
                    ...workspace,
                    disabled: !workspace.active,
                };
            },
        };
    };

    document.addEventListener('alpine:init', () => {
        Alpine.data('userMenu', userMenu);
    });
}

(function attachWorkspaceContextToFetch() {
    const originalFetch = window.fetch;
    const multiWorkspaceUiEnabled = () =>
        document.documentElement.dataset.multiWorkspaceUi === 'true';
    const demoModeEnabled = () => document.documentElement.dataset.demoMode === 'true';
    const workspaceHeaderName = 'X-DMARQ-Workspace-ID';
    const readonlyMessage = 'Diese öffentliche Demo ist read-only. Änderungen werden nicht gespeichert.';
    let readonlyToastTimer = null;
    const normalizeWorkspaceId = (workspaceId) => {
        const trimmed = String(workspaceId || '').trim();
        return /^[1-9]\d*$/.test(trimmed) ? trimmed : '';
    };
    const showReadonlyToast = () => {
        if (!demoModeEnabled() || typeof document === 'undefined') return;
        let toast = document.querySelector('[data-demo-readonly-toast]');
        if (!toast) {
            toast = document.createElement('div');
            toast.setAttribute('data-demo-readonly-toast', 'true');
            toast.setAttribute('role', 'status');
            toast.setAttribute('aria-live', 'polite');
            toast.className = 'fixed bottom-5 right-5 z-50 max-w-sm rounded-lg border border-[#f5c16c] bg-[#fff8e5] p-4 text-sm font-semibold text-[#7a4b00] shadow-lg';
            document.body.appendChild(toast);
        }
        toast.textContent = readonlyMessage;
        toast.hidden = false;
        if (readonlyToastTimer) {
            window.clearTimeout(readonlyToastTimer);
        }
        readonlyToastTimer = window.setTimeout(() => {
            toast.hidden = true;
        }, 6000);
    };
    const mirrorDemoReadOnlyError = async (response) => {
        if (!demoModeEnabled() || response.status !== 403) return response;
        try {
            const payload = await response.clone().json();
            if (String(payload.detail || '').toLowerCase().includes('public demo is read-only')) {
                showReadonlyToast();
            }
        } catch (_) {
            // Non-JSON 403 responses are handled by the caller.
        }
        return response;
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

    window.fetch = async function dmarqWorkspaceFetch(input, init) {
        if (!multiWorkspaceUiEnabled()) {
            return mirrorDemoReadOnlyError(await originalFetch(input, withoutWorkspaceContext(input, init)));
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
            return mirrorDemoReadOnlyError(await originalFetch(input, init));
        }
        const nextInit = Object.assign({}, init || {});
        const headers = new Headers(nextInit.headers || (input && input.headers) || {});
        if (!headers.has(workspaceHeaderName)) {
            headers.set(workspaceHeaderName, workspaceId);
        }
        nextInit.headers = headers;
        return mirrorDemoReadOnlyError(await originalFetch(input, nextInit));
    };
})();

(function bindSupportSessionExit() {
    document.addEventListener('click', async (event) => {
        const target = event.target;
        if (!(target instanceof Element)) return;
        const button = target.closest('[data-support-session-exit]');
        if (!button) return;
        const originalLabel = button.textContent;
        button.disabled = true;
        try {
            const response = await fetch('/api/v1/operator/support-session', {
                method: 'DELETE',
                headers: {Accept: 'application/json'},
            });
            if (!response.ok) throw new Error('Support session could not be ended');
            localStorage.removeItem('dmarq.selectedWorkspaceId');
            window.location.assign(button.dataset.supportSessionExitUrl || '/provider#accounts');
        } catch (_) {
            button.disabled = false;
            button.textContent = 'Sitzung konnte nicht beendet werden';
            window.setTimeout(() => {
                if (button.isConnected) button.textContent = originalLabel;
            }, 2500);
        }
    });
})();

(function restoreThemePreference() {
    const darkMode = localStorage.getItem('darkMode') === 'true';
    if (darkMode) {
        document.documentElement.classList.add('dark');
        document.documentElement.setAttribute('data-theme', 'dark');
    } else {
        document.documentElement.classList.remove('dark');
        document.documentElement.setAttribute('data-theme', 'dmarqlight');
    }
})();

(function bindReleaseModalTriggers() {
    document.addEventListener('click', (event) => {
        const target = event.target;
        if (!(target instanceof Element)) {
            return;
        }
        const trigger = target.closest('[data-release-modal-trigger]');
        if (!trigger) {
            return;
        }
        const modal = document.getElementById('dmarq-release-modal');
        if (modal && typeof modal.showModal === 'function' && !modal.open) {
            modal.showModal();
        }
    });
})();
