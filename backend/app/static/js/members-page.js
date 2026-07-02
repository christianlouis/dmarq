function membershipApp() {
    return {
        organizations: [],
        memberships: [],
        availableRoles: [],
        selectedOrgId: '',
        selectedWorkspaceId: '',
        scope: 'workspace',
        loading: false,
        saving: false,
        flash: { message: '', ok: true },
        invite: { email: '', full_name: '', role: '' },

        async init() {
            await this.loadOrganizations();
        },

        apiHeaders() {
            return { 'Content-Type': 'application/json' };
        },

        async loadOrganizations() {
            this.loading = true;
            try {
                const response = await fetch('/api/v1/organizations');
                if (response.status === 401) {
                    window.location.href = '/login?next=/members';
                    return;
                }
                if (!response.ok) {
                    throw new Error(await this.errorText(response));
                }
                const data = await response.json();
                this.organizations = data.organizations || [];
                if (this.organizations.length > 0) {
                    this.selectedOrgId = this.organizations[0].id;
                    const workspaces = this.currentWorkspaces();
                    this.selectedWorkspaceId = workspaces.length > 0 ? workspaces[0].id : '';
                    if (!this.selectedWorkspaceId) {
                        this.scope = 'organization';
                    }
                }
                await this.loadMemberships();
            } catch (error) {
                this.showFlash(`Could not load tenants: ${error.message}`, false);
            } finally {
                this.loading = false;
            }
        },

        async loadMemberships() {
            const endpoint = this.membershipEndpoint();
            if (!endpoint) {
                this.memberships = [];
                this.availableRoles = [];
                return;
            }
            this.loading = true;
            try {
                const response = await fetch(`${endpoint}?include_inactive=true`);
                if (response.status === 401) {
                    window.location.href = '/login?next=/members';
                    return;
                }
                if (!response.ok) {
                    throw new Error(await this.errorText(response));
                }
                const data = await response.json();
                this.memberships = data.memberships || [];
                this.availableRoles = data.available_roles || [];
                if (!this.invite.role || !this.availableRoles.includes(this.invite.role)) {
                    this.invite.role = this.defaultRole();
                }
            } catch (error) {
                this.memberships = [];
                this.availableRoles = [];
                this.showFlash(`Could not load members: ${error.message}`, false);
            } finally {
                this.loading = false;
            }
        },

        async inviteMember() {
            if (!this.canInvite()) {
                return;
            }
            this.saving = true;
            try {
                const response = await fetch(`${this.membershipEndpoint()}/invites`, {
                    method: 'POST',
                    headers: this.apiHeaders(),
                    body: JSON.stringify({
                        email: this.invite.email,
                        full_name: this.invite.full_name || null,
                        role: this.invite.role,
                    }),
                });
                if (!response.ok) {
                    throw new Error(await this.errorText(response));
                }
                this.invite.email = '';
                this.invite.full_name = '';
                this.showFlash('Member assignment added.', true);
                await this.loadMemberships();
            } catch (error) {
                this.showFlash(`Could not add member: ${error.message}`, false);
            } finally {
                this.saving = false;
            }
        },

        async updateMembership(membership, active) {
            this.saving = true;
            try {
                const response = await fetch(`${this.membershipEndpoint()}/users/${membership.user.id}`, {
                    method: 'PUT',
                    headers: this.apiHeaders(),
                    body: JSON.stringify({
                        user_id: membership.user.id,
                        role: membership.role,
                        active,
                    }),
                });
                if (!response.ok) {
                    throw new Error(await this.errorText(response));
                }
                this.showFlash('Member assignment updated.', true);
                await this.loadMemberships();
            } catch (error) {
                this.showFlash(`Could not update member: ${error.message}`, false);
                await this.loadMemberships();
            } finally {
                this.saving = false;
            }
        },

        async deactivateMembership(membership) {
            this.saving = true;
            try {
                const response = await fetch(`${this.membershipEndpoint()}/users/${membership.user.id}`, {
                    method: 'DELETE',
                    headers: this.apiHeaders(),
                });
                if (!response.ok) {
                    throw new Error(await this.errorText(response));
                }
                this.showFlash('Member assignment deactivated.', true);
                await this.loadMemberships();
            } catch (error) {
                this.showFlash(`Could not deactivate member: ${error.message}`, false);
            } finally {
                this.saving = false;
            }
        },

        setScope(scope) {
            this.scope = scope;
            if (scope === 'workspace' && !this.selectedWorkspaceId) {
                const workspaces = this.currentWorkspaces();
                this.selectedWorkspaceId = workspaces.length > 0 ? workspaces[0].id : '';
            }
            this.loadMemberships();
        },

        selectOrganization(value) {
            this.selectedOrgId = value;
            const workspaces = this.currentWorkspaces();
            this.selectedWorkspaceId = workspaces.length > 0 ? workspaces[0].id : '';
            if (this.scope === 'workspace' && !this.selectedWorkspaceId) {
                this.scope = 'organization';
            }
            this.loadMemberships();
        },

        membershipEndpoint() {
            if (this.scope === 'organization') {
                return this.selectedOrgId
                    ? `/api/v1/memberships/organizations/${this.selectedOrgId}`
                    : '';
            }
            return this.selectedWorkspaceId
                ? `/api/v1/memberships/workspaces/${this.selectedWorkspaceId}`
                : '';
        },

        currentOrganization() {
            return this.organizations.find((organization) => String(organization.id) === String(this.selectedOrgId));
        },

        currentWorkspaces() {
            const organization = this.currentOrganization();
            return organization ? (organization.workspaces || []) : [];
        },

        currentBillingOwner() {
            return this.currentOrganization()?.billing_owner || {};
        },

        currentAccountState() {
            return this.currentOrganization()?.account_state || {};
        },

        workspaceCount() {
            return this.organizations.reduce((count, organization) => {
                return count + (organization.workspaces || []).length;
            }, 0);
        },

        currentWorkspace() {
            return this.currentWorkspaces().find((workspace) => String(workspace.id) === String(this.selectedWorkspaceId));
        },

        scopeLabel() {
            if (this.scope === 'organization') {
                const organization = this.currentOrganization();
                return organization ? organization.name : 'Organization';
            }
            const workspace = this.currentWorkspace();
            return workspace ? workspace.name : 'Workspace';
        },

        scopeDescription() {
            if (this.scope === 'organization') {
                return 'Organization roles apply across tenant-level account and billing surfaces.';
            }
            return 'Workspace roles control reports, domains, mail sources, settings, and audit access.';
        },

        planLimit(metric) {
            return this.currentOrganization()?.plan_limits?.[metric] || null;
        },

        planLimitRows() {
            const limits = this.currentOrganization()?.plan_limits || {};
            return Object.entries(limits)
                .map(([metric, limit]) => ({
                    metric,
                    label: this.planLimitLabel(metric),
                    current: limit.current,
                    limit: limit.limit,
                    unit: limit.unit || '',
                    enforced: Boolean(limit.enforced),
                    near_limit: Boolean(limit.near_limit),
                    usage_percent: Number(limit.usage_percent || 0),
                    message: limit.message || '',
                }))
                .sort((left, right) => left.label.localeCompare(right.label));
        },

        seatLimitWarning() {
            const limit = this.planLimit('users');
            if (!limit || !limit.near_limit || !limit.message) return null;
            return limit;
        },

        planLimitLabel(metric) {
            const labels = {
                aggregate_messages: 'Monthly messages',
                api_tokens: 'API tokens',
                mail_sources: 'Mail sources',
                monitored_domains: 'Monitored domains',
                retention_days: 'Retention',
                users: 'Seats',
                webhooks: 'Webhooks',
            };
            return labels[metric] || metric.replaceAll('_', ' ');
        },

        formatLimitValue(value, unit) {
            if (value === null || value === undefined) return 'unlimited';
            if (typeof value === 'boolean') return value ? 'enabled' : 'disabled';
            const suffix = unit ? ` ${unit}` : '';
            return `${value}${suffix}`;
        },

        formatLimitUsage(limit) {
            return `${this.formatLimitValue(limit.current, limit.unit)} / ${this.formatLimitValue(limit.limit, limit.unit)}`;
        },

        limitTrackClass(limit) {
            if (limit.limit === null || limit.limit === undefined) return 'bg-[#2c9aa3]';
            if (limit.usage_percent >= 100) return 'bg-[#ff6333]';
            if (limit.near_limit) return 'bg-[#f2a23a]';
            return 'bg-[#2c9aa3]';
        },

        ownerBadgeClass() {
            const ownerType = this.currentBillingOwner().owner_type;
            if (ownerType === 'provider') return 'badge-info';
            if (ownerType === 'self_hosted') return 'badge-success';
            if (ownerType === 'dmarq') return 'badge-primary';
            return 'badge-ghost';
        },

        accountStateLabel() {
            const state = this.currentAccountState();
            return state.status ? state.status.replaceAll('_', ' ') : 'unconfigured';
        },

        stateBadgeClass() {
            const state = this.currentAccountState();
            if (state.read_only || state.closed) return 'badge-error';
            if (state.grace_period) return 'badge-warning';
            if (state.can_mutate) return 'badge-success';
            return 'badge-ghost';
        },

        isAccountRestricted() {
            const state = this.currentAccountState();
            return Boolean(state.read_only || state.grace_period);
        },

        roleLabel(role) {
            const labels = {
                workspace_owner: 'Workspace owner',
                domain_admin: 'Domain admin',
                operator: 'Operator',
                analyst: 'Analyst',
                auditor: 'Auditor',
                organization_owner: 'Organization owner',
                organization_admin: 'Organization admin',
                billing_admin: 'Billing admin',
                organization_auditor: 'Organization auditor',
            };
            return labels[role] || role.replaceAll('_', ' ');
        },

        defaultRole() {
            if (this.scope === 'organization' && this.availableRoles.includes('organization_auditor')) {
                return 'organization_auditor';
            }
            if (this.availableRoles.includes('analyst')) {
                return 'analyst';
            }
            return this.availableRoles[0] || '';
        },

        canInvite() {
            return Boolean(this.membershipEndpoint() && this.invite.email && this.invite.role);
        },

        memberInitial(membership) {
            const value = membership.user.full_name || membership.user.email || '?';
            return value.trim().charAt(0).toUpperCase();
        },

        showFlash(message, ok) {
            this.flash = { message, ok };
            window.setTimeout(() => {
                if (this.flash.message === message) {
                    this.flash.message = '';
                }
            }, 4500);
        },

        async errorText(response) {
            try {
                const data = await response.json();
                return data.detail || response.statusText;
            } catch (_) {
                return response.statusText;
            }
        },
    };
}