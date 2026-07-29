function profileApp() {
    return {
        user: null,
        guidanceLoaded: false,
        guidanceSaving: false,
        guidanceSaved: false,
        guidanceError: '',
        guidance: {
            depth: 'standard',
            context: 'watch',
            teaching_hints_enabled: false,
        },
        guidanceDepthOptions: [
            {id: 'guided', label: 'Guide me', example: 'Lead with the conclusion and one safe next step.'},
            {id: 'standard', label: 'Balanced', example: 'Show concise operational detail beside the recommendation.'},
            {id: 'expert', label: 'Show full technical detail', example: 'Expose protocol fields, evidence inputs, and advanced controls first.'},
        ],
        guidanceContextOptions: [
            {id: 'watch', label: 'Watch'},
            {id: 'diagnose', label: 'Diagnose'},
            {id: 'evidence', label: 'Evidence'},
        ],

        get hasPicture() {
            return Boolean(this.user && this.user.picture);
        },

        get showPlaceholderAvatar() {
            return Boolean(this.user && !this.user.picture);
        },

        get avatarAlt() {
            if (!this.user) return 'User avatar';
            return this.user.full_name || this.user.email || 'User avatar';
        },

        get avatarInitial() {
            if (!this.user) return '?';
            const source = this.user.full_name || this.user.email || '?';
            return source.charAt(0).toUpperCase();
        },

        get displayName() {
            if (!this.user) return '...';
            return this.user.full_name || '-';
        },

        get emailText() {
            return this.user && this.user.email ? this.user.email : '';
        },

        get usernameText() {
            return this.user && this.user.username ? this.user.username : '-';
        },

        get isAdmin() {
            return Boolean(this.user && this.user.is_superuser);
        },

        get isRegularUser() {
            return Boolean(this.user && !this.user.is_superuser);
        },

        get externalIdText() {
            return this.user && this.user.logto_id ? this.user.logto_id : '-';
        },

        get authDisabled() {
            return Boolean(this.user && this.user.auth_disabled);
        },

        get externalAuthEnabled() {
            return Boolean(this.user && !this.user.auth_disabled);
        },

        get authProviderText() {
            return this.user && this.user.auth_provider_label
                ? this.user.auth_provider_label
                : 'External auth';
        },

        get guidanceContextDescription() {
            const descriptions = {
                watch: 'See what changed, whether action is needed, and the next step.',
                diagnose: 'Start with the affected mailflow and the evidence needed to resolve it.',
                evidence: 'Open with complete report, DNS, and protocol evidence.',
            };
            return descriptions[this.guidance.context] || descriptions.watch;
        },

        guidanceChoiceClass(selected) {
            return selected
                ? 'border-primary bg-primary/5 text-base-content ring-1 ring-primary'
                : 'border-base-300 bg-base-100 text-base-content hover:border-primary/60';
        },

        async init() {
            await Promise.allSettled([this.loadUser(), this.loadGuidancePreference()]);
        },

        async loadUser() {
            try {
                const response = await fetch('/api/v1/auth/me');
                if (response.ok) {
                    this.user = await response.json();
                }
            } catch (error) {
                console.error('Failed to load user profile:', error);
            }
        },

        async loadGuidancePreference() {
            try {
                const response = await fetch('/api/v1/workspaces/guidance/preferences');
                const data = await response.json().catch(() => ({}));
                if (!response.ok) throw new Error(data.detail || 'Explanation preferences could not be loaded.');
                this.guidance = {
                    depth: data.depth || 'standard',
                    context: data.context || 'watch',
                    teaching_hints_enabled: Boolean(data.teaching_hints_enabled),
                };
                this.guidanceLoaded = true;
            } catch (error) {
                this.guidanceError = error.message || 'Explanation preferences could not be loaded.';
                this.guidanceLoaded = true;
            }
        },

        async saveGuidancePreference() {
            if (this.guidanceSaving) return;
            this.guidanceSaving = true;
            this.guidanceSaved = false;
            this.guidanceError = '';
            try {
                const response = await fetch('/api/v1/workspaces/guidance/preferences', {
                    method: 'PUT',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(this.guidance),
                });
                const data = await response.json().catch(() => ({}));
                if (!response.ok) throw new Error(data.detail || 'Explanation preferences could not be saved.');
                this.guidance = {
                    depth: data.depth,
                    context: data.context,
                    teaching_hints_enabled: Boolean(data.teaching_hints_enabled),
                };
                this.guidanceSaved = true;
            } catch (error) {
                this.guidanceError = error.message || 'Explanation preferences could not be saved.';
            } finally {
                this.guidanceSaving = false;
            }
        },
    };
}

document.addEventListener('alpine:init', () => {
    Alpine.data('profileApp', profileApp);
});
