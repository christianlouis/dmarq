function profileApp() {
    return {
        user: null,

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

        async init() {
            try {
                const response = await fetch('/api/v1/auth/me');
                if (response.ok) {
                    this.user = await response.json();
                }
            } catch (error) {
                console.error('Failed to load user profile:', error);
            }
        },
    };
}

document.addEventListener('alpine:init', () => {
    Alpine.data('profileApp', profileApp);
});
