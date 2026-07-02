function profileApp() {
    return {
        user: null,
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
