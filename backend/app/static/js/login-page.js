document.addEventListener('alpine:init', () => {
    Alpine.data('loginErrorBanner', () => ({
        error: new URLSearchParams(window.location.search).get('error'),

        get hasError() {
            return Boolean(this.error);
        },

        get errorMessage() {
            if (this.error === 'callback_failed') {
                return 'The authentication callback failed. Please try again.';
            }
            if (this.error === 'token_error') {
                return 'Could not read authentication token. Please try again.';
            }
            return 'An unexpected error occurred. Please try again.';
        },
    }));
});

if (localStorage.getItem('darkMode') === 'true') {
    document.documentElement.setAttribute('data-theme', 'dark');
}
