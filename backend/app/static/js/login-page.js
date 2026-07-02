document.addEventListener('alpine:init', () => {
    Alpine.data('loginErrorBanner', () => ({
        error: new URLSearchParams(window.location.search).get('error'),
    }));
});

if (localStorage.getItem('darkMode') === 'true') {
    document.documentElement.setAttribute('data-theme', 'dmarqdark');
}
