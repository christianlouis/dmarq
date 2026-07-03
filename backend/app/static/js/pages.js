document.addEventListener('alpine:init', () => {
    // components/ui/alert.html
    Alpine.data('alertComponent', () => ({
        open: true,
        init() {
            this.bindControls();
        },
        bindControls() {
            if (typeof document === 'undefined') return;
            const hasElement = typeof Element !== 'undefined';
            const root = hasElement && this.$root instanceof Element ? this.$root : null;
            if (!root || root.dataset.alertControlsBound === 'true') return;
            root.dataset.alertControlsBound = 'true';

            root.addEventListener('click', (event) => {
                if (!hasElement || !(event.target instanceof Element)) return;
                const closeButton = event.target.closest('[data-alert-close]');
                if (closeButton && root.contains(closeButton)) {
                    this.close();
                }
            });
        },
        close() {
            this.open = false;
        }
    }));
});
