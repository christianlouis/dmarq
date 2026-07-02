document.addEventListener('alpine:init', () => {
    // components/ui/alert.html
    Alpine.data('alertComponent', () => ({
        open: true,
        close() {
            this.open = false;
        }
    }));
});
