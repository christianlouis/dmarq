function deliveryEventsApp() {
    return {
        events: [], loading: true, error: '', message: '',
        async init() {
            this.$root.addEventListener('change', event => {
                const input = event.target.closest('[data-delivery-dsn-file]');
                if (input?.files?.[0]) this.uploadDsn(input.files[0]);
            });
            await this.load();
        },
        async load() {
            this.loading = true; this.error = '';
            try {
                const domain = new URLSearchParams(window.location.search).get('domain');
                const query = domain ? `?domain=${encodeURIComponent(domain)}` : '';
                const response = await fetch(`/api/v1/delivery-events${query}`);
                const payload = await response.json().catch(() => ({}));
                if (!response.ok) throw new Error(payload.detail || 'Delivery evidence could not be loaded.');
                this.events = payload.events || [];
            } catch (error) { this.error = error?.message || 'Delivery evidence could not be loaded.'; }
            finally { this.loading = false; }
        },
        async uploadDsn(file) {
            this.error = ''; this.message = 'Importing delivery status…';
            const form = new FormData(); form.append('file', file);
            try {
                const response = await fetch('/api/v1/delivery-events/dsn', { method: 'POST', body: form });
                const payload = await response.json().catch(() => ({}));
                if (!response.ok) throw new Error(payload.detail || 'Delivery status could not be imported.');
                this.message = `${payload.accepted?.length || 0} delivery event(s) imported; ${payload.duplicates?.length || 0} duplicate(s).`;
                await this.load();
            } catch (error) { this.message = ''; this.error = error?.message || 'Delivery status could not be imported.'; }
        },
        outcomeClass(outcome) {
            if (['bounced', 'blocked', 'dropped'].includes(outcome)) return 'bg-red-100 text-red-800';
            if (outcome === 'deferred') return 'bg-yellow-100 text-yellow-800';
            if (outcome === 'delivered') return 'bg-green-100 text-green-800';
            return 'bg-gray-100 text-gray-700';
        },
        causeLabel(cause) { return String(cause || 'unknown other').replaceAll('_', ' '); },
        formatDate(value) { return value ? new Date(value).toLocaleString() : 'Time unavailable'; },
        nextStep(event) {
            const steps = {
                authentication_policy_rejection: 'Open the affected domain sender setup and repair aligned DKIM or SPF before retrying.',
                recipient_user_unknown: 'Verify the recipient address before retrying.',
                mailbox_quota: 'Ask the recipient to free quota or use another address.',
                rate_limiting: 'Slow delivery and retry after the remote provider window.',
                reputation_spam_policy: 'Review the rejecting MTA response, sender reputation, and authentication before retrying.',
                transport_tls_dns: 'Check destination DNS, connectivity, and TLS before retrying.',
                content_attachment_policy: 'Change the rejected content or attachment according to the remote policy.',
            };
            return steps[event.cause_family] || 'Use the SMTP status and remote diagnostic to correct the sending path, then verify a newer event.';
        },
        domainHref(event) {
            return event?.domain
                ? `/domains/${encodeURIComponent(event.domain)}#sending-sources`
                : '/domains';
        },
        domainActionLabel(event) {
            return event?.domain ? 'Open sender setup' : 'Review domains';
        },
    };
}
document.addEventListener('alpine:init', () => Alpine.data('deliveryEventsApp', deliveryEventsApp));
