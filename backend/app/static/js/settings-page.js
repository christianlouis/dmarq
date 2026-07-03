function settingsApp() {
    return {
        s: {},           // flat map of key → value (strings)
        saving: false,
        flashMsg: '',
        flashOk: true,
        _flashTimer: null,
        testingNotification: false,
        checkingAlerts: false,
        sendingAlerts: false,
        alertPreview: null,
        previewingSummary: false,
        sendingSummary: false,
        summaryPeriod: 'daily',
        summaryPreview: null,
        loadingAlertHistory: false,
        alertHistory: [],
        loadingConfigAudit: false,
        configAudit: [],
        loadingDnsProviders: false,
        dnsProviders: [],
        selectedDnsProvider: 'cloudflare',
        loadingCfZones: false,
        importingCfZones: false,
        dnsProviderImportSummary: '',
        dnsProviderImportError: '',
        connectingCloudflare: false,
        cfOAuthStatus: {
            oauth_configured: false,
            connected: false,
            auth_mode: null,
            scopes: null,
            scope_profile: 'read_only',
            scope_profiles: [],
            connected_at: null,
        },
        cfZones: [],
        showCfToken: false,
        loadingMailServiceDomains: false,
        importingMailServiceDomains: false,
        mailServiceDomains: [],
        showPostmarkToken: false,
        loadingWebhooks: false,
        savingWebhook: false,
        testingWebhookId: null,
        disablingWebhookId: null,
        processingWebhooks: false,
        loadingWebhookDeliveries: false,
        loadingAIProfiles: false,
        testingAIConnection: false,
        aiProviderProfiles: [],
        aiConnectionResult: null,
        aiModels: [],
        showAIKey: false,
        webhooks: [],
        webhookDeliveries: [],
        webhookEventTypes: [],
        newWebhook: {
            name: '',
            url: '',
            eventType: '*',
            max_attempts: 5,
            timeout_seconds: 10,
        },

        // Session cookie is sent automatically by the browser (httpOnly, same-origin).
        // No manual auth header needed for API calls from the UI.
        apiHeaders() {
            return { 'Content-Type': 'application/json' };
        },

        workspaceHeaders() {
            const headers = this.apiHeaders();
            const workspaceId = localStorage.getItem('dmarq.selectedWorkspaceId');
            if (workspaceId) {
                headers['X-DMARQ-Workspace-ID'] = workspaceId;
            }
            return headers;
        },

        async loadSettings() {
            try {
                const res = await fetch('/api/v1/settings', { headers: this.apiHeaders() });
                if (res.status === 401 || res.status === 403) {
                    window.location.href = '/login?next=/settings';
                    return;
                }
                if (!res.ok) {
                    this.showFlash('Failed to load settings: ' + res.statusText, false);
                    return;
                }
                const rows = await res.json();
                const map = {};
                rows.forEach(r => { map[r.key] = r.value ?? ''; });
                this.s = map;
                await this.loadAlertHistory(false);
                await this.loadConfigAudit(false);
                await this.loadWebhooks(false);
                await this.loadWebhookDeliveries(false);
                await this.loadCloudflareOAuthStatus(false);
                await this.loadDNSProviders(false);
                await this.loadAIProviderProfiles(false);
            } catch (err) {
                this.showFlash('Error loading settings: ' + err.message, false);
            }
        },

        async saveCategory(category) {
            this.saving = true;
            // Collect all keys that belong to this category
            const categoryKeys = Object.keys(this.s).filter(k => k.startsWith(category + '.'));
            const settings = {};
            categoryKeys.forEach(k => { settings[k] = String(this.s[k] ?? ''); });
            try {
                const res = await fetch('/api/v1/settings/bulk', {
                    method: 'POST',
                    headers: this.apiHeaders(),
                    body: JSON.stringify({ settings }),
                });
                if (!res.ok) {
                    const data = await res.json().catch(() => ({}));
                    this.showFlash('Save failed: ' + (data.detail || res.statusText), false);
                } else {
                    const rows = await res.json();
                    rows.forEach(r => { this.s[r.key] = r.value ?? ''; });
                    if (category === 'notifications') {
                        await this.loadConfigAudit(false);
                    }
                    this.showFlash('Settings saved successfully.', true);
                }
            } catch (err) {
                this.showFlash('Error saving settings: ' + err.message, false);
            } finally {
                this.saving = false;
            }
        },

        async saveAutomationSettings() {
            this.saving = true;
            const keys = Object.keys(this.s).filter(k => k.startsWith('ai.') || k.startsWith('mcp.'));
            const settings = {};
            keys.forEach(k => { settings[k] = String(this.s[k] ?? ''); });
            try {
                const res = await fetch('/api/v1/settings/bulk', {
                    method: 'POST',
                    headers: this.apiHeaders(),
                    body: JSON.stringify({ settings }),
                });
                const data = await res.json().catch(() => ({}));
                if (!res.ok) {
                    this.showFlash('Save failed: ' + (data.detail || res.statusText), false);
                } else {
                    data.forEach(r => { this.s[r.key] = r.value ?? ''; });
                    this.showFlash('Automation settings saved.', true);
                }
            } catch (err) {
                this.showFlash('Error saving automation settings: ' + err.message, false);
            } finally {
                this.saving = false;
            }
        },

        aiProviderProfile(provider = null) {
            const selected = String(provider || this.s['ai.provider'] || 'template').replaceAll('-', '_');
            return (this.aiProviderProfiles || []).find(profile => profile.id === selected)
                || this.aiProviderProfiles[0]
                || { id: 'template', name: 'Offline template', description: '', requires_api_key: false, requires_base_url: false };
        },

        aiProviderNeedsApiKey() {
            return Boolean(this.aiProviderProfile().requires_api_key);
        },

        aiProviderNeedsBaseUrl() {
            return Boolean(this.aiProviderProfile().requires_base_url);
        },

        async loadAIProviderProfiles(showMessage = false) {
            this.loadingAIProfiles = true;
            try {
                const res = await fetch('/api/v1/settings/ai/provider-profiles', {
                    headers: this.apiHeaders(),
                });
                const data = await res.json().catch(() => ([]));
                if (!res.ok) {
                    if (showMessage) {
                        this.showFlash('AI provider profiles failed: ' + (data.detail || res.statusText), false);
                    }
                    return;
                }
                this.aiProviderProfiles = Array.isArray(data) ? data : [];
                const profile = this.aiProviderProfile();
                if (!this.s['ai.provider']) {
                    this.s['ai.provider'] = profile.id || 'template';
                }
                if (!this.s['ai.remote_base_url'] && profile.default_base_url) {
                    this.s['ai.remote_base_url'] = profile.default_base_url;
                }
            } catch (err) {
                if (showMessage) {
                    this.showFlash('Error loading AI provider profiles: ' + err.message, false);
                }
            } finally {
                this.loadingAIProfiles = false;
            }
        },

        onAIProviderChanged() {
            const profile = this.aiProviderProfile();
            this.aiConnectionResult = null;
            this.aiModels = [];
            if (profile.default_base_url && !this.s['ai.remote_base_url']) {
                this.s['ai.remote_base_url'] = profile.default_base_url;
            }
            if (profile.default_model && !this.s['ai.model']) {
                this.s['ai.model'] = profile.default_model;
            }
        },

        async testAIConnection() {
            this.testingAIConnection = true;
            this.aiConnectionResult = null;
            try {
                const res = await fetch('/api/v1/settings/ai/test', {
                    method: 'POST',
                    headers: this.apiHeaders(),
                    body: JSON.stringify({
                        provider: this.s['ai.provider'] || 'template',
                        base_url: this.s['ai.remote_base_url'] || '',
                        api_key: this.s['ai.api_key'] || '',
                        model: this.s['ai.model'] || '',
                    }),
                });
                const data = await res.json().catch(() => ({}));
                if (!res.ok) {
                    const detail = typeof data.detail === 'string' ? data.detail : data.detail?.message;
                    this.aiConnectionResult = { success: false, message: detail || res.statusText };
                    this.showFlash('AI connection failed: ' + this.aiConnectionResult.message, false);
                    return;
                }
                this.aiConnectionResult = data;
                this.aiModels = data.models || [];
                if (!this.s['ai.model'] && data.selected_model) {
                    this.s['ai.model'] = data.selected_model;
                }
                this.showFlash(data.message || 'AI connection succeeded.', true);
            } catch (err) {
                this.aiConnectionResult = { success: false, message: err.message };
                this.showFlash('Error testing AI connection: ' + err.message, false);
            } finally {
                this.testingAIConnection = false;
            }
        },

        async sendTestNotification() {
            this.testingNotification = true;
            try {
                await this.saveCategory('notifications');
                const res = await fetch('/api/v1/settings/notifications/test', {
                    method: 'POST',
                    headers: this.apiHeaders(),
                });
                const data = await res.json().catch(() => ({}));
                if (!res.ok) {
                    const detail = data.detail || {};
                    this.showFlash('Test failed: ' + (detail.message || data.detail || res.statusText), false);
                } else {
                    this.showFlash('Test notification sent.', true);
                }
            } catch (err) {
                this.showFlash('Error sending test notification: ' + err.message, false);
            } finally {
                this.testingNotification = false;
            }
        },

        async checkAlerts() {
            this.checkingAlerts = true;
            try {
                await this.saveCategory('notifications');
                const res = await fetch('/api/v1/settings/notifications/alerts', {
                    headers: this.apiHeaders(),
                });
                const data = await res.json().catch(() => ({}));
                if (!res.ok) {
                    this.showFlash('Alert check failed: ' + (data.detail || res.statusText), false);
                } else {
                    this.alertPreview = (data.alerts || []).length;
                    await this.loadAlertHistory(false);
                    this.showFlash(`${this.alertPreview} active alert${this.alertPreview === 1 ? '' : 's'} found.`, true);
                }
            } catch (err) {
                this.showFlash('Error checking alerts: ' + err.message, false);
            } finally {
                this.checkingAlerts = false;
            }
        },

        async sendAlertSummary() {
            this.sendingAlerts = true;
            try {
                await this.saveCategory('notifications');
                const res = await fetch('/api/v1/settings/notifications/alerts/send', {
                    method: 'POST',
                    headers: this.apiHeaders(),
                });
                const data = await res.json().catch(() => ({}));
                if (!res.ok) {
                    const detail = data.detail || {};
                    const notification = detail.notification || {};
                    this.showFlash('Alert send failed: ' + (notification.message || data.detail || res.statusText), false);
                } else {
                    this.alertPreview = (data.alerts || []).length;
                    await this.loadAlertHistory(false);
                    this.showFlash(data.notification.skipped ? 'No active alerts to send.' : 'Alert summary sent.', true);
                }
            } catch (err) {
                this.showFlash('Error sending alerts: ' + err.message, false);
            } finally {
                this.sendingAlerts = false;
            }
        },

        async previewSummary() {
            this.previewingSummary = true;
            try {
                await this.saveCategory('notifications');
                const res = await fetch(`/api/v1/settings/notifications/summary?period=${this.summaryPeriod}`, {
                    headers: this.apiHeaders(),
                });
                const data = await res.json().catch(() => ({}));
                if (!res.ok) {
                    this.showFlash('Summary preview failed: ' + (data.detail || res.statusText), false);
                } else {
                    this.summaryPreview = data.summary;
                    this.showFlash('Summary preview updated.', true);
                }
            } catch (err) {
                this.showFlash('Error previewing summary: ' + err.message, false);
            } finally {
                this.previewingSummary = false;
            }
        },

        async sendSummaryNow() {
            this.sendingSummary = true;
            try {
                await this.saveCategory('notifications');
                const res = await fetch(`/api/v1/settings/notifications/summary/send?period=${this.summaryPeriod}`, {
                    method: 'POST',
                    headers: this.apiHeaders(),
                });
                const data = await res.json().catch(() => ({}));
                if (!res.ok) {
                    const detail = data.detail || {};
                    const notification = detail.notification || {};
                    this.showFlash('Summary send failed: ' + (notification.message || data.detail || res.statusText), false);
                } else {
                    this.summaryPreview = data.summary;
                    await this.loadAlertHistory(false);
                    this.showFlash('Summary notification sent.', true);
                }
            } catch (err) {
                this.showFlash('Error sending summary: ' + err.message, false);
            } finally {
                this.sendingSummary = false;
            }
        },

        async loadAlertHistory(showMessage = true) {
            this.loadingAlertHistory = true;
            try {
                const res = await fetch('/api/v1/settings/notifications/alerts/history?limit=10', {
                    headers: this.apiHeaders(),
                });
                const data = await res.json().catch(() => ({}));
                if (!res.ok) {
                    if (showMessage) {
                        this.showFlash('Alert history failed: ' + (data.detail || res.statusText), false);
                    }
                } else {
                    this.alertHistory = data.history || [];
                    if (showMessage) {
                        this.showFlash('Alert history refreshed.', true);
                    }
                }
            } catch (err) {
                if (showMessage) {
                    this.showFlash('Error loading alert history: ' + err.message, false);
                }
            } finally {
                this.loadingAlertHistory = false;
            }
        },

        async loadConfigAudit(showMessage = true) {
            this.loadingConfigAudit = true;
            try {
                const res = await fetch('/api/v1/settings/notifications/config-audit?limit=10', {
                    headers: this.apiHeaders(),
                });
                const data = await res.json().catch(() => ({}));
                if (!res.ok) {
                    if (showMessage) {
                        this.showFlash('Configuration audit failed: ' + (data.detail || res.statusText), false);
                    }
                } else {
                    this.configAudit = data.audit || [];
                    if (showMessage) {
                        this.showFlash('Configuration audit refreshed.', true);
                    }
                }
            } catch (err) {
                if (showMessage) {
                    this.showFlash('Error loading configuration audit: ' + err.message, false);
                }
            } finally {
                this.loadingConfigAudit = false;
            }
        },

        async discoverCloudflareZones() {
            return this.discoverDNSProviderZones('cloudflare');
        },

        dnsImportProviders() {
            const providers = (this.dnsProviders || []).filter(provider => provider.import_available);
            return providers.length ? providers : [{ id: 'cloudflare', name: 'Cloudflare' }];
        },

        selectedDnsProviderMetadata() {
            return this.dnsImportProviders().find(provider => provider.id === this.selectedDnsProvider)
                || this.dnsImportProviders()[0]
                || { id: 'cloudflare', name: 'Cloudflare' };
        },

        selectedDnsProviderName() {
            return this.selectedDnsProviderMetadata().name || this.selectedDnsProvider || 'Selected provider';
        },

        selectedDnsProviderHint() {
            const provider = this.selectedDnsProviderMetadata();
            const status = provider.zone_import_status || (provider.import_available ? 'ready' : 'planned');
            if (status !== 'ready') {
                return ' is tracked in the connector registry, but zone import is not ready yet.';
            }
            const permissions = (provider.minimum_permissions || []).join('; ');
            return permissions
                ? ` import can use ${permissions}.`
                : ' import is available with configured provider credentials.';
        },

        selectedDnsProviderAuthHint() {
            const provider = this.selectedDnsProviderMetadata();
            return (provider.auth_models || [])
                .map(value => String(value).replaceAll('_', ' '))
                .join(', ');
        },

        selectedDnsProviderSetupHint() {
            return this.selectedDnsProviderMetadata().setup_hint || '';
        },

        selectedDnsProviderDocsUrl() {
            return this.selectedDnsProviderMetadata().docs_url || '';
        },

        resetDnsProviderImportState() {
            this.cfZones = [];
            this.dnsProviderImportSummary = '';
            this.dnsProviderImportError = '';
        },

        importableDnsProviderZoneCount() {
            return this.cfZones.filter(zone => !zone.imported).length;
        },

        providerErrorDetail(data, fallback) {
            const detail = data?.detail;
            if (typeof detail === 'string') return detail;
            if (detail?.message) return detail.message;
            if (detail?.error) return detail.error;
            if (Array.isArray(detail)) {
                return detail.map(item => item?.msg || item?.message || String(item)).join('; ');
            }
            return fallback || 'Provider request failed.';
        },

        async loadDNSProviders(showMessage = false) {
            this.loadingDnsProviders = true;
            try {
                const res = await fetch('/api/v1/domains/dns/providers', {
                    headers: this.workspaceHeaders(),
                });
                const data = await res.json().catch(() => ({}));
                if (!res.ok) {
                    if (showMessage) {
                        this.showFlash('DNS provider registry failed: ' + (data.detail || res.statusText), false);
                    }
                    return;
                }
                this.dnsProviders = data.providers || [];
                const importProviders = this.dnsImportProviders();
                if (!importProviders.some(provider => provider.id === this.selectedDnsProvider)) {
                    this.selectedDnsProvider = importProviders[0]?.id || 'cloudflare';
                    this.resetDnsProviderImportState();
                }
            } catch (err) {
                if (showMessage) {
                    this.showFlash('Error loading DNS providers: ' + err.message, false);
                }
            } finally {
                this.loadingDnsProviders = false;
            }
        },

        async discoverDNSProviderZones(provider = null) {
            const providerId = provider || this.selectedDnsProvider || 'cloudflare';
            this.selectedDnsProvider = providerId;
            this.loadingCfZones = true;
            this.cfZones = [];
            this.dnsProviderImportSummary = '';
            this.dnsProviderImportError = '';
            try {
                if (providerId === 'cloudflare') {
                    await this.saveCategory('cloudflare');
                }
                const res = await fetch(`/api/v1/domains/dns/import/${encodeURIComponent(providerId)}/preview`, {
                    headers: this.workspaceHeaders(),
                });
                const data = await res.json().catch(() => ({}));
                if (!res.ok) {
                    this.dnsProviderImportError = this.providerErrorDetail(data, res.statusText);
                    this.showFlash(`${this.selectedDnsProviderName()} discovery failed: ` + this.dnsProviderImportError, false);
                } else {
                    this.cfZones = (data.zones || []).map(zone => ({
                        id: `${zone.provider || providerId}:${zone.zone_id || zone.id || zone.domain}`,
                        name: zone.domain,
                        provider: zone.provider || providerId,
                        provider_name: zone.provider_name || data.provider_name || this.selectedDnsProviderName(),
                        status: zone.status,
                        account_name: zone.account_name,
                        imported: zone.imported,
                    }));
                    const importableCount = data.importable_count ?? this.cfZones.filter(zone => !zone.imported).length;
                    this.dnsProviderImportSummary = this.cfZones.length
                        ? `${importableCount} of ${this.cfZones.length} discovered zones can be imported.`
                        : 'Check that the connected provider account has zone-list permissions and that the account actually manages DNS zones for this workspace.';
                    this.showFlash(`${this.cfZones.length} ${this.selectedDnsProviderName()} zone${this.cfZones.length === 1 ? '' : 's'} found.`, true);
                }
            } catch (err) {
                this.dnsProviderImportError = err.message || 'Provider request failed.';
                this.showFlash(`Error discovering ${this.selectedDnsProviderName()} zones: ` + this.dnsProviderImportError, false);
            } finally {
                this.loadingCfZones = false;
            }
        },

        async loadCloudflareOAuthStatus(showMessage = false) {
            try {
                const res = await fetch('/api/v1/domains/cloudflare/oauth/status', {
                    headers: this.workspaceHeaders(),
                });
                const data = await res.json().catch(() => ({}));
                if (!res.ok) {
                    if (showMessage) {
                        this.showFlash('Cloudflare status failed: ' + (data.detail || res.statusText), false);
                    }
                    return;
                }
                this.cfOAuthStatus = data;
                if (!this.s['cloudflare.oauth_scope_profile']) {
                    this.s['cloudflare.oauth_scope_profile'] = data.scope_profile || 'read_only';
                }
            } catch (err) {
                if (showMessage) {
                    this.showFlash('Error loading Cloudflare status: ' + err.message, false);
                }
            }
        },

        async connectCloudflare() {
            this.connectingCloudflare = true;
            try {
                const profile = encodeURIComponent(this.s['cloudflare.oauth_scope_profile'] || 'read_only');
                const res = await fetch(`/api/v1/domains/cloudflare/oauth/authorize-url?return_to=/settings&scope_profile=${profile}`, {
                    headers: this.workspaceHeaders(),
                });
                const data = await res.json().catch(() => ({}));
                if (!res.ok) {
                    const detail = typeof data.detail === 'string' ? data.detail : data.detail?.message;
                    this.showFlash('Cloudflare connect failed: ' + (detail || res.statusText), false);
                    return;
                }
                window.location.href = data.authorization_url;
            } catch (err) {
                this.showFlash('Error starting Cloudflare connection: ' + err.message, false);
            } finally {
                this.connectingCloudflare = false;
            }
        },

        async importCloudflareZones() {
            return this.importDNSProviderZones('cloudflare');
        },

        async importDNSProviderZones(provider = null) {
            const providerId = provider || this.selectedDnsProvider || 'cloudflare';
            this.selectedDnsProvider = providerId;
            this.importingCfZones = true;
            this.dnsProviderImportError = '';
            try {
                const domains = this.cfZones.filter(z => !z.imported).map(z => z.name);
                const res = await fetch(`/api/v1/domains/dns/import/${encodeURIComponent(providerId)}`, {
                    method: 'POST',
                    headers: this.workspaceHeaders(),
                    body: JSON.stringify({ domains }),
                });
                const data = await res.json().catch(() => ({}));
                if (!res.ok) {
                    this.dnsProviderImportError = this.providerErrorDetail(data, res.statusText);
                    this.showFlash(`${this.selectedDnsProviderName()} import failed: ` + this.dnsProviderImportError, false);
                } else {
                    await this.discoverDNSProviderZones(providerId);
                    this.showFlash(`${data.imported.length} domain${data.imported.length === 1 ? '' : 's'} imported.`, true);
                }
            } catch (err) {
                this.showFlash(`Error importing ${this.selectedDnsProviderName()} zones: ` + err.message, false);
            } finally {
                this.importingCfZones = false;
            }
        },

        async discoverMailServiceDomains() {
            this.loadingMailServiceDomains = true;
            try {
                await this.saveCategory('postmark');
                const res = await fetch('/api/v1/domains/mail-services/import/postmark/preview', {
                    headers: this.workspaceHeaders(),
                });
                const data = await res.json().catch(() => ({}));
                if (!res.ok) {
                    this.showFlash('Postmark discovery failed: ' + (data.detail || res.statusText), false);
                } else {
                    this.mailServiceDomains = data.domains || [];
                    this.showFlash(`${this.mailServiceDomains.length} sender domain${this.mailServiceDomains.length === 1 ? '' : 's'} found.`, true);
                }
            } catch (err) {
                this.showFlash('Error discovering sender domains: ' + err.message, false);
            } finally {
                this.loadingMailServiceDomains = false;
            }
        },

        async importMailServiceDomains() {
            this.importingMailServiceDomains = true;
            try {
                const domains = this.mailServiceDomains.filter(d => !d.imported).map(d => d.domain);
                const res = await fetch('/api/v1/domains/mail-services/import/postmark', {
                    method: 'POST',
                    headers: this.workspaceHeaders(),
                    body: JSON.stringify({ domains }),
                });
                const data = await res.json().catch(() => ({}));
                if (!res.ok) {
                    this.showFlash('Postmark import failed: ' + (data.detail || res.statusText), false);
                } else {
                    await this.discoverMailServiceDomains();
                    this.showFlash(`${data.imported.length} domain${data.imported.length === 1 ? '' : 's'} imported.`, true);
                }
            } catch (err) {
                this.showFlash('Error importing sender domains: ' + err.message, false);
            } finally {
                this.importingMailServiceDomains = false;
            }
        },

        async loadWebhooks(showMessage = true) {
            this.loadingWebhooks = true;
            try {
                const res = await fetch('/api/v1/webhooks', { headers: this.apiHeaders() });
                const data = await res.json().catch(() => ({}));
                if (!res.ok) {
                    if (showMessage) this.showFlash('Webhook load failed: ' + (data.detail || res.statusText), false);
                } else {
                    this.webhooks = data.endpoints || [];
                    this.webhookEventTypes = data.supported_event_types || [];
                    if (showMessage) this.showFlash('Webhooks refreshed.', true);
                }
            } catch (err) {
                if (showMessage) this.showFlash('Error loading webhooks: ' + err.message, false);
            } finally {
                this.loadingWebhooks = false;
            }
        },

        async createWebhook() {
            this.savingWebhook = true;
            try {
                const payload = {
                    name: this.newWebhook.name,
                    url: this.newWebhook.url,
                    event_types: [this.newWebhook.eventType || '*'],
                    max_attempts: Number(this.newWebhook.max_attempts || 5),
                    timeout_seconds: Number(this.newWebhook.timeout_seconds || 10),
                    enabled: true,
                };
                const res = await fetch('/api/v1/webhooks', {
                    method: 'POST',
                    headers: this.apiHeaders(),
                    body: JSON.stringify(payload),
                });
                const data = await res.json().catch(() => ({}));
                if (!res.ok) {
                    this.showFlash('Webhook create failed: ' + (data.detail || res.statusText), false);
                } else {
                    this.newWebhook = { name: '', url: '', eventType: '*', max_attempts: 5, timeout_seconds: 10 };
                    await this.loadWebhooks(false);
                    this.showFlash('Webhook created. Signing secret was generated and stored securely.', true);
                }
            } catch (err) {
                this.showFlash('Error creating webhook: ' + err.message, false);
            } finally {
                this.savingWebhook = false;
            }
        },

        async testWebhook(endpointId) {
            this.testingWebhookId = endpointId;
            try {
                const res = await fetch(`/api/v1/webhooks/${endpointId}/test`, {
                    method: 'POST',
                    headers: this.apiHeaders(),
                });
                const data = await res.json().catch(() => ({}));
                if (!res.ok) {
                    this.showFlash('Webhook test failed: ' + (data.detail || res.statusText), false);
                } else {
                    await this.loadWebhooks(false);
                    await this.loadWebhookDeliveries(false);
                    const status = data.delivery ? data.delivery.status : 'queued';
                    this.showFlash(`Webhook test ${status}.`, status === 'delivered');
                }
            } catch (err) {
                this.showFlash('Error testing webhook: ' + err.message, false);
            } finally {
                this.testingWebhookId = null;
            }
        },

        async disableWebhook(endpointId) {
            this.disablingWebhookId = endpointId;
            try {
                const res = await fetch(`/api/v1/webhooks/${endpointId}`, {
                    method: 'DELETE',
                    headers: this.apiHeaders(),
                });
                const data = await res.json().catch(() => ({}));
                if (!res.ok) {
                    this.showFlash('Webhook disable failed: ' + (data.detail || res.statusText), false);
                } else {
                    await this.loadWebhooks(false);
                    this.showFlash('Webhook disabled.', true);
                }
            } catch (err) {
                this.showFlash('Error disabling webhook: ' + err.message, false);
            } finally {
                this.disablingWebhookId = null;
            }
        },

        async loadWebhookDeliveries(showMessage = true) {
            this.loadingWebhookDeliveries = true;
            try {
                const res = await fetch('/api/v1/webhooks/deliveries?limit=10', {
                    headers: this.apiHeaders(),
                });
                const data = await res.json().catch(() => ({}));
                if (!res.ok) {
                    if (showMessage) this.showFlash('Delivery history failed: ' + (data.detail || res.statusText), false);
                } else {
                    this.webhookDeliveries = data.deliveries || [];
                    if (showMessage) this.showFlash('Webhook deliveries refreshed.', true);
                }
            } catch (err) {
                if (showMessage) this.showFlash('Error loading webhook deliveries: ' + err.message, false);
            } finally {
                this.loadingWebhookDeliveries = false;
            }
        },

        async processWebhooks() {
            this.processingWebhooks = true;
            try {
                const res = await fetch('/api/v1/webhooks/deliveries/process', {
                    method: 'POST',
                    headers: this.apiHeaders(),
                });
                const data = await res.json().catch(() => ({}));
                if (!res.ok) {
                    this.showFlash('Webhook processing failed: ' + (data.detail || res.statusText), false);
                } else {
                    await this.loadWebhooks(false);
                    await this.loadWebhookDeliveries(false);
                    this.showFlash(`${(data.deliveries || []).length} due webhook deliver${(data.deliveries || []).length === 1 ? 'y' : 'ies'} processed.`, true);
                }
            } catch (err) {
                this.showFlash('Error processing webhooks: ' + err.message, false);
            } finally {
                this.processingWebhooks = false;
            }
        },

        showFlash(msg, ok) {
            this.flashMsg = msg;
            this.flashOk = ok;
            if (this._flashTimer) clearTimeout(this._flashTimer);
            this._flashTimer = setTimeout(() => {
                this.flashMsg = '';
                this._flashTimer = null;
            }, 4000);
        },
    };
}
