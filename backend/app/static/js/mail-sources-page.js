function mailSourcesApp() {
    return {
        sources: [],
        showForm: false,
        editingId: null,
        deleteTarget: null,
        showPassword: false,
        isTesting: false,
        isSaving: false,
        testing: {},
        fetching: {},
        backfillJobs: {},
        backfillLoading: {},
        backfillAction: {},
        backfillSource: null,
        backfillDays: 30,
        historySource: null,
        importHistory: [],
        historyLoading: false,
        feedback: { message: '', type: '', diagnostic_summary: '', recovery_steps: [] },
        testResult: { message: '', success: false, diagnostic_summary: '', recovery_steps: [] },
        gmailConnected: false,
        gmailEmail: '',
        m365Connected: false,
        m365Email: '',
        m365Folders: [],
        m365FoldersLoading: false,
        m365FoldersError: '',

        form: {
            name: '',
            method: 'IMAP',
            server: '',
            port: 993,
            username: '',
            password: '',
            use_ssl: true,
            folder: 'INBOX',
            polling_interval: 60,
            enabled: true,
            gmail_client_id: '',
            gmail_client_secret: '',
            m365_tenant_id: 'common',
            m365_client_id: '',
            m365_client_secret: '',
            m365_mailbox: '',
            m365_folder_id: '',
        },

        async init() {
            this.bindPageControls();
            await this.loadSources();
        },

        bindPageControls() {
            if (this._pageControlsBound || !this.$root) {
                return;
            }
            this._pageControlsBound = true;
            this.$root.addEventListener('click', event => {
                const target = event.target instanceof Element ? event.target : null;
                const button = target ? target.closest('button') : null;
                if (!button || !this.$root.contains(button)) {
                    return;
                }
                const source = this.sourceById(button.dataset.sourceId);
                const latestJob = source ? this.latestBackfill(source) : null;
                if (button.matches('[data-mail-source-add]')) {
                    event.preventDefault();
                    this.openAddForm();
                } else if (button.matches('[data-mail-source-edit]') && source) {
                    event.preventDefault();
                    this.openEditForm(source);
                } else if (button.matches('[data-mail-source-test]') && source) {
                    event.preventDefault();
                    this.testSource(source.id);
                } else if (button.matches('[data-mail-source-fetch]') && source) {
                    event.preventDefault();
                    this.fetchSource(source);
                } else if (button.matches('[data-mail-source-backfill]') && source) {
                    event.preventDefault();
                    this.openBackfill(source);
                } else if (button.matches('[data-mail-source-history]') && source) {
                    event.preventDefault();
                    this.loadImportHistory(source);
                } else if (button.matches('[data-mail-source-delete]') && source) {
                    event.preventDefault();
                    this.confirmDelete(source);
                } else if (button.matches('[data-mail-source-history-close]')) {
                    event.preventDefault();
                    this.closeHistory();
                } else if (button.matches('[data-mail-source-backfill-refresh]') && source) {
                    event.preventDefault();
                    this.loadBackfills(source);
                } else if (button.matches('[data-mail-source-backfill-cancel]') && source && latestJob) {
                    event.preventDefault();
                    this.cancelBackfill(source, latestJob);
                } else if (button.matches('[data-mail-source-backfill-retry]') && source && latestJob) {
                    event.preventDefault();
                    this.retryBackfill(source, latestJob);
                } else if (button.matches('[data-mail-source-backfill-close]')) {
                    event.preventDefault();
                    this.closeBackfill();
                } else if (button.matches('[data-backfill-days]')) {
                    event.preventDefault();
                    this.backfillDays = Number(button.dataset.backfillDays);
                } else if (button.matches('[data-mail-source-backfill-run]')) {
                    event.preventDefault();
                    this.runBackfill();
                } else if (button.matches('[data-mail-source-form-close]')) {
                    event.preventDefault();
                    this.closeForm();
                } else if (button.matches('[data-mail-source-password-toggle]')) {
                    event.preventDefault();
                    this.showPassword = !this.showPassword;
                } else if (button.matches('[data-mail-source-m365-load-folders]')) {
                    event.preventDefault();
                    this.loadM365Folders();
                } else if (button.matches('[data-mail-source-test-adhoc]')) {
                    event.preventDefault();
                    this.testAdHoc();
                } else if (button.matches('[data-mail-source-connect-gmail]')) {
                    event.preventDefault();
                    this.connectGmail();
                } else if (button.matches('[data-mail-source-connect-m365]')) {
                    event.preventDefault();
                    this.connectM365();
                } else if (button.matches('[data-mail-source-delete-cancel]')) {
                    event.preventDefault();
                    this.deleteTarget = null;
                } else if (button.matches('[data-mail-source-delete-confirm]')) {
                    event.preventDefault();
                    this.deleteSource();
                }
            });
            this.$root.addEventListener('change', event => {
                const target = event.target instanceof Element ? event.target : null;
                if (!target) {
                    return;
                }
                if (target.matches('[data-mail-source-toggle]')) {
                    const source = this.sourceById(target.dataset.sourceId);
                    if (source) {
                        this.toggleSource(source.id);
                    }
                } else if (target.matches('[data-mail-source-m365-folder-select]')) {
                    this.applyM365FolderSelection(target.value);
                }
            });
            this.$root.addEventListener('input', event => {
                const target = event.target instanceof Element ? event.target : null;
                if (target && target.matches('[data-mail-source-m365-manual-folder]')) {
                    this.form.m365_folder_id = '';
                }
            });
            this.$root.addEventListener('submit', event => {
                const form = event.target instanceof Element ? event.target : null;
                if (form && form.matches('[data-mail-source-form]')) {
                    event.preventDefault();
                    this.saveSource();
                }
            });
            window.addEventListener('keydown', event => {
                if (event.key !== 'Escape') {
                    return;
                }
                if (this.deleteTarget && this.$root.querySelector('[data-mail-source-delete-modal]')) {
                    event.preventDefault();
                    this.deleteTarget = null;
                } else if (this.backfillSource && this.$root.querySelector('[data-mail-source-backfill-modal]')) {
                    event.preventDefault();
                    this.closeBackfill();
                } else if (this.showForm && this.$root.querySelector('[data-mail-source-form-modal]')) {
                    event.preventDefault();
                    this.closeForm();
                }
            });
        },

        sourceById(id) {
            if (!id) return null;
            const numericId = Number(id);
            return this.sources.find(source => Number(source.id) === numericId) || null;
        },

        async loadSources() {
            try {
                const resp = await fetch('/api/v1/mail-sources');
                if (resp.ok) {
                    this.sources = await resp.json();
                    await this.loadBackfillsForSources();
                }
            } catch (e) {
                console.error('Failed to load mail sources', e);
            }
        },

        async fetchSource(source, days = 7) {
            this.fetching[source.id] = true;
            this.feedback = this.emptyFeedback();
            try {
                const safeDays = Math.min(365, Math.max(1, Number(days) || 7));
                const resp = await fetch(`/api/v1/mail-sources/${source.id}/fetch?days=${safeDays}`, {
                    method: 'POST',
                });
                const result = await resp.json();
                if (!resp.ok) {
                    this.feedback = this.apiErrorFeedback(result, 'Import error', 'Import failed');
                    return;
                }
                this.feedback = {
                    message: `Import finished for ${source.name} (${safeDays} day${safeDays === 1 ? '' : 's'}): ${result.reports_found} report${result.reports_found === 1 ? '' : 's'}, ${result.duplicate_reports || 0} duplicate${result.duplicate_reports === 1 ? '' : 's'}.`,
                    type: result.success ? 'success' : 'error',
                };
                await this.loadSources();
                if (this.historySource && this.historySource.id === source.id) {
                    const updated = this.sources.find(s => s.id === source.id) || source;
                    await this.loadImportHistory(updated);
                }
                await this.loadBackfills(source, true);
            } catch (e) {
                this.feedback = { ...this.emptyFeedback(), message: `Import error: ${e.message}`, type: 'error' };
            } finally {
                this.fetching[source.id] = false;
            }
        },

        openBackfill(source) {
            this.backfillSource = source;
            this.backfillDays = 30;
            this.feedback = { message: '', type: '' };
        },

        closeBackfill() {
            this.backfillSource = null;
            this.backfillDays = 30;
        },

        validBackfillDays() {
            const days = Number(this.backfillDays);
            return Number.isInteger(days) && days >= 1 && days <= 365;
        },

        async runBackfill() {
            if (!this.backfillSource || !this.validBackfillDays()) return;
            const source = this.backfillSource;
            const days = Number(this.backfillDays);
            this.closeBackfill();
            await this.queueBackfill(source, days);
        },

        async loadBackfillsForSources() {
            await Promise.all(this.sources.map(source => this.loadBackfills(source, true)));
        },

        async loadBackfills(source, silent = false) {
            if (!source) return;
            this.backfillLoading = { ...this.backfillLoading, [source.id]: true };
            this.backfillAction = { ...this.backfillAction, [source.id]: 'refresh' };
            if (!silent) {
                this.feedback = this.emptyFeedback();
            }
            try {
                const resp = await fetch(`/api/v1/mail-sources/${source.id}/backfills?limit=5`);
                const data = await resp.json();
                if (!resp.ok) {
                    throw new Error(this.apiErrorMessage(data, 'Failed to load backfill jobs'));
                }
                this.backfillJobs = { ...this.backfillJobs, [source.id]: data };
            } catch (e) {
                if (!silent) {
                    this.feedback = { message: `Backfill status error: ${e.message}`, type: 'error' };
                }
            } finally {
                this.backfillLoading = { ...this.backfillLoading, [source.id]: false };
                this.backfillAction = { ...this.backfillAction, [source.id]: '' };
            }
        },

        async queueBackfill(source, days) {
            if (!source) return;
            const safeDays = Math.min(365, Math.max(1, Number(days) || 30));
            const requestedEnd = new Date();
            const requestedStart = new Date(requestedEnd.getTime() - safeDays * 24 * 60 * 60 * 1000);
            this.backfillAction = { ...this.backfillAction, [source.id]: 'queue' };
            this.feedback = this.emptyFeedback();
            try {
                const resp = await fetch(`/api/v1/mail-sources/${source.id}/backfills`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        requested_start: requestedStart.toISOString(),
                        requested_end: requestedEnd.toISOString(),
                        max_attempts: 3,
                    }),
                });
                const data = await resp.json();
                if (!resp.ok) {
                    this.feedback = this.apiErrorFeedback(data, 'Backfill error', 'Failed to queue backfill');
                    return;
                }
                this.feedback = {
                    message: `Backfill queued for ${source.name} (${safeDays} day${safeDays === 1 ? '' : 's'}).`,
                    type: 'success',
                };
                const existing = this.backfillJobs[source.id] || [];
                this.backfillJobs = { ...this.backfillJobs, [source.id]: [data, ...existing].slice(0, 5) };
                await this.loadBackfills(source, true);
            } catch (e) {
                this.feedback = { ...this.emptyFeedback(), message: `Backfill error: ${e.message}`, type: 'error' };
            } finally {
                this.backfillAction = { ...this.backfillAction, [source.id]: '' };
            }
        },

        async cancelBackfill(source, job) {
            if (!source || !job) return;
            this.backfillAction = { ...this.backfillAction, [source.id]: 'cancel' };
            this.feedback = this.emptyFeedback();
            try {
                const resp = await fetch(`/api/v1/mail-sources/${source.id}/backfills/${job.id}/cancel`, {
                    method: 'POST',
                });
                const data = await resp.json();
                if (!resp.ok) {
                    throw new Error(this.apiErrorMessage(data, 'Failed to cancel backfill'));
                }
                this.replaceBackfill(source, data);
                this.feedback = { message: `Backfill cancelled for ${source.name}.`, type: 'success' };
            } catch (e) {
                this.feedback = { message: `Cancel error: ${e.message}`, type: 'error' };
            } finally {
                this.backfillAction = { ...this.backfillAction, [source.id]: '' };
            }
        },

        async retryBackfill(source, job) {
            if (!source || !job) return;
            this.backfillAction = { ...this.backfillAction, [source.id]: 'retry' };
            this.feedback = this.emptyFeedback();
            try {
                const resp = await fetch(`/api/v1/mail-sources/${source.id}/backfills/${job.id}/retry`, {
                    method: 'POST',
                });
                const data = await resp.json();
                if (!resp.ok) {
                    throw new Error(this.apiErrorMessage(data, 'Failed to retry backfill'));
                }
                this.replaceBackfill(source, data);
                this.feedback = { message: `Backfill retried for ${source.name}.`, type: 'success' };
            } catch (e) {
                this.feedback = { message: `Retry error: ${e.message}`, type: 'error' };
            } finally {
                this.backfillAction = { ...this.backfillAction, [source.id]: '' };
            }
        },

        replaceBackfill(source, updated) {
            const rows = this.backfillJobs[source.id] || [];
            const nextRows = rows.map(row => row.id === updated.id ? updated : row);
            if (!nextRows.some(row => row.id === updated.id)) {
                nextRows.unshift(updated);
            }
            this.backfillJobs = { ...this.backfillJobs, [source.id]: nextRows.slice(0, 5) };
        },

        async loadImportHistory(source) {
            this.historySource = source;
            this.importHistory = [];
            this.historyLoading = true;
            this.feedback = { message: '', type: '' };
            try {
                const resp = await fetch(`/api/v1/mail-sources/${source.id}/imports?limit=20`);
                if (!resp.ok) {
                    const err = await resp.json();
                    throw new Error(err.detail || 'Failed to load import history');
                }
                this.importHistory = await resp.json();
            } catch (e) {
                this.feedback = { message: `Error: ${e.message}`, type: 'error' };
            } finally {
                this.historyLoading = false;
            }
        },

        closeHistory() {
            this.historySource = null;
            this.importHistory = [];
            this.historyLoading = false;
        },

        formatDate(value) {
            return value ? new Date(value).toLocaleString() : '—';
        },

        sourceAccountLabel(source) {
            if (source.method === 'GMAIL_API') {
                return source.gmail_email || '—';
            }
            if (source.method === 'M365_GRAPH') {
                return source.m365_mailbox || source.m365_email || 'authorized account';
            }
            return source.server ? `${source.server}:${source.port}` : '—';
        },

        sourceTargetLabel(source) {
            if (!source) return '—';
            if (source.method === 'M365_GRAPH') {
                const mailbox = source.m365_mailbox || source.m365_email || 'authorized account';
                return `${mailbox} / ${source.folder || 'INBOX'}`;
            }
            return this.sourceAccountLabel(source);
        },

        sourceStatusLabel(source) {
            if (source.method === 'GMAIL_API') {
                return source.gmail_connected ? 'Connected' : 'Not authorised';
            }
            if (source.method === 'M365_GRAPH') {
                return source.m365_connected ? 'Connected' : 'Not authorised';
            }
            return source.username || '—';
        },

        formatList(value) {
            return value && value.length ? value.join(', ') : '—';
        },

        apiErrorMessage(data, fallback) {
            const detail = data && data.detail;
            if (!detail) return fallback;
            if (typeof detail === 'string') return detail;
            if (Array.isArray(detail)) {
                return detail.map(item => item.msg || item.detail || JSON.stringify(item)).join('; ');
            }
            return detail.message || JSON.stringify(detail);
        },

        apiErrorFeedback(data, prefix, fallback) {
            const detail = data && data.detail;
            const message = this.apiErrorMessage(data, fallback);
            if (!detail || typeof detail === 'string' || Array.isArray(detail)) {
                return { ...this.emptyFeedback(), message: `${prefix}: ${message}`, type: 'error' };
            }
            return {
                ...this.emptyFeedback(),
                message: `${prefix}: ${message}`,
                type: 'error',
                diagnostic_summary: detail.summary || detail.diagnostic_summary || '',
                recovery_steps: detail.next_steps || detail.recovery_steps || [],
                links: detail.links || [],
            };
        },

        latestBackfill(source) {
            const rows = source ? this.backfillJobs[source.id] || [] : [];
            return rows.length ? rows[0] : null;
        },

        backfillStatusLabel(status) {
            const labels = {
                queued: 'Queued',
                running: 'Running',
                backoff: 'Backoff',
                failed: 'Failed',
                cancelled: 'Cancelled',
                completed: 'Completed',
            };
            return labels[status] || status || 'Unknown';
        },

        backfillBadgeClass(status) {
            if (status === 'completed') return 'badge-success';
            if (status === 'running') return 'badge-info';
            if (status === 'queued') return 'badge-outline';
            if (status === 'backoff') return 'badge-warning';
            if (status === 'failed') return 'badge-error';
            if (status === 'cancelled') return 'badge-neutral';
            return 'badge-outline';
        },

        backfillProgress(job) {
            if (!job) return 0;
            if (Number.isFinite(Number(job.progress_percent))) {
                return Math.max(0, Math.min(100, Number(job.progress_percent)));
            }
            const processed = Number(job.processed || 0);
            if (job.status === 'completed') return 100;
            if (job.status === 'queued') return 5;
            if (job.status === 'running') return Math.min(95, Math.max(20, 20 + processed / 2));
            if (job.status === 'backoff') return Math.min(80, Math.max(25, 25 + processed / 2));
            return Math.min(100, Math.max(10, processed || 10));
        },

        backfillWindowLabel(job) {
            if (job && job.requested_window_days) return `${job.requested_window_days} days`;
            if (!job || !job.requested_start || !job.requested_end) return 'Default search window';
            const start = new Date(job.requested_start).toLocaleDateString();
            const end = new Date(job.requested_end).toLocaleDateString();
            return `${start} – ${end}`;
        },

        canCancelBackfill(job) {
            if (job && typeof job.can_cancel === 'boolean') return job.can_cancel;
            return Boolean(job && ['queued', 'running', 'backoff'].includes(job.status));
        },

        canRetryBackfill(job) {
            if (job && typeof job.can_retry === 'boolean') return job.can_retry;
            return Boolean(job && ['failed', 'cancelled', 'backoff'].includes(job.status));
        },

        formatDetailsSummary(details) {
            const counts = details.reduce((acc, detail) => {
                const key = detail.status || 'unknown';
                acc[key] = (acc[key] || 0) + 1;
                return acc;
            }, {});
            return Object.entries(counts)
                .map(([key, count]) => `${count} ${key}`)
                .join(', ');
        },

        statusBadgeClass(status) {
            if (status === 'success') return 'badge-success';
            if (status === 'warning') return 'badge-warning';
            if (status === 'failed') return 'badge-error';
            return 'badge-outline';
        },

        detailBadgeClass(status) {
            if (status === 'imported') return 'badge-success';
            if (status === 'duplicate' || status === 'skipped') return 'badge-warning';
            if (status === 'error') return 'badge-error';
            return 'badge-outline';
        },

        emptyTestResult() {
            return { message: '', success: false, diagnostic_summary: '', recovery_steps: [] };
        },

        emptyFeedback() {
            return { message: '', type: '', diagnostic_summary: '', recovery_steps: [], links: [] };
        },

        diagnosticFromResult(result) {
            const diagnostic = result.diagnostic || {};
            return {
                diagnostic_summary: diagnostic.summary || '',
                recovery_steps: result.recovery_steps || diagnostic.recovery_steps || [],
            };
        },

        openAddForm() {
            this.editingId = null;
            this.gmailConnected = false;
            this.gmailEmail = '';
            this.m365Connected = false;
            this.m365Email = '';
            this.m365Folders = [];
            this.m365FoldersError = '';
            this.form = {
                name: '',
                method: 'IMAP',
                server: '',
                port: 993,
                username: '',
                password: '',
                use_ssl: true,
                folder: 'INBOX',
                polling_interval: 60,
                enabled: true,
                gmail_client_id: '',
                gmail_client_secret: '',
                m365_tenant_id: 'common',
                m365_client_id: '',
                m365_client_secret: '',
                m365_mailbox: '',
                m365_folder_id: '',
            };
            this.testResult = this.emptyTestResult();
            this.showForm = true;
        },

        openEditForm(source) {
            this.editingId = source.id;
            this.gmailConnected = source.gmail_connected || false;
            this.gmailEmail = source.gmail_email || '';
            this.m365Connected = source.m365_connected || false;
            this.m365Email = source.m365_email || '';
            this.m365Folders = [];
            this.m365FoldersError = '';
            this.form = {
                name: source.name,
                method: source.method,
                server: source.server || '',
                port: source.port || 993,
                username: source.username || '',
                password: '',   // never pre-fill password
                use_ssl: source.use_ssl !== false,
                folder: source.folder || 'INBOX',
                polling_interval: source.polling_interval || 60,
                enabled: source.enabled !== false,
                gmail_client_id: source.gmail_client_id || '',
                gmail_client_secret: '',  // never pre-fill client secret
                m365_tenant_id: source.m365_tenant_id || 'common',
                m365_client_id: source.m365_client_id || '',
                m365_client_secret: '',  // never pre-fill client secret
                m365_mailbox: source.m365_mailbox || '',
                m365_folder_id: source.m365_folder_id || '',
            };
            this.testResult = this.emptyTestResult();
            this.showForm = true;
        },

        closeForm() {
            this.showForm = false;
            this.editingId = null;
            this.m365Folders = [];
            this.m365FoldersError = '';
            this.testResult = this.emptyTestResult();
        },

        async connectGmail() {
            if (!this.editingId) return;
            try {
                const resp = await fetch(
                    `/api/v1/mail-sources/${this.editingId}/gmail/authorize-url`
                );
                if (!resp.ok) {
                    const err = await resp.json();
                    this.feedback = { message: `Error: ${err.detail || 'Failed to get authorization URL'}`, type: 'error' };
                    return;
                }
                const data = await resp.json();
                // Open the OAuth2 URL in a new popup window
                const popup = window.open(
                    data.authorization_url,
                    'gmail_oauth',
                    'width=600,height=700,scrollbars=yes'
                );
                // Poll for popup close and refresh source list
                const pollInterval = setInterval(async () => {
                    if (popup && popup.closed) {
                        clearInterval(pollInterval);
                        await this.loadSources();
                        // Refresh the editing form state
                        const updated = this.sources.find(s => s.id === this.editingId);
                        if (updated) {
                            this.gmailConnected = updated.gmail_connected || false;
                            this.gmailEmail = updated.gmail_email || '';
                            if (this.gmailConnected) {
                                this.feedback = {
                                    message: `Gmail connected successfully (${this.gmailEmail}).`,
                                    type: 'success',
                                };
                            }
                        }
                    }
                }, 1000);
            } catch (e) {
                this.feedback = { message: `Error: ${e.message}`, type: 'error' };
            }
        },

        async connectM365() {
            if (!this.editingId) return;
            try {
                const resp = await fetch(
                    `/api/v1/mail-sources/${this.editingId}/m365/authorize-url`
                );
                if (!resp.ok) {
                    const err = await resp.json();
                    this.feedback = { message: `Error: ${err.detail || 'Failed to get authorization URL'}`, type: 'error' };
                    return;
                }
                const data = await resp.json();
                const popup = window.open(
                    data.authorization_url,
                    'm365_oauth',
                    'width=700,height=760,scrollbars=yes'
                );
                const pollInterval = setInterval(async () => {
                    if (popup && popup.closed) {
                        clearInterval(pollInterval);
                        await this.loadSources();
                        const updated = this.sources.find(s => s.id === this.editingId);
                        if (updated) {
                            this.m365Connected = updated.m365_connected || false;
                            this.m365Email = updated.m365_email || '';
                            this.form.m365_folder_id = updated.m365_folder_id || this.form.m365_folder_id || '';
                            if (this.m365Connected) {
                                this.feedback = {
                                    message: `Microsoft 365 connected successfully (${this.m365Email || 'account connected'}).`,
                                    type: 'success',
                                };
                            }
                        }
                    }
                }, 1000);
            } catch (e) {
                this.feedback = { message: `Error: ${e.message}`, type: 'error' };
            }
        },

        applyM365FolderSelection(folderId) {
            if (!folderId) return;
            const selected = this.m365Folders.find(folder => folder.id === folderId);
            if (selected) {
                this.form.folder = selected.display_name || 'INBOX';
            }
        },

        async loadM365Folders() {
            if (!this.editingId) return;
            this.m365FoldersLoading = true;
            this.m365FoldersError = '';
            try {
                const resp = await fetch(`/api/v1/mail-sources/${this.editingId}/m365/folders`);
                const data = await resp.json();
                if (!resp.ok) {
                    throw new Error(data.detail || 'Could not load Microsoft 365 folders');
                }
                this.m365Folders = data.folders || [];
                if (this.m365Folders.length === 0) {
                    this.m365FoldersError = 'No selectable folders were returned for this mailbox.';
                }
            } catch (e) {
                this.m365FoldersError = e.message;
            } finally {
                this.m365FoldersLoading = false;
            }
        },

        async saveSource() {
            this.isSaving = true;
            this.feedback = { message: '', type: '' };
            try {
                const payload = { ...this.form };
                // Don't send empty password on edit
                if (this.editingId && !payload.password) {
                    delete payload.password;
                }
                // Don't send empty gmail_client_secret on edit
                if (this.editingId && !payload.gmail_client_secret) {
                    delete payload.gmail_client_secret;
                }
                // Don't send empty m365_client_secret on edit
                if (this.editingId && !payload.m365_client_secret) {
                    delete payload.m365_client_secret;
                }

                const url = this.editingId
                    ? `/api/v1/mail-sources/${this.editingId}`
                    : '/api/v1/mail-sources';
                const method = this.editingId ? 'PUT' : 'POST';

                const resp = await fetch(url, {
                    method,
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload),
                });
                if (!resp.ok) {
                    const err = await resp.json();
                    throw new Error(err.detail || 'Save failed');
                }
                this.feedback = {
                    message: this.editingId
                        ? 'Mail source updated successfully.'
                        : 'Mail source created successfully.',
                    type: 'success',
                };
                await this.loadSources();
                this.closeForm();
            } catch (e) {
                this.feedback = { message: `Error: ${e.message}`, type: 'error' };
            } finally {
                this.isSaving = false;
            }
        },

        async toggleSource(id) {
            try {
                const resp = await fetch(`/api/v1/mail-sources/${id}/toggle`, { method: 'POST' });
                if (!resp.ok) throw new Error('Toggle failed');
                await this.loadSources();
            } catch (e) {
                this.feedback = { message: `Error toggling source: ${e.message}`, type: 'error' };
            }
        },

        confirmDelete(source) {
            this.deleteTarget = source;
        },

        async deleteSource() {
            if (!this.deleteTarget) return;
            try {
                const resp = await fetch(`/api/v1/mail-sources/${this.deleteTarget.id}`, {
                    method: 'DELETE',
                });
                if (!resp.ok && resp.status !== 204) throw new Error('Delete failed');
                this.feedback = {
                    message: `Mail source "${this.deleteTarget.name}" deleted.`,
                    type: 'success',
                };
                this.deleteTarget = null;
                await this.loadSources();
            } catch (e) {
                this.feedback = { message: `Error: ${e.message}`, type: 'error' };
                this.deleteTarget = null;
            }
        },

        async testSource(id) {
            this.testing[id] = true;
            this.feedback = this.emptyFeedback();
            try {
                const resp = await fetch(`/api/v1/mail-sources/${id}/test`, { method: 'POST' });
                const result = await resp.json();
                const diagnostic = this.diagnosticFromResult(result);
                if (result.success) {
                    this.feedback = {
                        message: `Connection test successful for source #${id}: ${result.message}`,
                        type: 'success',
                        ...diagnostic,
                    };
                    await this.loadSources();
                } else {
                    this.feedback = {
                        message: `Connection test failed for source #${id}: ${result.message}`,
                        type: 'error',
                        ...diagnostic,
                    };
                }
            } catch (e) {
                this.feedback = { message: `Test error: ${e.message}`, type: 'error' };
            } finally {
                this.testing[id] = false;
            }
        },

        async testAdHoc() {
            this.isTesting = true;
            this.testResult = this.emptyTestResult();
            try {
                const payload = {
                    server: this.form.server,
                    port: this.form.port,
                    username: this.form.username,
                    password: this.form.password,
                    ssl: this.form.use_ssl,
                    method: this.form.method,
                };
                const resp = await fetch('/api/v1/mail-sources/test-connection', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload),
                });
                const result = await resp.json();
                const diagnostic = this.diagnosticFromResult(result);
                this.testResult = {
                    success: result.success,
                    message: result.success
                        ? `✓ Connected. ${result.message_count || 0} messages, ${result.dmarc_count || 0} potential DMARC reports.`
                        : `✗ ${result.message}`,
                    ...diagnostic,
                };
            } catch (e) {
                this.testResult = { success: false, message: `Error: ${e.message}` };
            } finally {
                this.isTesting = false;
            }
        },
    };
}

if (typeof document !== 'undefined') {
    document.addEventListener('alpine:init', () => {
        Alpine.data('mailSourcesApp', mailSourcesApp);
    });
}
