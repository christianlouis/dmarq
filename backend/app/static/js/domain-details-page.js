function domainDetailsApp(domainId) {
    return {
        domainId: domainId,
        stats: {
            complianceRate: '-',
            totalEmails: '-',
            failedEmails: '-',
            reportCount: '-'
        },
        dns: {
            dmarc: false,
            dmarcRecord: '',
            spf: false,
            spfRecord: '',
            dkim: false,
            dkimSelectors: [],
            nameservers: [],
            dnsProvider: null,
            providerContext: null,
            lookupStatus: 'ok',
            lookupError: ''
        },
        dnsRecordsLoading: true,
        dnsRecordsError: '',
        dnsHealth: {
            status: '',
            checks: [],
            recommendations: []
        },
        dnsGuidance: {
            status: '',
            findings: [],
            target_records: [],
            dns_provider: null,
            change_plans: [],
            recommended_provider: null,
            available_write_providers: [],
            safety_notes: []
        },
        dnsProviders: [
            { id: 'cloudflare', name: 'Cloudflare' }
        ],
        dnsWrite: {
            provider: 'cloudflare',
            allowProviderMismatch: false,
            loading: false,
            message: '',
            error: '',
            preview: null
        },
        posture: {
            status: '',
            score: 0,
            health: {
                grade: '',
                score: 0,
                status: '',
                factors: {},
                actions: []
            },
            summary: '',
            coverage: [],
            recommendations: [],
            changes: [],
            playbooks: []
        },
        remediationQueue: {
            status: '',
            summary: {
                total: 0,
                approval_ready: 0,
                manual_action: 0,
                investigate: 0,
                informational: 0,
                dispatch_ready: 0,
                dispatch_blocked: 0,
                dispatch_disabled: 0,
                dispatch_awaiting_acknowledgement: 0,
                dispatch_webhook_routes: 0
            },
            items: []
        },
        remediationAction: {
            itemId: '',
            action: '',
            loading: false,
            message: '',
            error: ''
        },
        mtaSts: {
            status: '',
            dns_record: '',
            mode: '',
            max_age: null,
            mx: [],
            errors: [],
            warnings: []
        },
        bimi: {
            status: '',
            selector: 'default',
            query_name: '',
            dns_record: '',
            logo_url: '',
            certificate_url: '',
            errors: [],
            warnings: []
        },
        selectors: [],
        reportSelectors: [],
        newSelector: '',
        selectorError: '',
        reports: [],
        reportsLoading: true,
        reportsError: '',
        sources: [],
        sourcesLoading: false,
        sourcesError: '',
        sourceIntelligence: {
            regions: [],
            anomalies: [],
            summary: {},
            loading: true,
            error: ''
        },
        ownership: {
            loading: false,
            error: '',
            message: '',
            verified: false,
            proof_record_name: '',
            proof_record_value: '',
            proof_reason: '',
            next_steps: []
        },
        complianceChart: null,
        healthScoreChart: null,
        healthHistory: {
            loading: true,
            error: '',
            points: [],
            current_score: null,
            previous_score: null,
            score_delta: null,
            current_grade: '',
            previous_grade: '',
            top_drivers: []
        },
        migration: {
            loading: true,
            error: '',
            status: '',
            readiness_score: 0,
            summary: '',
            parallel_reporting_days: 0,
            report_count: 0,
            source_count: 0,
            checklist: [],
            export_links: [],
            supported_sources: [],
            docs_url: 'https://github.com/christianlouis/dmarq/blob/main/docs/user_guide/migration.md'
        },
        migrationParity: {
            loading: true,
            error: '',
            status: '',
            summary: '',
            baseline_required: true,
            tolerance_percent: 10,
            metrics: [],
            next_steps: []
        },
        migrationBaseline: {
            report_count: '',
            total_emails: '',
            source_count: '',
            compliance_rate: '',
            policy: ''
        },
        migrationImport: {
            content: '',
            format: 'auto',
            source_platform: '',
            max_rows: 50,
            loading: false,
            error: '',
            preview: null
        },
        migrationToolsEnabled: false,
        migrationToolsLoaded: false,
        filters: {
            dateRange: '30',
            sourceFilter: '',
            exportStartDate: '',
            exportEndDate: ''
        },
        volumeScale: 'logarithmic',
        hasObservedVolume: false,
        lastComplianceTimeline: [],
        refreshingPage: false,

        init() {
            const storedVolumeScale = this.loadStoredVolumeScale();
            if (storedVolumeScale === 'linear' || storedVolumeScale === 'logarithmic') {
                this.volumeScale = storedVolumeScale;
            }

            this.loadInitialData();

            this.$watch('filters.dateRange', () => {
                this.fetchSources();
                this.fetchSourceIntelligence();
            });
        },

        async loadInitialData() {
            await Promise.allSettled([
                this.fetchDomainStats(),
                this.fetchReports()
            ]);

            Promise.allSettled([
                this.fetchSources(),
                this.fetchSourceIntelligence()
            ]);

            window.setTimeout(() => {
                Promise.allSettled([
                    this.fetchDomainOwnership(),
                    this.fetchDNSRecords(),
                    this.fetchDNSHealth(),
                    this.fetchDNSGuidance(),
                    this.fetchDNSProviders(),
                    this.fetchSelectors()
                ]);
            }, 250);

            window.setTimeout(() => {
                Promise.allSettled([
                    this.fetchPosture(),
                    this.fetchRemediationQueue(),
                    this.fetchHealthHistory(),
                    this.fetchMtaSts(),
                    this.fetchBimi()
                ]);
            }, 750);
        },

        async fetchWithTimeout(url, options = {}, timeoutMs = 12000) {
            const controller = new AbortController();
            const timeout = window.setTimeout(() => controller.abort(), timeoutMs);
            try {
                return await fetch(url, {
                    ...options,
                    signal: controller.signal
                });
            } catch (error) {
                if (error?.name === 'AbortError') {
                    throw new Error('The request timed out. Reload data or try again in a moment.');
                }
                throw error;
            } finally {
                window.clearTimeout(timeout);
            }
        },

        async reloadPageData() {
            this.refreshingPage = true;
            try {
                await Promise.all([
                    this.fetchDomainStats(),
                    this.fetchDNSRecords({ refresh: true }),
                    this.fetchDNSHealth({ refresh: true }),
                    this.fetchDNSGuidance({ refresh: true }),
                    this.fetchPosture({ refresh: true }),
                    this.fetchRemediationQueue(),
                    this.fetchHealthHistory(),
                    this.fetchMtaSts({ refresh: true }),
                    this.fetchBimi({ refresh: true }),
                    this.fetchSelectors(),
                    this.fetchReports(),
                    this.fetchSources({ refresh: true }),
                    this.fetchSourceIntelligence()
                ]);
            } finally {
                this.refreshingPage = false;
            }
        },

        loadStoredVolumeScale() {
            try {
                return window.localStorage?.getItem('dmarq:domain-volume-scale') || null;
            } catch (error) {
                return null;
            }
        },

        persistVolumeScale(scale) {
            try {
                window.localStorage?.setItem('dmarq:domain-volume-scale', scale);
            } catch (error) {
                // Private browsing and locked-down environments may reject local storage.
            }
        },

        effectiveVolumeScale() {
            return this.hasObservedVolume && this.volumeScale === 'logarithmic' ? 'logarithmic' : 'linear';
        },

        get sourceEvidenceCount() {
            const summary = this.sourceIntelligence.summary || {};
            const regionSources = (this.sourceIntelligence.regions || []).reduce(
                (total, region) => total + Number(region.source_count || 0),
                0
            );
            if (summary.sources !== null && summary.sources !== undefined) {
                return Number(summary.sources);
            }
            return Number(regionSources || this.sources.length || 0);
        },

        get filteredSources() {
            if (!this.sources) return [];

            return this.sources.filter(source => {
                if (!this.filters.sourceFilter) return true;
                const needle = this.filters.sourceFilter.toLowerCase();
                return [
                    source.ip,
                    source.hostname,
                    source.sender?.name,
                    source.sender?.provider,
                    source.sender?.status,
                    source.geo?.country,
                    source.geo?.country_code,
                    source.geo?.region,
                    source.geo?.asn,
                    source.geo?.network,
                    source.geo?.bgp_prefix,
                    source.geo?.registry,
                    source.geo?.allocated,
                    source.geo?.network_source,
                    source.first_seen ? this.sourceSeenLabel(source.first_seen) : '',
                    source.last_seen ? this.sourceSeenLabel(source.last_seen) : '',
                    source.reputation?.status,
                    source.reputation?.summary,
                    ...(source.reputation?.listings || []),
                ].some(value => String(value || '').toLowerCase().includes(needle));
            });
        },

        get exportReportsUrl() {
            const params = new URLSearchParams();
            if (this.filters.exportStartDate) params.set('start_date', this.filters.exportStartDate);
            if (this.filters.exportEndDate) params.set('end_date', this.filters.exportEndDate);
            const query = params.toString();
            const baseUrl = `/api/v1/domains/${encodeURIComponent(this.domainId)}/reports/export`;
            return query ? `${baseUrl}?${query}` : baseUrl;
        },

        get remediationReadinessText() {
            const summary = this.remediationQueue.summary || {};
            const ready = summary.dispatch_ready || 0;
            const blocked = summary.dispatch_blocked || 0;
            if (ready > 0) {
                return `${ready} remediation notification${ready === 1 ? '' : 's'} can be dispatched after review.`;
            }
            if (blocked > 0) {
                return `${blocked} remediation notification${blocked === 1 ? '' : 's'} ${blocked === 1 ? 'needs' : 'need'} settings, acknowledgement, or routing first.`;
            }
            return 'No remediation notifications need operator dispatch.';
        },

        get healthEvidenceExportUrl() {
            return `/api/v1/domains/${encodeURIComponent(this.domainId)}/posture/evidence/export?capture_current=false`;
        },

        get latestHealthPoint() {
            if (!this.healthHistory.points || !this.healthHistory.points.length) return {};
            return this.healthHistory.points[this.healthHistory.points.length - 1] || {};
        },

        get latestHealthPointLabel() {
            if (!this.latestHealthPoint.date) return 'No snapshot';
            return this.formatShortDate(this.latestHealthPoint.date);
        },

        get healthScoreDeltaClass() {
            if (this.healthHistory.score_delta > 0) return 'bg-green-100 text-green-700';
            if (this.healthHistory.score_delta < 0) return 'bg-red-100 text-red-700';
            return 'bg-white text-[#272a5f]';
        },

        get dkimLiveText() {
            if (this.dnsRecordsLoading) return 'Checking DKIM selectors...';
            if (this.dnsLookupFailed) return this.dnsLookupFailureText;
            if (!this.dns.dkim) return 'No DKIM record found for configured selectors';
            if (this.dns.dkimSelectors && this.dns.dkimSelectors.length > 0) {
                return 'selectors: ' + this.dns.dkimSelectors.join(', ');
            }
            return 'Verified';
        },

        get dnsLookupFailed() {
            return this.dns.lookupStatus === 'failed';
        },

        get dnsLookupStaleCache() {
            return this.dns.lookupStatus === 'stale_cache';
        },

        get dnsLookupFallback() {
            return this.dns.lookupStatus === 'fallback';
        },

        get dnsLookupPartial() {
            return this.dns.lookupStatus === 'partial';
        },

        get dnsLookupNoticeVisible() {
            return this.dnsLookupFailed || this.dnsLookupStaleCache || this.dnsLookupFallback || this.dnsLookupPartial;
        },

        get dnsLookupNoticeClass() {
            if (this.dnsLookupFailed) return 'border-red-200 bg-red-50 text-red-800';
            return 'border-yellow-200 bg-yellow-50 text-yellow-800';
        },

        get dnsLookupNoticeText() {
            if (this.dnsLookupFailed) return this.dnsLookupFailureText;
            if (this.dnsLookupStaleCache) return this.dns.lookupError || 'Using last known DNS evidence because live DNS refresh returned no usable result.';
            if (this.dnsLookupFallback) return this.dns.lookupError || 'DNS evidence was found through a fallback resolver.';
            if (this.dnsLookupPartial) return this.dns.lookupError || 'DNS fallback completed with partial resolver errors.';
            return '';
        },

        get dnsLookupFailureText() {
            return this.dns.lookupError || 'DNS lookup failed; cached or report evidence may be incomplete.';
        },

        dnsRecordText(record, missingText, checkingText) {
            if (this.dnsRecordsLoading) return checkingText;
            if (this.dnsLookupFailed) return this.dnsLookupFailureText;
            return record || missingText;
        },

        get detectedDnsProvider() {
            return this.dnsGuidance.dns_provider || this.dns.dnsProvider || null;
        },

        get providerContext() {
            return this.dns.providerContext || null;
        },

        get dnsProviderName() {
            if (this.dnsRecordsLoading) return 'Checking DNS provider...';
            if (this.dnsLookupFailed) return 'DNS lookup failed';
            return this.detectedDnsProvider?.provider_name || 'Unknown provider';
        },

        get dnsProviderConfidence() {
            if (this.dnsRecordsLoading) return 'checking';
            if (this.dnsLookupFailed) return 'unavailable';
            return this.detectedDnsProvider?.confidence || 'unknown';
        },

        get dnsProviderAction() {
            if (this.dnsRecordsLoading) return 'Looking up authoritative nameservers and authentication records.';
            if (this.dnsRecordsError) return this.dnsRecordsError;
            if (this.dnsLookupFailed) return this.dnsLookupFailureText;
            return this.detectedDnsProvider?.suggested_action || 'Review nameservers and select the DNS provider manually before making changes.';
        },

        get dnsProviderConfidenceClass() {
            const confidence = this.dnsProviderConfidence;
            if (confidence === 'high') return 'bg-green-100 text-green-700';
            if (confidence === 'medium') return 'bg-yellow-100 text-yellow-800';
            if (confidence === 'low') return 'bg-red-100 text-red-700';
            return 'bg-base-200 text-base-content/70';
        },

        get dnsNameserverText() {
            if (this.dnsRecordsLoading) return 'Checking nameservers...';
            if (this.dnsLookupFailed) return this.dnsLookupFailureText;
            const nameservers = this.dns.nameservers || this.detectedDnsProvider?.evidence || [];
            return nameservers.length ? nameservers.join(', ') : 'No NS evidence available yet';
        },

        get providerContextStatusLabel() {
            if (this.dnsRecordsLoading) return 'checking';
            return {
                connected: 'connected',
                read_only: 'read-only',
                connect: 'connect provider',
                manual: 'manual'
            }[this.providerContext?.status] || 'manual';
        },

        get providerContextBadgeClass() {
            if (this.dnsRecordsLoading) return 'bg-base-200 text-base-content/70';
            return {
                connected: 'bg-green-100 text-green-700',
                read_only: 'bg-blue-100 text-blue-700',
                connect: 'bg-yellow-100 text-yellow-800',
                manual: 'bg-base-200 text-base-content/70'
            }[this.providerContext?.status] || 'bg-base-200 text-base-content/70';
        },

        get providerContextSummary() {
            if (this.dnsRecordsLoading) return 'Checking provider connection and safe DNS repair options.';
            return this.providerContext?.summary || this.dnsProviderAction;
        },

        get providerContextSteps() {
            if (this.dnsRecordsLoading) return ['Wait for DNS checks to complete.'];
            const steps = this.providerContext?.next_steps || [];
            return steps.length ? steps : ['Review the DNS lint findings and apply changes manually.'];
        },

        get providerContextCtaLabel() {
            if (this.dnsRecordsLoading) return 'Checking...';
            return this.providerContext?.cta_label || 'Review DNS guidance';
        },

        get providerContextCtaHref() {
            return this.providerContext?.cta_href || '#dns-guidance';
        },

        syncDetectedDnsProvider() {
            const providerId = this.dnsGuidance.recommended_provider || this.detectedDnsProvider?.provider_id;
            if (!providerId) return;
            if (this.dnsProviders.some(provider => provider.id === providerId)) {
                this.dnsWrite.provider = providerId;
                this.dnsWrite.allowProviderMismatch = false;
            }
        },

        providerName(providerId) {
            const provider = this.dnsProviders.find(item => item.id === providerId);
            return provider ? provider.name : providerId;
        },

        canonicalProviderId(providerId) {
            const normalized = String(providerId || '').trim().toLowerCase().replace(/_/g, '-');
            return { 'azure-dns': 'azure' }[normalized] || normalized;
        },

        get detectedDnsProviderId() {
            const detectedProvider = this.canonicalProviderId(this.detectedDnsProvider?.provider_id);
            return ['custom', 'unknown', ''].includes(detectedProvider) ? null : detectedProvider;
        },

        get dnsProviderMatchTarget() {
            return this.canonicalProviderId(this.dnsGuidance.recommended_provider) || this.detectedDnsProviderId;
        },

        get dnsProviderMismatch() {
            const targetProvider = this.dnsProviderMatchTarget;
            return Boolean(
                targetProvider &&
                this.dnsWrite.provider &&
                this.canonicalProviderId(this.dnsWrite.provider) !== targetProvider
            );
        },

        get dnsHealthStatusClass() {
            if (this.dnsHealth.status === 'healthy') return 'bg-green-100 text-green-700';
            if (this.dnsHealth.status === 'degraded') return 'bg-yellow-100 text-yellow-800';
            if (this.dnsHealth.status === 'critical') return 'bg-red-100 text-red-700';
            return 'bg-base-200 text-base-content/70';
        },

        get postureStatusClass() {
            if (this.posture.status === 'healthy') return 'bg-green-100 text-green-700';
            if (this.posture.status === 'degraded') return 'bg-yellow-100 text-yellow-800';
            if (this.posture.status === 'critical') return 'bg-red-100 text-red-700';
            return 'bg-base-200 text-base-content/70';
        },

        get dnsGuidanceStatusClass() {
            if (this.dnsGuidance.status === 'ready') return 'bg-green-100 text-green-700';
            if (this.dnsGuidance.status === 'attention') return 'bg-yellow-100 text-yellow-800';
            if (this.dnsGuidance.status === 'critical') return 'bg-red-100 text-red-700';
            return 'bg-base-200 text-base-content/70';
        },

        get migrationStatusClass() {
            if (this.migration.error) return 'bg-red-100 text-red-700';
            if (this.migration.status === 'ready') return 'bg-green-100 text-green-700';
            if (this.migration.status === 'in_progress') return 'bg-yellow-100 text-yellow-800';
            if (this.migration.status === 'blocked') return 'bg-red-100 text-red-700';
            return 'bg-base-200 text-base-content/70';
        },

        get migrationParityStatusClass() {
            if (this.migrationParity.error) return 'bg-red-100 text-red-700';
            if (this.migrationParity.status === 'matched') return 'bg-green-100 text-green-700';
            if (this.migrationParity.status === 'attention') return 'bg-yellow-100 text-yellow-800';
            if (this.migrationParity.status === 'baseline_needed') return 'bg-base-200 text-base-content/70';
            return 'bg-base-200 text-base-content/70';
        },

        migrationItemStatusClass(status) {
            if (status === 'complete') return 'bg-green-100 text-green-700';
            if (status === 'in_progress') return 'bg-yellow-100 text-yellow-800';
            return 'bg-red-100 text-red-700';
        },

        migrationItemStatusDot(status) {
            if (status === 'complete') return 'bg-green-500';
            if (status === 'in_progress') return 'bg-yellow-500';
            return 'bg-red-500';
        },

        migrationParityMetricStatusClass(status) {
            if (status === 'matched') return 'bg-green-100 text-green-700';
            if (status === 'attention') return 'bg-yellow-100 text-yellow-800';
            return 'bg-base-200 text-base-content/70';
        },

        migrationImportStatusClass(status) {
            if (status === 'planned') return 'bg-green-100 text-green-700';
            if (status === 'existing_report') return 'bg-blue-100 text-blue-700';
            if (status === 'needs_report_id') return 'bg-yellow-100 text-yellow-800';
            return 'bg-base-200 text-base-content/70';
        },

        apiHeaders() {
            return { 'Content-Type': 'application/json' };
        },

        workspaceHeaders() {
            const headers = this.apiHeaders();
            let workspaceId = null;
            try {
                workspaceId = window.localStorage?.getItem('dmarq.selectedWorkspaceId') || null;
            } catch (error) {
                workspaceId = null;
            }
            if (workspaceId) {
                headers['X-DMARQ-Workspace-ID'] = workspaceId;
            }
            return headers;
        },

        apiErrorDetail(data, fallback) {
            const detail = data?.detail;
            if (typeof detail === 'string') {
                return detail;
            }
            if (detail?.message) {
                return detail.message;
            }
            if (Array.isArray(detail)) {
                const message = detail
                    .map(item => item?.msg || item?.message || item?.detail || '')
                    .filter(Boolean)
                    .join(', ');
                return message || fallback;
            }
            return fallback;
        },

        recommendationSeverityClass(severity) {
            if (severity === 'error') return 'bg-red-500';
            if (severity === 'warning') return 'bg-yellow-500';
            return 'bg-blue-500';
        },

        remediationSeverityDotClass(severity) {
            if (['critical', 'high', 'error'].includes(severity)) return 'bg-red-500';
            if (['medium', 'warning'].includes(severity)) return 'bg-yellow-500';
            if (severity === 'low') return 'bg-blue-500';
            return 'bg-base-300';
        },

        remediationStateClass(state) {
            if (state === 'approval_ready') return 'bg-green-100 text-green-700';
            if (state === 'manual_action') return 'bg-yellow-100 text-yellow-800';
            if (state === 'investigate') return 'bg-blue-100 text-blue-700';
            return 'bg-base-200 text-base-content/70';
        },

        remediationNotificationClass(state) {
            if (state === 'approval_required') return 'bg-green-100 text-green-700';
            if (state === 'action_required') return 'bg-red-100 text-red-700';
            if (state === 'investigation_required') return 'bg-blue-100 text-blue-700';
            return 'bg-base-200 text-base-content/70';
        },

        remediationDispatchStatus(dispatch) {
            if (dispatch?.delivery_enqueued) return 'delivery_enqueued';
            if (dispatch?.eligible) return 'ready';
            if (dispatch?.enabled) return 'blocked';
            return 'disabled';
        },

        remediationDispatchClass(dispatch) {
            return {
                delivery_enqueued: 'bg-teal-100 text-teal-700',
                ready: 'bg-green-100 text-green-700',
                blocked: 'bg-yellow-100 text-yellow-800',
                disabled: 'bg-base-200 text-base-content/70'
            }[this.remediationDispatchStatus(dispatch)];
        },

        remediationDispatchLabel(dispatch) {
            return {
                delivery_enqueued: 'delivery queued',
                ready: 'ready',
                blocked: 'blocked',
                disabled: 'disabled'
            }[this.remediationDispatchStatus(dispatch)];
        },

        remediationDispatchNextStep(dispatch) {
            const status = this.remediationDispatchStatus(dispatch);
            if (status === 'delivery_enqueued') return 'Delivery has been queued for the configured webhook route.';
            if (status === 'ready') return 'Review the payload preview and explicitly dispatch when the operator is ready.';
            const nextStep = (dispatch?.next_steps || [])[0];
            return nextStep || 'Review notification settings before dispatching this remediation item.';
        },

        remediationActionBusy(item, action = '') {
            if (!this.remediationAction.loading) return false;
            if (this.remediationAction.itemId !== item?.id) return false;
            return !action || this.remediationAction.action === action;
        },

        remediationActionMessage(item) {
            if (this.remediationAction.itemId !== item?.id) return '';
            return this.remediationAction.message || this.remediationAction.error || '';
        },

        remediationActionMessageClass(item) {
            if (this.remediationAction.itemId !== item?.id) return 'text-[#5f5c78]';
            return this.remediationAction.error ? 'text-red-700' : 'text-green-700';
        },

        remediationHistoryDotClass(entry) {
            if (entry?.delivery_enqueued) return 'bg-teal-500';
            if (['acknowledged', 'resolved'].includes(entry?.state)) return 'bg-green-500';
            if (entry?.state === 'rejected') return 'bg-red-500';
            if (entry?.state === 'snoozed') return 'bg-yellow-500';
            return 'bg-blue-500';
        },

        senderStatusClass(status) {
            if (status === 'known') return 'bg-green-100 text-green-800';
            if (status === 'ambiguous') return 'bg-yellow-100 text-yellow-800';
            if (status === 'suspicious') return 'bg-red-100 text-red-800';
            return 'bg-gray-100 text-gray-700';
        },

        reputationStatusClass(status) {
            if (['listed', 'critical'].includes(status)) return 'bg-red-100 text-red-800';
            if (['suspicious', 'watch', 'warning'].includes(status)) return 'bg-yellow-100 text-yellow-800';
            if (status === 'clean') return 'bg-green-100 text-green-800';
            return 'bg-gray-100 text-gray-700';
        },

        reputationFeedClass(status) {
            if (status === 'listed') return 'bg-red-50 text-red-800';
            if (status === 'error') return 'bg-yellow-50 text-yellow-800';
            if (status === 'checked') return 'bg-green-50 text-green-800';
            return 'bg-base-200 text-base-content/70';
        },

        reputationLabel(reputation) {
            return reputation?.status_label || reputation?.status || 'Reputation unavailable';
        },

        reputationRiskLabel(reputation) {
            if (!reputation || reputation.risk_score === undefined || reputation.risk_score === null) {
                return 'risk not calculated';
            }
            return `risk ${reputation.risk_score}/100`;
        },

        reputationCheckedLabel(reputation) {
            if (!reputation?.checked_at) return 'not checked yet';
            const date = new Date(reputation.checked_at);
            if (Number.isNaN(date.getTime())) return reputation.checked_at;
            return `checked ${date.toLocaleString()}`;
        },

        reputationEvidencePreview(reputation) {
            return (reputation?.evidence || []).slice(0, 3);
        },

        sourceGeoSummary(source) {
            const geo = source?.geo || {};
            const isKnown = (value) => value && String(value).trim().toLowerCase() !== 'unknown';
            const region = isKnown(geo.region) ? geo.region : null;
            const country = isKnown(geo.country) ? geo.country : null;
            const network = isKnown(geo.network) ? geo.network : null;
            const asn = isKnown(geo.asn) ? geo.asn : null;
            const prefix = isKnown(geo.bgp_prefix) ? geo.bgp_prefix : null;
            const parts = [region, country, [asn, network, prefix].filter(Boolean).join(' · ')].filter(Boolean);
            return parts.length ? parts.join(' · ') : 'Geo unavailable';
        },

        formatLargeNumber(value) {
            const number = Number(value || 0);
            return new Intl.NumberFormat().format(number);
        },

        sourceSeenLabel(timestamp) {
            if (!timestamp) return 'never';
            const date = new Date(Number(timestamp) * 1000);
            const now = new Date();
            const diffMs = now.getTime() - date.getTime();
            const diffDays = Math.floor(diffMs / 86400000);
            if (Number.isFinite(diffDays) && diffDays >= 0) {
                if (diffDays === 0) return 'today';
                if (diffDays === 1) return 'yesterday';
                if (diffDays < 90) return `${diffDays} days ago`;
            }
            return date.toLocaleDateString();
        },

        sourceVolumeBars(source) {
            const history = (source.volume_history || []).slice(-14);
            const max = Math.max(...history.map(point => Number(point.count || 0)), 1);
            return history.map(point => {
                const count = Number(point.count || 0);
                const failed = Number(point.failed || 0);
                return {
                    ...point,
                    failed,
                    height: Math.max(12, Math.round((count / max) * 100)),
                    label: `${point.date}: ${this.formatLargeNumber(count)} emails${failed ? ', ' + this.formatLargeNumber(failed) + ' failed' : ''}`,
                };
            });
        },

        sourceDateWindow() {
            return this.filters.dateRange === 'all' ? '3650' : this.filters.dateRange;
        },

        async fetchDomainOwnership() {
            try {
                const response = await fetch(`/api/v1/domains/${encodeURIComponent(this.domainId)}/ownership`);
                if (!response.ok) {
                    throw new Error('Ownership proof could not be loaded.');
                }
                this.ownership = {
                    ...this.ownership,
                    ...(await response.json()),
                    loading: false,
                    error: '',
                    message: ''
                };
            } catch (error) {
                this.ownership = {
                    ...this.ownership,
                    loading: false,
                    error: error.message || 'Ownership proof could not be loaded.',
                    message: error.message || 'Ownership proof could not be loaded.'
                };
                console.error('Error fetching ownership proof:', error);
            }
        },

        async verifyDomainOwnership() {
            this.ownership.loading = true;
            this.ownership.error = '';
            this.ownership.message = '';
            try {
                const response = await fetch(`/api/v1/domains/${encodeURIComponent(this.domainId)}/ownership/verify`, {
                    method: 'POST'
                });
                const data = await response.json().catch(() => ({}));
                if (!response.ok) {
                    throw new Error(data.detail || 'Ownership proof could not be checked.');
                }
                this.ownership = {
                    ...this.ownership,
                    ...data,
                    loading: false,
                    error: '',
                    message: data.matched
                        ? 'Ownership verified. DNS write and repair workflows can now trust this domain.'
                        : 'TXT proof was not found yet. Check the record name and wait for DNS propagation.'
                };
            } catch (error) {
                this.ownership = {
                    ...this.ownership,
                    loading: false,
                    error: error.message || 'Ownership proof could not be checked.',
                    message: error.message || 'Ownership proof could not be checked.'
                };
                console.error('Error verifying ownership proof:', error);
            }
        },

        async verifyDomainOwnershipCloudflare() {
            this.ownership.loading = true;
            this.ownership.error = '';
            this.ownership.message = '';
            try {
                const headers = this.workspaceHeaders();
                const response = await fetch(`/api/v1/domains/${encodeURIComponent(this.domainId)}/ownership/cloudflare`, {
                    method: 'POST',
                    headers
                });
                const data = await response.json().catch(() => ({}));
                if (!response.ok) {
                    const detail = typeof data.detail === 'string' ? data.detail : data.detail?.message;
                    const nextSteps = Array.isArray(data.detail?.next_steps) ? data.detail.next_steps : data.next_steps;
                    if (nextSteps) {
                        this.ownership.next_steps = nextSteps;
                    }
                    throw new Error(detail || 'Cloudflare ownership could not be verified.');
                }
                this.ownership = {
                    ...this.ownership,
                    verified: data.verified,
                    proof_reason: data.proof_reason || this.ownership.proof_reason,
                    next_steps: data.next_steps || this.ownership.next_steps,
                    loading: false,
                    error: '',
                    message: `Cloudflare verified ${data.domain} through zone ${data.zone_name || data.zone_id}.`
                };
            } catch (error) {
                this.ownership = {
                    ...this.ownership,
                    loading: false,
                    error: error.message || 'Cloudflare ownership could not be verified.',
                    message: error.message || 'Cloudflare ownership could not be verified.'
                };
                console.error('Error verifying Cloudflare ownership:', error);
            }
        },

        async deleteDomain() {
            const typed = window.prompt(`Delete ${this.domainId}? Type the domain name to confirm.`);
            if (typed !== this.domainId) return;
            try {
                const response = await fetch(`/api/v1/domains/${encodeURIComponent(this.domainId)}`, {
                    method: 'DELETE'
                });
                if (response.status === 204) {
                    window.location.href = '/domains';
                    return;
                }
                const data = await response.json().catch(() => ({}));
                window.alert(data.detail || 'Domain could not be deleted.');
            } catch (error) {
                window.alert(error.message || 'Domain could not be deleted.');
            }
        },

        enableMigrationTools() {
            this.migrationToolsEnabled = true;
            if (this.migrationToolsLoaded) return;
            this.migrationToolsLoaded = true;
            this.fetchMigrationReadiness();
            this.fetchMigrationParity();
        },

        async fetchDomainStats() {
            try {
                const response = await this.fetchWithTimeout(
                    `/api/v1/domains/${this.domainId}/stats`,
                    {},
                    10000
                );
                if (response.ok) {
                    const data = await response.json();
                    this.stats = data;
                }
            } catch (error) {
                console.error('Error fetching domain stats:', error);
            }
        },

        async fetchDNSRecords(options = {}) {
            this.dnsRecordsLoading = true;
            this.dnsRecordsError = '';
            try {
                const response = await this.fetchWithTimeout(
                    `/api/v1/domains/${this.domainId}/dns${options.refresh ? '?refresh=true' : ''}`,
                    {},
                    options.refresh ? 20000 : 10000
                );
                if (!response.ok) {
                    const data = await response.json().catch(() => ({}));
                    const detail = typeof data.detail === 'string' ? data.detail : data.detail?.message;
                    throw new Error(detail || 'DNS records could not be loaded.');
                }
                const data = await response.json();
                this.dns = data;
                this.syncDetectedDnsProvider();
            } catch (error) {
                this.dnsRecordsError = error.message || 'DNS records could not be loaded.';
                console.error('Error fetching DNS records:', error);
            } finally {
                this.dnsRecordsLoading = false;
            }
        },

        async fetchDNSHealth(options = {}) {
            try {
                const response = await fetch(
                    `/api/v1/domains/${this.domainId}/dns/health${options.refresh ? '?refresh=true' : ''}`
                );
                if (response.ok) {
                    this.dnsHealth = await response.json();
                }
            } catch (error) {
                console.error('Error fetching DNS health:', error);
            }
        },

        async fetchDNSGuidance(options = {}) {
            try {
                const response = await fetch(
                    `/api/v1/domains/${this.domainId}/dns/lint${options.refresh ? '?refresh=true' : ''}`
                );
                if (response.ok) {
                    this.dnsGuidance = await response.json();
                    this.syncDetectedDnsProvider();
                }
            } catch (error) {
                console.error('Error fetching DNS guidance:', error);
            }
        },

        async fetchDNSProviders() {
            try {
                const response = await fetch('/api/v1/domains/dns/providers');
                if (response.ok) {
                    const data = await response.json();
                    const ready = (data.providers || []).filter(provider => provider.status === 'ready');
                    this.dnsProviders = ready.length ? ready : this.dnsProviders;
                    if (!this.dnsProviders.some(provider => provider.id === this.dnsWrite.provider)) {
                        this.dnsWrite.provider = this.dnsProviders[0].id;
                    }
                    this.syncDetectedDnsProvider();
                }
            } catch (error) {
                console.error('Error fetching DNS providers:', error);
            }
        },

        dnsApplyConfirmationText(preview) {
            const mutation = preview?.mutation || {};
            const previousValues = mutation.current_values || [];
            const previousText = previousValues.length ? previousValues.join('\n') : 'None captured by the provider preview.';
            const proposedText = mutation.content || 'No proposed value available.';
            const rollbackText = preview?.rollback?.summary || 'Review provider history before reverting this DNS record.';
            const provider = this.providerName(preview?.provider || mutation.provider || this.dnsWrite.provider);
            return [
                'Apply this live DNS change?',
                '',
                `Provider: ${provider}`,
                `Operation: ${mutation.operation || 'unknown'}`,
                `Record: ${mutation.name || 'unknown'}`,
                `Type: ${mutation.record_type || 'unknown'}`,
                `TTL: ${mutation.ttl || 'provider default'}`,
                '',
                'Previous value:',
                previousText,
                '',
                'Proposed value:',
                proposedText,
                '',
                `Rollback: ${rollbackText}`,
                '',
                'DMARQ will verify the provider readback after apply, but DNS propagation may still take time.'
            ].join('\n');
        },

        async submitDNSChange(plan, apply) {
            this.dnsWrite.loading = true;
            this.dnsWrite.error = '';
            this.dnsWrite.message = '';
            try {
                const response = await fetch(`/api/v1/domains/${this.domainId}/dns/change-plan/apply`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        plan_id: plan.plan_id,
                        provider: this.dnsWrite.provider,
                        allow_provider_mismatch: this.dnsWrite.allowProviderMismatch,
                        dry_run: !apply,
                        confirm: apply
                    })
                });
                const data = await response.json();
                if (!response.ok) {
                    this.dnsWrite.error = data.detail || 'DNS change could not be prepared';
                    return;
                }
                data.plan_id = plan.plan_id;
                this.dnsWrite.preview = data;
                this.dnsWrite.message = apply
                    ? (data.verification?.verified
                        ? 'DNS change verified by the provider. Refreshing DNS evidence now.'
                        : 'DNS change submitted, but provider verification is not complete. Review the verification details before treating it as repaired.')
                    : 'Preview ready. Review the provider mutation before applying.';
                if (apply) {
                    await this.fetchDNSRecords();
                    await this.fetchDNSHealth();
                    await this.fetchDNSGuidance();
                    await this.fetchPosture();
                    await this.fetchRemediationQueue();
                }
                return data;
            } catch (error) {
                this.dnsWrite.error = 'Network error — DNS change could not be prepared';
                console.error('Error submitting DNS change:', error);
                return null;
            } finally {
                this.dnsWrite.loading = false;
            }
        },

        previewDNSChange(plan) {
            return this.submitDNSChange(plan, false);
        },

        async applyDNSChange(plan) {
            const previewProvider = this.canonicalProviderId(this.dnsWrite.preview?.provider);
            const selectedProvider = this.canonicalProviderId(this.dnsWrite.provider);
            let preview = this.dnsWrite.preview &&
                this.dnsWrite.preview.plan_id === plan.plan_id &&
                previewProvider === selectedProvider
                ? this.dnsWrite.preview
                : null;
            if (!preview) {
                preview = await this.submitDNSChange(plan, false);
            }
            if (!preview?.mutation) {
                return null;
            }
            if (!window.confirm(this.dnsApplyConfirmationText(preview))) {
                return null;
            }
            return this.submitDNSChange(plan, true);
        },

        async fetchPosture(options = {}) {
            try {
                const response = await fetch(
                    `/api/v1/domains/${this.domainId}/posture${options.refresh ? '?refresh=true' : ''}`
                );
                if (response.ok) {
                    this.posture = await response.json();
                }
            } catch (error) {
                console.error('Error fetching posture dashboard:', error);
            }
        },

        resetRemediationQueue() {
            this.remediationQueue = {
                status: 'unavailable',
                summary: {
                    total: 0,
                    approval_ready: 0,
                    manual_action: 0,
                    investigate: 0,
                    informational: 0,
                    notify_approval_required: 0,
                    notify_action_required: 0,
                    notify_investigation_required: 0,
                    notify_summary_only: 0,
                    dispatch_ready: 0,
                    dispatch_blocked: 0,
                    dispatch_disabled: 0,
                    dispatch_awaiting_acknowledgement: 0,
                    dispatch_webhook_routes: 0
                },
                items: []
            };
        },

        async fetchRemediationQueue() {
            try {
                const response = await fetch(`/api/v1/domains/${encodeURIComponent(this.domainId)}/remediation`);
                if (!response.ok) {
                    console.error('Error fetching remediation queue:', {
                        domainId: this.domainId,
                        status: response.status,
                        statusText: response.statusText
                    });
                    this.resetRemediationQueue();
                    return;
                }
                this.remediationQueue = await response.json();
            } catch (error) {
                console.error('Error fetching remediation queue:', error);
                this.resetRemediationQueue();
            }
        },

        async recordRemediationLifecycle(item, lifecycleState) {
            const notification = item?.notification || {};
            if (!item?.id || !notification.event || !notification.dedupe_key) {
                this.remediationAction = {
                    itemId: item?.id || '',
                    action: lifecycleState,
                    loading: false,
                    message: '',
                    error: 'This remediation item does not have notification metadata.'
                };
                return;
            }
            this.remediationAction = {
                itemId: item.id,
                action: lifecycleState,
                loading: true,
                message: '',
                error: ''
            };
            try {
                const response = await fetch(
                    `/api/v1/domains/${encodeURIComponent(this.domainId)}/remediation/notifications/audit`,
                    {
                        method: 'POST',
                        headers: this.workspaceHeaders(),
                        body: JSON.stringify({
                            item_id: item.id,
                            lifecycle_state: lifecycleState,
                            event: notification.event,
                            dedupe_key: notification.dedupe_key
                        })
                    }
                );
                const data = await response.json().catch(() => ({}));
                if (!response.ok) {
                    throw new Error(this.apiErrorDetail(data, 'Remediation lifecycle marker could not be recorded.'));
                }
                this.remediationAction = {
                    itemId: item.id,
                    action: lifecycleState,
                    loading: false,
                    message: `Marked ${lifecycleState.replaceAll('_', ' ')}. No DNS changes were made.`,
                    error: ''
                };
                await this.fetchRemediationQueue();
            } catch (error) {
                this.remediationAction = {
                    itemId: item.id,
                    action: lifecycleState,
                    loading: false,
                    message: '',
                    error: error.message || 'Remediation lifecycle marker could not be recorded.'
                };
                console.error('Error recording remediation lifecycle marker:', error);
            }
        },

        async dispatchRemediationNotification(item) {
            const notification = item?.notification || {};
            const dispatch = notification.dispatch || {};
            if (!dispatch.eligible) {
                this.remediationAction = {
                    itemId: item?.id || '',
                    action: 'dispatch',
                    loading: false,
                    message: '',
                    error: this.remediationDispatchNextStep(dispatch)
                };
                return;
            }
            if (!window.confirm('Dispatch this remediation notification to the configured webhook route? This does not make DNS changes.')) {
                return;
            }
            this.remediationAction = {
                itemId: item.id,
                action: 'dispatch',
                loading: true,
                message: '',
                error: ''
            };
            try {
                const response = await fetch(
                    `/api/v1/domains/${encodeURIComponent(this.domainId)}/remediation/notifications/dispatch`,
                    {
                        method: 'POST',
                        headers: this.workspaceHeaders(),
                        body: JSON.stringify({
                            item_id: item.id,
                            confirm: true,
                            event: notification.event,
                            dedupe_key: notification.dedupe_key
                        })
                    }
                );
                const data = await response.json().catch(() => ({}));
                if (!response.ok) {
                    throw new Error(this.apiErrorDetail(data, 'Remediation notification could not be dispatched.'));
                }
                this.remediationAction = {
                    itemId: item.id,
                    action: 'dispatch',
                    loading: false,
                    message: `Dispatch queued for ${data.delivery_count || 0} webhook route${data.delivery_count === 1 ? '' : 's'}. No DNS changes were made.`,
                    error: ''
                };
                await this.fetchRemediationQueue();
            } catch (error) {
                this.remediationAction = {
                    itemId: item.id,
                    action: 'dispatch',
                    loading: false,
                    message: '',
                    error: error.message || 'Remediation notification could not be dispatched.'
                };
                console.error('Error dispatching remediation notification:', error);
            }
        },

        async fetchHealthHistory() {
            this.healthHistory.loading = true;
            this.healthHistory.error = '';
            try {
                const response = await fetch(`/api/v1/domains/${encodeURIComponent(this.domainId)}/posture/history?capture_current=false&limit=30`);
                if (!response.ok) {
                    throw new Error('Health score history could not be loaded.');
                }
                this.healthHistory = {
                    loading: false,
                    error: '',
                    ...(await response.json())
                };
                this.renderHealthScoreChart();
            } catch (error) {
                this.healthHistory = {
                    ...this.healthHistory,
                    loading: false,
                    error: error.message || 'Health score history could not be loaded.'
                };
                console.error('Error fetching health score history:', error);
            }
        },

        async fetchMigrationReadiness() {
            this.migration.loading = true;
            this.migration.error = '';
            try {
                const response = await fetch(`/api/v1/domains/${encodeURIComponent(this.domainId)}/migration/readiness`);
                if (!response.ok) {
                    throw new Error('Migration readiness could not be loaded.');
                }
                this.migration = {
                    loading: false,
                    error: '',
                    ...(await response.json())
                };
            } catch (error) {
                this.migration = {
                    ...this.migration,
                    loading: false,
                    error: error.message || 'Migration readiness could not be loaded.'
                };
                console.error('Error fetching migration readiness:', error);
            }
        },

        migrationParityQueryString() {
            const params = new URLSearchParams();
            if (this.migrationBaseline.report_count !== '') params.set('baseline_report_count', this.migrationBaseline.report_count);
            if (this.migrationBaseline.total_emails !== '') params.set('baseline_total_emails', this.migrationBaseline.total_emails);
            if (this.migrationBaseline.source_count !== '') params.set('baseline_source_count', this.migrationBaseline.source_count);
            if (this.migrationBaseline.compliance_rate !== '') params.set('baseline_compliance_rate', this.migrationBaseline.compliance_rate);
            if (this.migrationBaseline.policy) params.set('baseline_policy', this.migrationBaseline.policy);
            const query = params.toString();
            return query ? `?${query}` : '';
        },

        async fetchMigrationParity() {
            this.migrationParity.loading = true;
            this.migrationParity.error = '';
            try {
                const response = await fetch(`/api/v1/domains/${encodeURIComponent(this.domainId)}/migration/parity${this.migrationParityQueryString()}`);
                if (!response.ok) {
                    throw new Error('Migration parity could not be loaded.');
                }
                this.migrationParity = {
                    loading: false,
                    error: '',
                    ...(await response.json())
                };
            } catch (error) {
                this.migrationParity = {
                    ...this.migrationParity,
                    loading: false,
                    error: error.message || 'Migration parity could not be loaded.'
                };
                console.error('Error fetching migration parity:', error);
            }
        },

        compareMigrationBaseline() {
            return this.fetchMigrationParity();
        },

        loadMigrationImportSample() {
            const domain = this.domainId || 'example.com';
            this.migrationImport.format = 'csv';
            this.migrationImport.source_platform = 'DMARCguard';
            this.migrationImport.content = [
                'Domain,Report ID,Date,Source IP,Messages,DKIM,SPF,Policy',
                `${domain},legacy-${domain}-001,2026-06-01,192.0.2.10,1250,pass,pass,quarantine`,
                `${domain},legacy-${domain}-002,2026-06-02,198.51.100.23,340,pass,fail,quarantine`,
                `${domain},legacy-${domain}-003,2026-06-02,203.0.113.44,84,fail,pass,quarantine`,
                `${domain},legacy-${domain}-003,2026-06-02,203.0.113.44,84,fail,pass,quarantine`,
                `${domain},,2026-06-03,192.0.2.77,19,fail,fail,quarantine`
            ].join('\n');
        },

        async previewMigrationImport() {
            this.migrationImport.loading = true;
            this.migrationImport.error = '';
            try {
                const response = await fetch(`/api/v1/domains/${encodeURIComponent(this.domainId)}/migration/import/preview`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        format: this.migrationImport.format || 'auto',
                        source_platform: this.migrationImport.source_platform || null,
                        content: this.migrationImport.content,
                        max_rows: this.migrationImport.max_rows
                    })
                });
                if (!response.ok) {
                    const errorBody = await response.json().catch(() => ({}));
                    throw new Error(errorBody.detail || 'Historical export preview could not be loaded.');
                }
                this.migrationImport.preview = await response.json();
            } catch (error) {
                this.migrationImport.error = error.message || 'Historical export preview could not be loaded.';
                console.error('Error previewing migration import:', error);
            } finally {
                this.migrationImport.loading = false;
            }
        },

        applyMigrationPreviewBaseline() {
            const baseline = this.migrationImport.preview?.baseline;
            if (!baseline) return;
            this.migrationBaseline.report_count = baseline.report_count ?? '';
            this.migrationBaseline.total_emails = baseline.total_emails ?? '';
            this.migrationBaseline.source_count = baseline.source_count ?? '';
            this.migrationBaseline.compliance_rate = baseline.compliance_rate ?? '';
            this.migrationBaseline.policy = baseline.policy || '';
            return this.fetchMigrationParity();
        },

        async fetchMtaSts(options = {}) {
            try {
                const response = await fetch(
                    `/api/v1/domains/${this.domainId}/dns/mta-sts${options.refresh ? '?refresh=true' : ''}`
                );
                if (response.ok) {
                    this.mtaSts = await response.json();
                }
            } catch (error) {
                console.error('Error fetching MTA-STS posture:', error);
            }
        },

        async fetchBimi(options = {}) {
            try {
                const response = await fetch(
                    `/api/v1/domains/${this.domainId}/dns/bimi${options.refresh ? '?refresh=true' : ''}`
                );
                if (response.ok) {
                    this.bimi = await response.json();
                }
            } catch (error) {
                console.error('Error fetching BIMI posture:', error);
            }
        },

        async fetchSelectors() {
            try {
                const response = await fetch(`/api/v1/domains/${this.domainId}/selectors`);
                if (response.ok) {
                    const data = await response.json();
                    this.selectors = data.selectors || [];
                    this.reportSelectors = data.report_selectors || [];
                }
            } catch (error) {
                console.error('Error fetching selectors:', error);
            }
        },

        async addSelector() {
            this.selectorError = '';
            const sel = this.newSelector.trim();
            if (!sel) return;
            try {
                const response = await fetch(`/api/v1/domains/${this.domainId}/selectors`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ selector: sel })
                });
                if (response.ok) {
                    this.newSelector = '';
                    // Refresh selectors (both manual and report) and DNS check
                    this.fetchSelectors();
                    this.fetchDNSRecords();
                    this.fetchDNSHealth();
                    this.fetchDNSGuidance();
                    this.fetchPosture();
                    this.fetchMtaSts();
                } else {
                    const err = await response.json();
                    this.selectorError = err.detail || 'Failed to add selector';
                }
            } catch (error) {
                this.selectorError = 'Network error — could not add selector';
                console.error('Error adding selector:', error);
            }
        },

        async deleteSelector(selector) {
            try {
                const response = await fetch(
                    `/api/v1/domains/${this.domainId}/selectors/${encodeURIComponent(selector)}`,
                    { method: 'DELETE' }
                );
                if (response.ok) {
                    // Refresh selectors (both manual and report) and DNS check
                    this.fetchSelectors();
                    this.fetchDNSRecords();
                    this.fetchDNSHealth();
                    this.fetchDNSGuidance();
                    this.fetchPosture();
                    this.fetchMtaSts();
                } else {
                    console.error('Error deleting selector:', response.status);
                }
            } catch (error) {
                console.error('Error deleting selector:', error);
            }
        },

        async fetchReports() {
            this.reportsLoading = true;
            this.reportsError = '';
            try {
                const response = await this.fetchWithTimeout(
                    `/api/v1/domains/${this.domainId}/reports?limit=10`,
                    {},
                    10000
                );
                if (!response.ok) {
                    const data = await response.json().catch(() => ({}));
                    const detail = typeof data.detail === 'string' ? data.detail : data.detail?.message;
                    throw new Error(detail || 'Recent reports could not be loaded.');
                }
                const data = await response.json();
                this.reports = data.reports || [];
                this.lastComplianceTimeline = data.compliance_timeline || [];
                this.initComplianceChart(data.compliance_timeline);
            } catch (error) {
                this.reports = [];
                this.reportsError = error.message || 'Recent reports could not be loaded.';
                console.error('Error fetching reports:', error);
            } finally {
                this.reportsLoading = false;
            }
        },

        setVolumeScale(scale) {
            if (!['linear', 'logarithmic'].includes(scale)) return;
            if (scale === 'logarithmic' && !this.hasObservedVolume) return;
            this.volumeScale = scale;
            this.persistVolumeScale(scale);
            if (this.lastComplianceTimeline.length) {
                this.initComplianceChart(this.lastComplianceTimeline);
            }
        },
        
        async fetchSources(options = {}) {
            this.sourcesLoading = true;
            this.sourcesError = '';
            try {
                const params = new URLSearchParams({ days: this.sourceDateWindow() });
                if (options.refresh) params.set('refresh', 'true');
                const response = await this.fetchWithTimeout(
                    `/api/v1/domains/${encodeURIComponent(this.domainId)}/sources?${params.toString()}`,
                    {},
                    options.refresh ? 25000 : 12000
                );
                if (!response.ok) {
                    const data = await response.json().catch(() => ({}));
                    const detail = typeof data.detail === 'string' ? data.detail : data.detail?.message;
                    throw new Error(detail || 'Sending sources could not be loaded.');
                }
                const data = await response.json();
                this.sources = data.sources || [];
            } catch (error) {
                this.sources = [];
                this.sourcesError = error.message || 'Sending sources could not be loaded.';
                console.error('Error fetching sources:', error);
            } finally {
                this.sourcesLoading = false;
            }
        },

        async fetchSourceIntelligence() {
            this.sourceIntelligence.loading = true;
            this.sourceIntelligence.error = '';
            try {
                const response = await this.fetchWithTimeout(
                    `/api/v1/domains/${encodeURIComponent(this.domainId)}/source-intelligence?days=${this.sourceDateWindow()}`,
                    {},
                    10000
                );
                if (!response.ok) {
                    const data = await response.json().catch(() => ({}));
                    const detail = typeof data.detail === 'string' ? data.detail : data.detail?.message;
                    throw new Error(detail || 'Source intelligence could not be loaded.');
                }
                const data = await response.json();
                this.sourceIntelligence = {
                    ...data,
                    loading: false,
                    error: ''
                };
            } catch (error) {
                this.sourceIntelligence = {
                    regions: [],
                    anomalies: [],
                    summary: {},
                    loading: false,
                    error: error.message || 'Source intelligence could not be loaded.'
                };
                console.error('Error fetching source intelligence:', error);
            } finally {
                this.sourceIntelligence.loading = false;
            }
        },
        
        initComplianceChart(timelineData) {
            if (!timelineData || !timelineData.length) return;

            const canvas = document.getElementById('compliance-chart');
            if (!canvas) return;
            const ctx = canvas.getContext('2d');
            
            if (this.complianceChart) {
                this.complianceChart.destroy();
            }
            
            const labels = timelineData.map(item => item.date);
            const complianceData = timelineData.map(item => (item.volume || item.total || 0) > 0 ? item.compliance_rate : null);
            const failureData = timelineData.map(item => (item.volume || item.total || 0) > 0 ? (item.failure_rate || 0) : null);
            const volumeRawData = timelineData.map(item => item.volume || item.total || 0);
            const volumeData = volumeRawData.map(value => value > 0 ? value : null);
            const observedRates = [...complianceData, ...failureData]
                .filter(value => value !== null && Number.isFinite(value));
            const observedVolumes = volumeRawData.filter(value => value > 0 && Number.isFinite(value));
            this.hasObservedVolume = observedVolumes.length > 0;
            const volumeScale = this.effectiveVolumeScale();
            
            // Calculate the threshold line data (recommended 98% for policy advancement)
            const thresholdData = Array(labels.length).fill(98);
            
            this.complianceChart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: labels,
                    datasets: [
                        {
                            label: 'Compliance Rate',
                            data: complianceData,
                            yAxisID: 'yRate',
                            borderColor: 'rgb(59, 130, 246)', // blue-500
                            backgroundColor: 'rgba(59, 130, 246, 0.1)',
                            tension: 0.4,
                            fill: true,
                            pointBackgroundColor: 'rgb(59, 130, 246)',
                            pointRadius: 3,
                            pointHoverRadius: 5,
                            spanGaps: false
                        },
                        {
                            label: 'Failure Rate',
                            data: failureData,
                            yAxisID: 'yRate',
                            borderColor: 'rgb(220, 38, 38)',
                            backgroundColor: 'rgba(220, 38, 38, 0.08)',
                            tension: 0.4,
                            fill: false,
                            pointBackgroundColor: 'rgb(220, 38, 38)',
                            pointRadius: 3,
                            pointHoverRadius: 5,
                            spanGaps: false
                        },
                        {
                            label: 'Message Volume',
                            type: 'bar',
                            data: volumeData,
                            yAxisID: 'yVolume',
                            backgroundColor: 'rgba(107, 114, 128, 0.22)',
                            borderColor: 'rgba(107, 114, 128, 0.5)',
                            borderWidth: 1,
                            borderRadius: 4,
                            maxBarThickness: 28
                        },
                        {
                            label: 'Recommended Threshold (98%)',
                            data: thresholdData,
                            yAxisID: 'yRate',
                            borderColor: 'rgba(220, 38, 38, 0.6)', // red-600 with opacity
                            borderDash: [5, 5],
                            pointRadius: 0,
                            borderWidth: 2,
                            fill: false,
                            tension: 0
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        yRate: {
                            type: 'linear',
                            position: 'left',
                            beginAtZero: false,
                            min: observedRates.length ? Math.max(0, Math.min(...observedRates) - 10) : 0,
                            max: 100,
                            ticks: {
                                callback: value => value + '%'
                            },
                            title: {
                                display: true,
                                text: 'Compliance Rate (%)',
                                font: {
                                    weight: 'bold'
                                }
                            },
                            grid: {
                                color: 'rgba(0, 0, 0, 0.05)'
                            }
                        },
                        yVolume: {
                            type: volumeScale,
                            position: 'right',
                            min: volumeScale === 'logarithmic' ? 1 : 0,
                            ticks: {
                                precision: 0,
                                callback: function(value) {
                                    const numeric = Number(value);
                                    if (!Number.isFinite(numeric)) return value;
                                    if (numeric >= 1000000) return `${(numeric / 1000000).toFixed(numeric % 1000000 === 0 ? 0 : 1)}m`;
                                    if (numeric >= 1000) return `${(numeric / 1000).toFixed(numeric % 1000 === 0 ? 0 : 1)}k`;
                                    return numeric;
                                }
                            },
                            title: {
                                display: true,
                                text: volumeScale === 'logarithmic' ? 'Messages (log scale)' : 'Messages (linear scale)',
                                font: {
                                    weight: 'bold'
                                }
                            },
                            grid: {
                                drawOnChartArea: false
                            }
                        },
                        x: {
                            title: {
                                display: true,
                                text: 'Date',
                                font: {
                                    weight: 'bold'
                                }
                            },
                            grid: {
                                display: false
                            }
                        }
                    },
                    plugins: {
                        tooltip: {
                            backgroundColor: 'rgba(0, 0, 0, 0.8)',
                            titleFont: {
                                size: 13
                            },
                            bodyFont: {
                                size: 12
                            },
                            padding: 10,
                            callbacks: {
                                label: function(context) {
                                    if (context.dataset.label === 'Compliance Rate') {
                                        if (context.parsed.y === null) return 'Compliance: no observed mail volume';
                                        return `Compliance: ${context.parsed.y}%`;
                                    }
                                    if (context.dataset.label === 'Failure Rate') {
                                        if (context.parsed.y === null) return 'Failures: no observed mail volume';
                                        return `Failures: ${context.parsed.y}%`;
                                    }
                                    if (context.dataset.label === 'Message Volume') {
                                        const rawVolume = volumeRawData[context.dataIndex] || 0;
                                        if (rawVolume <= 0) return 'Messages: no observed mail volume';
                                        return `Messages: ${rawVolume.toLocaleString()}`;
                                    }
                                    return context.dataset.label;
                                },
                                title: function(context) {
                                    return `Date: ${context[0].label}`;
                                }
                            }
                        },
                        legend: {
                            display: true,
                            position: 'top',
                            labels: {
                                usePointStyle: true,
                                padding: 15
                            }
                        },
                        annotation: {
                            annotations: {
                                box1: {
                                    type: 'box',
                                    yScaleID: 'yRate',
                                    yMin: 90,
                                    yMax: 100,
                                    backgroundColor: 'rgba(34, 197, 94, 0.05)',
                                    borderWidth: 0
                                }
                            }
                        }
                    }
                }
            });
        },

        renderHealthScoreChart() {
            const canvas = document.getElementById('health-score-chart');
            if (!canvas || !this.healthHistory.points || !this.healthHistory.points.length) return;
            const labels = this.healthHistory.points.map(point => this.formatShortDate(point.date));
            const scores = this.healthHistory.points.map(point => point.score);
            const compliance = this.healthHistory.points.map(point => point.compliance_rate || 0);

            if (this.healthScoreChart) {
                this.healthScoreChart.destroy();
            }

            this.healthScoreChart = new Chart(canvas.getContext('2d'), {
                type: 'line',
                data: {
                    labels,
                    datasets: [
                        {
                            label: 'Health Score',
                            data: scores,
                            borderColor: '#272a5f',
                            backgroundColor: 'rgba(47, 157, 165, 0.14)',
                            fill: true,
                            tension: 0.35,
                            pointRadius: 2,
                            pointHoverRadius: 5
                        },
                        {
                            label: 'DMARC Compliance',
                            data: compliance,
                            borderColor: '#2f9da5',
                            backgroundColor: 'rgba(47, 157, 165, 0.05)',
                            borderDash: [4, 4],
                            fill: false,
                            tension: 0.35,
                            pointRadius: 0
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: {
                            min: 0,
                            max: 100,
                            ticks: {
                                callback: value => value + '%'
                            },
                            grid: {
                                color: 'rgba(7, 7, 31, 0.06)'
                            }
                        },
                        x: {
                            grid: {
                                display: false
                            }
                        }
                    },
                    plugins: {
                        legend: {
                            display: true,
                            position: 'top',
                            labels: {
                                usePointStyle: true,
                                padding: 12
                            }
                        },
                        tooltip: {
                            callbacks: {
                                label: context => {
                                    const suffix = context.dataset.label === 'DMARC Compliance' ? '%' : '/100';
                                    return `${context.dataset.label}: ${context.parsed.y}${suffix}`;
                                }
                            }
                        }
                    }
                }
            });
        },
        
        formatDate(timestamp) {
            const date = new Date(timestamp * 1000);
            return date.toLocaleDateString();
        },

        formatShortDate(value) {
            const date = new Date(`${value}T00:00:00`);
            if (Number.isNaN(date.getTime())) return value;
            return date.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
        },

        formatIsoDate(value) {
            const date = new Date(value);
            if (Number.isNaN(date.getTime())) return value;
            return date.toLocaleString();
        },

        formatScoreDelta(value) {
            if (value === null || value === undefined) return 'No previous score';
            if (value > 0) return `+${value} since previous`;
            if (value < 0) return `${value} since previous`;
            return 'No score change';
        },
        
        getPassRateClass(rate) {
            if (rate >= 90) return 'bg-green-100 text-green-800';
            if (rate >= 50) return 'bg-yellow-100 text-yellow-800';
            return 'bg-red-100 text-red-800';
        }
    };
}
