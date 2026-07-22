function reportDetailApp(reportId = '') {
    return {
        reportId: reportId,
        report: null,
        loading: true,
        error: null,
        reputationRefreshing: false,
        reputationRefreshError: '',
        enrichmentHydrating: false,
        recordRiskFilter: 'all',
        recordPageSize: 25,

        async init() {
            this.reportId = this.$el?.dataset?.reportId || this.reportId;
            this.bindPageControls();
            await this.fetchReport();
        },

        bindPageControls() {
            const root = this.$root || document;
            if (root.dataset?.reportControlsBound === 'true') {
                return;
            }
            if (root.dataset) {
                root.dataset.reportControlsBound = 'true';
            }
            root.addEventListener('click', (event) => {
                if (!(event.target instanceof Element)) {
                    return;
                }
                const retryButton = event.target.closest('[data-report-retry-load]');
                if (retryButton && root.contains(retryButton)) {
                    this.fetchReport();
                    return;
                }

                const refreshReputationButton = event.target.closest('[data-report-refresh-reputation]');
                if (refreshReputationButton && root.contains(refreshReputationButton)) {
                    this.fetchReport({ refreshReputation: true });
                    return;
                }

                const riskFilterButton = event.target.closest('[data-report-risk-filter]');
                if (riskFilterButton && root.contains(riskFilterButton)) {
                    this.setRecordRiskFilter(riskFilterButton.dataset.reportRiskFilter || 'all');
                    return;
                }

                const showMoreButton = event.target.closest('[data-report-show-more-records]');
                if (showMoreButton && root.contains(showMoreButton)) {
                    this.recordPageSize += 25;
                    return;
                }

                const button = event.target.closest('[data-report-delete]');
                if (!button || !root.contains(button)) {
                    return;
                }
                const domain = button.dataset.reportDomain || '';
                const reportId = button.dataset.reportId || '';
                if (domain && reportId) {
                    this.deleteReport(domain, reportId);
                }
            });
        },

        async fetchReport(options = {}) {
            const refreshReputation = Boolean(options.refreshReputation);
            if (refreshReputation) {
                this.reputationRefreshing = true;
                this.reputationRefreshError = '';
            } else {
                this.loading = true;
                this.error = null;
            }
            try {
                const query = refreshReputation ? '?refresh_reputation=true' : '';
                const requestUrl = `/api/v1/reports/${encodeURIComponent(this.reportId)}${query}`;
                let response;
                if (refreshReputation) {
                    const controller = new AbortController();
                    const timeout = window.setTimeout(() => controller.abort(), 30000);
                    try {
                        response = await fetch(requestUrl, { signal: controller.signal });
                    } finally {
                        window.clearTimeout(timeout);
                    }
                } else {
                    response = await fetch(requestUrl);
                }
                if (response.ok) {
                    this.report = this.normalizeReport(await response.json());
                    if (!refreshReputation) {
                        this.recordRiskFilter = this.recordRiskCounts.authReview > 0 ? 'auth_review' : 'all';
                        this.recordPageSize = 25;
                    }
                    if (!refreshReputation) {
                        this.reputationRefreshError = '';
                    }
                    if (!refreshReputation && this.report?.enrichment?.pending) {
                        this.hydrateEnrichment();
                    }
                } else if (response.status === 404) {
                    if (!refreshReputation) {
                        this.report = null;
                        this.error = `Report '${this.reportId}' was not found. It may have been deleted or may not exist.`;
                    } else {
                        this.reputationRefreshError = `Report '${this.reportId}' was not found.`;
                    }
                } else {
                    const data = await response.json().catch(() => ({}));
                    const detail = typeof data.detail === 'string' ? data.detail : data.detail?.message;
                    if (!refreshReputation) {
                        this.report = null;
                        this.error = detail || 'Failed to load report. Please try again later.';
                    } else {
                        this.reputationRefreshError = detail || 'Reputation could not be refreshed. Please try again later.';
                    }
                }
            } catch (err) {
                if (!refreshReputation) {
                    this.report = null;
                    this.error = 'Network error — could not load report.';
                } else if (err?.name === 'AbortError') {
                    this.reputationRefreshError = 'Reputation refresh timed out. Please try again in a moment.';
                } else {
                    this.reputationRefreshError = 'Network error — reputation could not be refreshed.';
                }
                console.error('Error fetching report:', err);
            } finally {
                if (refreshReputation) {
                    this.reputationRefreshing = false;
                } else {
                    this.loading = false;
                }
            }
        },

        async deleteReport(domain, reportId) {
            if (
                !confirm(
                    `Delete report "${reportId}" for domain "${domain}"?\n\nThis will remove the report from the system. You can re-import it afterwards.`
                )
            ) {
                return;
            }
            try {
                const response = await fetch(
                    `/api/v1/reports/domain/${encodeURIComponent(domain)}/reports/${encodeURIComponent(reportId)}`,
                    { method: 'DELETE' }
                );
                if (response.ok) {
                    window.location.href = '/reports';
                } else {
                    const data = await response.json().catch(() => ({}));
                    alert(`Failed to delete report: ${data.detail || response.statusText}`);
                }
            } catch (error) {
                console.error('Error deleting report:', error);
                alert('Network error — could not delete report.');
            }
        },

        formatDate(timestamp) {
            if (!timestamp) return '—';
            return new Date(timestamp * 1000).toLocaleString();
        },

        normalizeReport(report) {
            const normalized = report && typeof report === 'object' ? report : {};
            return {
                ...normalized,
                reputation_summary: normalized.reputation_summary || {},
                enrichment: normalized.enrichment || {
                    status: 'complete',
                    pending: false,
                    ptr: 'complete',
                    network: 'complete',
                    reputation: 'complete',
                    unique_source_ips: 0,
                    record_count: 0,
                },
                records: (normalized.records || []).map((record) => ({
                    ...record,
                    source_details: record.source_details || {},
                })),
            };
        },

        async hydrateEnrichment() {
            if (this.enrichmentHydrating || !this.reportId) {
                return;
            }
            this.enrichmentHydrating = true;
            try {
                const response = await fetch(
                    `/api/v1/reports/${encodeURIComponent(this.reportId)}`
                );
                if (!response.ok) {
                    return;
                }
                const next = this.normalizeReport(await response.json());
                // Keep evidence already on screen; only replace enrichment-bearing fields.
                this.report = {
                    ...this.report,
                    ...next,
                    records: next.records,
                    reputation_summary: next.reputation_summary,
                    enrichment: next.enrichment,
                };
            } catch (_err) {
                // Evidence remains visible; enrichment stays partial until the next load.
            } finally {
                this.enrichmentHydrating = false;
            }
        },

        get reportDomainUrl() {
            const domain = this.report?.domain || '';
            return domain ? `/domains/${encodeURIComponent(domain)}` : '/domains';
        },

        passRateClass(rate) {
            if (rate >= 90) return 'text-success';
            if (rate >= 50) return 'text-warning';
            return 'text-error';
        },

        get filteredRecords() {
            const records = this.report?.records || [];
            return records.filter((record) => this.recordRiskMatches(record, this.recordRiskFilter));
        },

        get visibleFilteredRecords() {
            return this.filteredRecords.slice(0, this.recordPageSize);
        },

        get hiddenFilteredRecordCount() {
            return Math.max(this.filteredRecords.length - this.visibleFilteredRecords.length, 0);
        },

        get senderClusters() {
            const clusters = new Map();
            (this.report?.records || []).forEach((record) => {
                const details = record.source_details || {};
                const sender = this.recordSender(record);
                const provider = sender.provider || sender.name || details.organization || 'Unknown sender';
                const network = details.network || details.asn || details.bgp_prefix || 'Unknown network';
                const key = `${provider}|${network}`;
                const cluster = clusters.get(key) || {
                    key,
                    provider,
                    network,
                    messages: 0,
                    records: 0,
                    failures: 0,
                    mixed: 0,
                    unknown: 0,
                    ips: [],
                    nextAction: '',
                    nextActionPriority: -1,
                };
                const count = Number(record.count || 0);
                const dkim = String(record.dkim_result || '').toLowerCase();
                const spf = String(record.spf_result || '').toLowerCase();
                const disposition = String(record.disposition || '').toLowerCase();
                const authFailure = (dkim === 'fail' && spf === 'fail') || ['reject', 'quarantine'].includes(disposition);
                const mixed = (dkim === 'pass' && spf === 'fail') || (dkim === 'fail' && spf === 'pass');
                const unknown = this.recordSenderStatus(record) === 'unknown' || provider === 'Unknown sender';
                cluster.messages += count;
                cluster.records += 1;
                if (authFailure) cluster.failures += count;
                if (mixed) cluster.mixed += count;
                if (unknown) cluster.unknown += count;
                if (record.source_ip && !cluster.ips.includes(record.source_ip)) cluster.ips.push(record.source_ip);
                const actionPriority = authFailure ? 3 : mixed ? 2 : unknown ? 1 : 0;
                const nextAction = (record.next_steps || [])[0] ||
                    this.recordSenderRemediationHint(record) ||
                    (record.failure_reasons || [])[0] || '';
                if (actionPriority > cluster.nextActionPriority) {
                    cluster.nextAction = nextAction;
                    cluster.nextActionPriority = actionPriority;
                }
                clusters.set(key, cluster);
            });
            return Array.from(clusters.values())
                .sort((left, right) => (
                    right.failures - left.failures ||
                    right.mixed - left.mixed ||
                    right.unknown - left.unknown ||
                    right.messages - left.messages
                ))
                .slice(0, 8);
        },

        get investigationCounts() {
            return (this.report?.records || []).reduce((counts, record) => {
                const count = Number(record.count || 0);
                const dkim = String(record.dkim_result || '').toLowerCase();
                const spf = String(record.spf_result || '').toLowerCase();
                const disposition = String(record.disposition || '').toLowerCase();
                if ((dkim === 'fail' && spf === 'fail') || ['reject', 'quarantine'].includes(disposition)) {
                    counts.failed += count;
                } else if ((dkim === 'pass' && spf === 'fail') || (dkim === 'fail' && spf === 'pass')) {
                    counts.mixed += count;
                } else if (!dkim || !spf || (dkim !== 'pass' && spf !== 'pass')) {
                    counts.unknown += count;
                }
                return counts;
            }, { failed: 0, mixed: 0, unknown: 0 });
        },

        get investigationTitle() {
            const counts = this.investigationCounts;
            if (counts.failed > 0) {
                return `${this.countLabel(counts.failed, 'message')} ${counts.failed === 1 ? 'needs' : 'need'} authentication review`;
            }
            if (counts.mixed > 0) {
                return `${this.countLabel(counts.mixed, 'message')} ${counts.mixed === 1 ? 'has' : 'have'} mixed SPF and DKIM results`;
            }
            if (counts.unknown > 0) {
                return `${this.countLabel(counts.unknown, 'message')} ${counts.unknown === 1 ? 'needs' : 'need'} classification`;
            }
            return 'No authentication failure requires action';
        },

        countLabel(count, singular) {
            const normalized = Number(count || 0);
            return `${normalized} ${singular}${normalized === 1 ? '' : 's'}`;
        },

        get investigationDetail() {
            const first = this.senderClusters.find(cluster => cluster.failures || cluster.mixed || cluster.unknown);
            if (!first) return 'Keep monitoring this domain for new or changed sending sources.';
            const signal = first.failures ? 'failing authentication' : first.mixed ? 'mixed authentication' : 'unclassified traffic';
            return `${first.provider} on ${first.network} is the largest ${signal} cluster in this report.`;
        },

        get investigationPrimaryLabel() {
            return this.investigationCounts.failed > 0 ? 'Review failing records' : 'Review source evidence';
        },

        get investigationPrimaryFilter() {
            return this.investigationCounts.failed > 0 ? 'auth_review' : 'all';
        },

        setRecordRiskFilter(filter) {
            this.recordRiskFilter = filter;
            this.recordPageSize = 25;
            const records = this.$root && typeof this.$root.querySelector === 'function'
                ? this.$root.querySelector('#report-records')
                : null;
            if (records) records.open = true;
            window.location.hash = 'report-records';
        },

        clusterStatusLabel(cluster) {
            if (cluster.failures > 0) return `${cluster.failures} failing`;
            if (cluster.mixed > 0) return `${cluster.mixed} mixed`;
            if (cluster.unknown > 0) return `${cluster.unknown} unknown`;
            return 'No auth issue';
        },

        clusterStatusClass(cluster) {
            if (cluster.failures > 0) return 'bg-red-100 text-red-800';
            if (cluster.mixed > 0) return 'bg-yellow-100 text-yellow-800';
            if (cluster.unknown > 0) return 'bg-gray-100 text-gray-700';
            return 'bg-green-100 text-green-800';
        },

        get recordRiskCounts() {
            const records = this.report?.records || [];
            return records.reduce(
                (counts, record) => {
                    counts.total += 1;
                    if (this.recordReputationNeedsReview(record)) counts.risky += 1;
                    if (record.reputation?.status === 'listed') counts.listed += 1;
                    if (!record.reputation) counts.unchecked += 1;
                    if (record.review_status === 'needs_review') counts.authReview += 1;
                    return counts;
                },
                { total: 0, risky: 0, listed: 0, unchecked: 0, authReview: 0 }
            );
        },

        recordRiskMatches(record, filter) {
            if (!record || filter === 'all') return true;
            if (filter === 'listed') return record.reputation?.status === 'listed';
            if (filter === 'risky') return this.recordReputationNeedsReview(record);
            if (filter === 'auth_review') return record.review_status === 'needs_review';
            if (filter === 'unchecked') return !record.reputation;
            if (filter === 'clean') return record.reputation?.status === 'clean';
            return true;
        },

        recordReputationNeedsReview(record) {
            const status = record?.reputation?.status || '';
            const risk = Number(record?.reputation?.risk_score || 0);
            return ['listed', 'critical', 'suspicious'].includes(status) || risk >= 50;
        },

        recordRiskLabel() {
            const counts = this.recordRiskCounts;
            if (this.recordRiskFilter === 'all') {
                return `${counts.total} source record${counts.total === 1 ? '' : 's'}`;
            }
            return `${this.filteredRecords.length} of ${counts.total} source record${counts.total === 1 ? '' : 's'}`;
        },

        resultClass(result) {
            if (result === 'pass') return 'bg-green-100 text-green-800';
            if (result === 'fail') return 'bg-red-100 text-red-800';
            return 'bg-gray-100 text-gray-800';
        },

        dispositionClass(disposition) {
            if (disposition === 'none') return 'bg-green-100 text-green-800';
            if (disposition === 'quarantine') return 'bg-yellow-100 text-yellow-800';
            if (disposition === 'reject') return 'bg-red-100 text-red-800';
            return 'bg-gray-100 text-gray-800';
        },

        reviewStatusClass(status) {
            if (status === 'needs_review') return 'bg-yellow-100 text-yellow-800';
            return 'bg-green-100 text-green-800';
        },

        reviewStatusLabel(status) {
            if (status === 'needs_review') return 'Needs review';
            return 'Pass';
        },

        senderStatusClass(status) {
            if (status === 'known') return 'bg-green-100 text-green-800';
            if (status === 'ambiguous') return 'bg-yellow-100 text-yellow-800';
            if (status === 'suspicious') return 'bg-red-100 text-red-800';
            return 'bg-gray-100 text-gray-700';
        },

        recordSender(record) {
            return record?.source_details?.sender || {};
        },

        recordSenderName(record) {
            const sender = this.recordSender(record);
            return sender.name || sender.label || 'Unknown sender';
        },

        recordSenderStatus(record) {
            return this.recordSender(record).status || 'unknown';
        },

        recordSenderProvider(record) {
            const sender = this.recordSender(record);
            return sender.provider || sender.category || 'Unclassified';
        },

        recordSenderConfidence(record) {
            return `${this.recordSender(record).confidence || 0}% confidence`;
        },

        recordSenderEvidence(record) {
            const evidence = this.recordSender(record).evidence || [];
            return evidence.length ? evidence[0] : '';
        },

        recordSenderRemediationHint(record) {
            return this.recordSender(record).remediation_hint || '';
        },

        sourceLocation(record) {
            const details = record.source_details || {};
            const countryKnown = details.country && details.country !== 'Unknown';
            const regionKnown = details.region && details.region !== 'Unknown';
            const country = countryKnown
                ? details.country
                : (details.country_code && details.country_code !== 'ZZ' ? details.country_code : null);
            const region = regionKnown ? details.region : null;
            const code = details.country_code && details.country_code !== 'ZZ' && countryKnown
                ? ` (${details.country_code})`
                : '';
            const network = [details.asn, details.network, details.bgp_prefix].filter(Boolean).join(' · ');
            const parts = [region, country ? `${country}${code}` : null, network].filter(Boolean);
            if (parts.length) {
                return parts.join(' · ');
            }
            if (details.enrichment_mode === 'tokenless-fallback') {
                return 'Tokenless ASN lookup pending or partial';
            }
            return details.network_error || 'Geo unavailable';
        },

        geoAvailabilityHint(details) {
            const geo = details || {};
            return geo.config_hint || '';
        },

        ptrStatusLabel(details) {
            const source = details || {};
            const status = source.ptr_status || '';
            const detail = (source.ptr_detail || '').trim();
            if (source.hostname) {
                return `PTR ${source.hostname}`;
            }
            if (status === 'nxdomain') {
                return 'PTR unavailable — no PTR record (NXDOMAIN)';
            }
            if (status === 'timeout') {
                return 'PTR unavailable — resolver timeout (will retry)';
            }
            if (status === 'refused') {
                return 'PTR unavailable — resolver refused the query (will retry)';
            }
            if (status === 'servfail') {
                return 'PTR unavailable — resolver failure (will retry)';
            }
            if (status === 'transient') {
                return 'PTR unavailable — transient DNS error (will retry)';
            }
            if (status === 'skipped') {
                return 'PTR skipped — address is not a global unicast IP';
            }
            if (status === 'invalid') {
                return 'PTR skipped — invalid IP address';
            }
            if (detail) {
                return `PTR unavailable — ${detail}`;
            }
            return 'PTR unavailable';
        },

        reputationClass(status) {
            if (status === 'listed' || status === 'critical') return 'bg-red-100 text-red-800';
            if (status === 'suspicious') return 'bg-yellow-100 text-yellow-800';
            if (status === 'clean') return 'bg-green-100 text-green-800';
            return 'bg-gray-100 text-gray-800';
        },

        reportReputationClass(status) {
            if (status === 'listed') return 'bg-red-100 text-red-800';
            if (status === 'attention') return 'bg-yellow-100 text-yellow-800';
            if (status === 'clean') return 'bg-green-100 text-green-800';
            return 'bg-gray-100 text-gray-800';
        },

        reportReputationRiskLabel(summary) {
            const score = summary?.highest_risk_score;
            if (typeof score === 'number') {
                return `highest risk ${score}/100`;
            }
            return 'risk unknown';
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

        reputationScoreLabel(reputation) {
            if (typeof reputation?.risk_score === 'number') {
                return `risk ${reputation.risk_score}/100`;
            }
            return 'risk unknown';
        },

        reputationDetail(reputation) {
            return (
                reputation?.status_detail ||
                reputation?.summary ||
                reputation?.evidence_summary ||
                'No reputation assessment is available for this IP yet.'
            );
        },

        reputationCheckedLabel(reputation) {
            if (!reputation?.checked_at) return 'not checked yet';
            const date = new Date(reputation.checked_at);
            if (Number.isNaN(date.getTime())) return reputation.checked_at;
            return `checked ${date.toLocaleString()}`;
        },

        reputationAgeLabel(reputation) {
            if (!reputation?.checked_at) return 'reputation not checked';
            const checked = new Date(reputation.checked_at);
            if (Number.isNaN(checked.getTime())) return 'reputation timestamp unknown';
            const ageHours = Math.max(0, Math.floor((Date.now() - checked.getTime()) / 3600000));
            if (ageHours < 1) return 'reputation checked recently';
            if (ageHours < 24) return `reputation checked ${ageHours}h ago`;
            const ageDays = Math.floor(ageHours / 24);
            return `reputation checked ${ageDays}d ago`;
        },

        reputationEvidencePreview(reputation) {
            return (reputation?.evidence || []).slice(0, 3);
        },

        reputationNextSteps(reputation) {
            return (reputation?.recommendations || []).slice(0, 2);
        },

        seenLabel(timestamp) {
            if (!timestamp) return '';
            const date = new Date(Number(timestamp) * 1000);
            if (Number.isNaN(date.getTime())) return String(timestamp);
            const diffDays = Math.floor((Date.now() - date.getTime()) / 86400000);
            if (Number.isFinite(diffDays) && diffDays >= 0) {
                if (diffDays === 0) return 'today';
                if (diffDays === 1) return 'yesterday';
                if (diffDays < 90) return `${diffDays} days ago`;
            }
            return date.toLocaleDateString();
        },
    };
}

if (typeof document !== 'undefined') {
    document.addEventListener('alpine:init', () => {
        Alpine.data('reportDetailApp', reportDetailApp);
    });
}
