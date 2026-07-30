function workspaceOnboarding(options = {}) {
    return {
        multiWorkspaceUiEnabled: Boolean(options.multiWorkspaceUiEnabled),
        previewing: false,
        applying: false,
        error: '',
        success: '',
        plan: null,
        result: null,
        tasks: [],
        lastPreviewSignature: '',
        initialized: false,
        setupStateLoading: true,
        setupStateError: '',
        setupStateLoaded: false,
        configuring: false,
        draftDirty: false,
        guidedMailHealthUiAvailable: false,
        guidanceInterviewCompleted: false,
        guidanceDepth: 'guided',
        selectedGoal: '',
        installationGoals: [],
        sovereigntyPreference: 'not_sure',
        notificationPosture: 'actionable_only',
        mailContext: {},
        savingGoal: false,
        goalSaved: false,
        goalError: '',
        interviewStep: 1,
        editingGuidance: false,
        diagnosticPlan: null,
        diagnosticPlanLoading: false,
        diagnosticPlanError: '',
        interviewDomain: '',
        interviewControlsDns: '',
        interviewDomainSendsMail: '',
        interviewBounceAvailable: false,
        interviewLowVolume: false,
        interviewRecipientProvider: '',
        interviewFirstObserved: '',
        mailHealthGoals: [
            {id: 'delivery_problem', label: 'Messages are being rejected or bounced', description: 'I need to understand what may be affecting mail I send.'},
            {id: 'spam_or_inconsistent', label: 'Mail is landing in spam or behaving inconsistently', description: 'I want to check authentication and likely delivery risks.'},
            {id: 'reports_confusing', label: 'I received DMARC reports I do not understand', description: 'Help me turn these reports into a clear next step.'},
            {id: 'suspected_abuse', label: 'Someone may be using my domain for spam', description: 'Help me separate likely abuse from my intended senders.'},
            {id: 'preventive_monitoring', label: 'I want to keep mail delivery healthy', description: 'Set up monitoring before a problem appears.'},
            {id: 'curious', label: 'I want to understand my mail setup', description: 'Show me the current picture without assuming there is a problem.'},
        ],
        guidanceGoalIds: {
            delivery_problem: 'troubleshoot_delivery',
            spam_or_inconsistent: 'improve_authentication',
            reports_confusing: 'understand_reports',
            suspected_abuse: 'protect_against_spoofing',
            preventive_monitoring: 'continuous_monitoring',
            curious: 'learn_or_explore',
        },
        guidanceUiGoals: {
            troubleshoot_delivery: 'delivery_problem',
            investigate_bounces: 'delivery_problem',
            understand_reports: 'reports_confusing',
            improve_authentication: 'spam_or_inconsistent',
            protect_against_spoofing: 'suspected_abuse',
            continuous_monitoring: 'preventive_monitoring',
            audit_or_compliance: 'curious',
            learn_or_explore: 'curious',
            other: 'curious',
        },
        translate(message, replacements = {}) {
            return typeof window.dmarqT === 'function'
                ? window.dmarqT(message, replacements)
                : Object.entries(replacements).reduce(
                    (result, [key, value]) => result.replaceAll(`{${key}}`, String(value)),
                    message
                );
        },
        get translatedMailHealthGoals() {
            return this.mailHealthGoals.map(goal => ({
                ...goal,
                label: this.translate(goal.label),
                description: this.translate(goal.description),
            }));
        },
        setupState: {
            domains: 0,
            reports: 0,
            sources: 0,
            healthySources: 0,
            dnsProviderConnected: false,
            notificationsConfigured: false,
        },
        form: {
            organizationName: '',
            workspaceName: '',
            workspaceDescription: '',
            domain: '',
            dnsProvider: 'Cloudflare',
            reportMailbox: '',
            mailSourcePath: 'imap',
            imapServer: '',
            imapUsername: '',
            imapPassword: '',
        },
        get saving() {
            return this.previewing || this.applying;
        },
        get singleUserMode() {
            return !this.multiWorkspaceUiEnabled;
        },
        get hasExistingSetup() {
            return this.setupState.domains > 0 || this.setupState.sources > 0 || this.setupState.reports > 0;
        },
        get showSetupStatus() {
            return this.singleUserMode && this.setupStateLoaded && this.hasExistingSetup && !this.configuring;
        },
        get showSetupForm() {
            if (this.multiWorkspaceUiEnabled || this.configuring) return true;
            if (this.showGoalInterview) return false;
            return this.setupStateLoaded &&
                !this.setupStateLoading &&
                !this.setupStateError &&
                !this.hasExistingSetup;
        },
        get showGoalInterview() {
            return this.singleUserMode && this.guidedMailHealthUiAvailable && (
                this.editingGuidance || (!this.guidanceInterviewCompleted && !this.hasExistingSetup)
            );
        },
        get showGoalRecommendation() {
            return this.singleUserMode && this.guidedMailHealthUiAvailable && !this.editingGuidance && (
                this.guidanceInterviewCompleted || this.hasExistingSetup
            ) && Boolean(this.diagnosticPlan);
        },
        get goalRecommendation() {
            const currentAction = this.diagnosticPlan?.current_action;
            return {
                title: currentAction?.title || '',
                description: currentAction?.description || '',
                evidenceNote: currentAction?.why || '',
                verification: currentAction?.verification || '',
                action: currentAction?.label || '',
                href: currentAction?.href || '/onboarding',
            };
        },
        get interviewProgress() {
            return this.translate('Step {step} of 4', {step: this.interviewStep});
        },
        get interviewStepTitle() {
            return this.translate({
                1: 'What brought you to DMARQ?',
                2: 'Which domain is affected?',
                3: 'What do you already know about the mail flow?',
                4: 'How should DMARQ guide you?',
            }[this.interviewStep] || 'What brought you to DMARQ?');
        },
        get interviewStepDescription() {
            return this.translate({
                1: 'Choose the problem that should determine the first next step.',
                2: 'You can skip anything you do not know. DMARQ will keep it visible as an unknown.',
                3: 'These answers help separate intended mail, likely abuse, and missing delivery evidence.',
                4: 'Choose the explanation depth and data-path preference. Technical evidence stays available.',
            }[this.interviewStep] || '');
        },
        get interviewCanContinue() {
            if (this.interviewStep === 1) return Boolean(this.selectedGoal);
            return true;
        },
        get guidanceEditLabel() {
            return this.translate(
                this.guidanceInterviewCompleted ? 'Change answers' : 'Resume setup questions'
            );
        },
        get interviewShowsBounceQuestion() {
            return this.selectedGoal === 'delivery_problem';
        },
        get diagnosticKnownFacts() {
            return Array.isArray(this.diagnosticPlan?.known_facts) ? this.diagnosticPlan.known_facts : [];
        },
        get diagnosticUnknowns() {
            return Array.isArray(this.diagnosticPlan?.unknowns) ? this.diagnosticPlan.unknowns : [];
        },
        get diagnosticInferences() {
            return Array.isArray(this.diagnosticPlan?.inferences) ? this.diagnosticPlan.inferences : [];
        },
        get diagnosticBlockers() {
            const blockers = this.diagnosticPlan?.current_action?.blocked_by;
            return Array.isArray(blockers) ? blockers : [];
        },
        get diagnosticLaterSteps() {
            return Array.isArray(this.diagnosticPlan?.later_steps) ? this.diagnosticPlan.later_steps : [];
        },
        get showDiagnosticPlanStatus() {
            return this.singleUserMode && this.guidedMailHealthUiAvailable && !this.editingGuidance && (
                this.guidanceInterviewCompleted || this.hasExistingSetup
            ) && (this.diagnosticPlanLoading || Boolean(this.diagnosticPlanError));
        },
        get sovereigntyDescription() {
            const descriptions = {
                keep_data_local: 'Prefer a mailbox or bridge close to DMARQ, with more operator responsibility.',
                privacy_first: 'Prefer privacy-focused paths while allowing clearly described managed components.',
                balanced: 'Rank reliable options by both data path and maintenance effort.',
                convenience_first: 'Prefer fewer moving parts while still explaining who processes report data.',
                not_sure: 'DMARQ will compare the trade-offs before recommending an intake path.',
            };
            return descriptions[this.sovereigntyPreference] || descriptions.not_sure;
        },
        get setupStatusItems() {
            const state = this.setupState;
            return [
                {
                    id: 'domain',
                    label: 'Monitored domains',
                    complete: state.domains > 0,
                    detail: state.domains > 0
                        ? `${state.domains} domain${state.domains === 1 ? '' : 's'} configured`
                        : 'Add the first domain you want to monitor.',
                    href: '/domains',
                    action: state.domains > 0 ? 'Review domains' : 'Add a domain',
                },
                {
                    id: 'source',
                    label: 'Report mailbox',
                    complete: state.healthySources > 0,
                    detail: state.sources === 0
                        ? 'No Gmail or IMAP source is connected.'
                        : state.healthySources > 0
                            ? `${state.healthySources} enabled source${state.healthySources === 1 ? '' : 's'} ready`
                            : `${state.sources} source${state.sources === 1 ? '' : 's'} need attention`,
                    href: '/mail-sources',
                    action: state.sources === 0 ? 'Connect mailbox' : 'Review mail sources',
                },
                {
                    id: 'reports',
                    label: 'DMARC evidence',
                    complete: state.reports > 0,
                    detail: state.reports > 0
                        ? `${state.reports} aggregate report${state.reports === 1 ? '' : 's'} imported`
                        : 'Import reports before acting on sender or policy guidance.',
                    href: state.sources > 0 ? '/mail-sources' : '/upload',
                    action: state.sources > 0 ? 'Import reports' : 'Choose import method',
                },
                {
                    id: 'dns',
                    label: 'DNS provider',
                    complete: state.dnsProviderConnected,
                    detail: state.dnsProviderConnected
                        ? 'A provider connection is available for read or repair workflows.'
                        : 'Optional: connect a provider for verified previews and approved changes.',
                    href: '/settings#provider-integrations',
                    action: state.dnsProviderConnected ? 'Review provider' : 'Connect provider',
                    optional: true,
                },
                {
                    id: 'notifications',
                    label: 'Notifications',
                    complete: state.notificationsConfigured,
                    detail: state.notificationsConfigured
                        ? 'Operator notifications are configured.'
                        : 'Optional: add a notification target after report intake works.',
                    href: '/settings#notification-settings',
                    action: state.notificationsConfigured ? 'Review notifications' : 'Configure notifications',
                    optional: true,
                },
            ];
        },
        get firstRequiredSetupAction() {
            return this.setupStatusItems.find(item => !item.complete && !item.optional) || null;
        },
        get setupPrimaryHref() {
            return this.firstRequiredSetupAction?.href || '/';
        },
        get setupPrimaryLabel() {
            return this.firstRequiredSetupAction?.action || 'Open dashboard';
        },
        get setupHeadline() {
            if (this.firstRequiredSetupAction) return 'Continue setup';
            return 'Core monitoring is ready';
        },
        get setupSummary() {
            if (this.firstRequiredSetupAction) {
                return `${this.firstRequiredSetupAction.label} is the next required step.`;
            }
            return 'Domains, report intake, and DMARC evidence are available. Optional integrations can be configured when needed.';
        },
        get hasUnsavedDraft() {
            return this.draftDirty;
        },
        get showWorkspaceSwitchSuccess() {
            return this.multiWorkspaceUiEnabled && Boolean(this.result?.workspace);
        },
        get resultWorkspaceName() {
            return this.result?.workspace?.name || '';
        },
        get showImapFields() {
            return this.form.mailSourcePath === 'imap';
        },
        get showDnsOnlyNotice() {
            return this.form.mailSourcePath === 'dns_only';
        },
        get imapButtonClass() {
            return this.showImapFields ? 'btn-primary' : 'btn-outline';
        },
        get dnsOnlyButtonClass() {
            return this.showDnsOnlyNotice ? 'btn-primary' : 'btn-outline';
        },
        get taskPreviewLabel() {
            return this.tasks.length
                ? `${this.tasks.length} task${this.tasks.length === 1 ? '' : 's'}`
                : 'No preview yet';
        },
        get showNoTasks() {
            return this.tasks.length === 0;
        },
        get currentPreviewSignature() {
            return this.previewSignature();
        },
        get hasCurrentPreview() {
            return Boolean(this.lastPreviewSignature && this.lastPreviewSignature === this.currentPreviewSignature);
        },
        get canApplySetup() {
            return this.hasCurrentPreview && this.tasks.length > 0;
        },
        get applyButtonLabel() {
            if (this.applying) return this.multiWorkspaceUiEnabled ? 'Creating workspace...' : 'Applying setup...';
            if (!this.canApplySetup) return 'Preview first';
            return this.multiWorkspaceUiEnabled ? 'Create workspace' : 'Apply setup';
        },
        get applyDisabledReason() {
            if (this.canApplySetup) return '';
            if (this.lastPreviewSignature) return 'Preview the updated form before applying setup.';
            return 'Preview setup tasks before applying changes.';
        },
        init() {
            if (this.initialized) return;
            this.initialized = true;
            const flag = this.$el?.dataset?.multiWorkspaceUi;
            if (flag === 'true' || flag === 'false') {
                this.multiWorkspaceUiEnabled = flag === 'true';
            }
            this.guidedMailHealthUiAvailable = this.$el?.dataset?.guidedMailHealthUi === 'true';
            this.draftDirty = localStorage.getItem('dmarq.onboarding.draftDirty') === 'true';
            this.draftFields().forEach((field) => {
                const storedValue = localStorage.getItem(`dmarq.onboarding.${field}`);
                if (storedValue !== null) {
                    this.form[field] = storedValue;
                }
                this.$watch(`form.${field}`, () => {
                    this.draftDirty = true;
                    this.persistDraft();
                });
            });
            this.bindControls();
            this.loadSetupState();
            this.loadGuidanceProfile();
        },
        bindControls() {
            const root = this.$root;
            root?.addEventListener('submit', (event) => {
                if (!(event.target instanceof Element)) return;
                if (!event.target.matches('[data-onboarding-form]')) return;
                event.preventDefault();
                this.previewPlan();
            });
            root?.addEventListener('click', (event) => {
                if (!(event.target instanceof Element)) return;
                const previewButton = event.target.closest('[data-onboarding-preview]');
                if (previewButton && root.contains(previewButton)) {
                    this.previewPlan();
                    return;
                }
                const applyButton = event.target.closest('[data-onboarding-apply]');
                if (applyButton && root.contains(applyButton)) {
                    this.applyPlan();
                    return;
                }
                const pathButton = event.target.closest('[data-onboarding-mail-path]');
                if (pathButton) {
                    this.form.mailSourcePath = pathButton.getAttribute('data-onboarding-mail-path') || 'imap';
                    return;
                }
                const reconfigureButton = event.target.closest('[data-onboarding-reconfigure]');
                if (reconfigureButton && root.contains(reconfigureButton)) {
                    this.configuring = true;
                }
                const guidanceEditButton = event.target.closest('[data-guidance-edit]');
                if (guidanceEditButton && root.contains(guidanceEditButton)) {
                    this.editingGuidance = true;
                    if (this.guidanceInterviewCompleted) this.interviewStep = 1;
                }
            });
        },
        async loadSetupState() {
            if (!this.singleUserMode) {
                this.setupStateLoading = false;
                this.setupStateLoaded = true;
                return;
            }
            this.setupStateLoading = true;
            this.setupStateError = '';
            try {
                const [domainResponse, sourceResponse, providerResponse, notificationResponse] = await Promise.all([
                    fetch('/api/v1/domains/summary?include_empty=true'),
                    fetch('/api/v1/mail-sources'),
                    fetch('/api/v1/domains/dns/providers'),
                    fetch('/api/v1/settings/notifications.apprise_enabled'),
                ]);
                if (!domainResponse.ok || !sourceResponse.ok) {
                    throw new Error('Core setup status could not be loaded.');
                }
                const domains = await domainResponse.json();
                const sources = await sourceResponse.json();
                const providers = providerResponse.ok ? await providerResponse.json() : {};
                const notifications = notificationResponse.ok ? await notificationResponse.json() : {};
                const providerList = Array.isArray(providers.providers) ? providers.providers : [];
                const sourceList = Array.isArray(sources) ? sources : [];
                this.setupState = {
                    domains: Number(domains.total_domains || 0),
                    reports: Number(domains.reports_processed || 0),
                    sources: sourceList.length,
                    healthySources: sourceList.filter(source => (
                        source.enabled && !source.connection_attention && source.connection_status !== 'reauth_required'
                    )).length,
                    dnsProviderConnected: providerList.some(provider => (
                        provider.credentials_configured || provider.connection_status === 'connected'
                    )),
                    notificationsConfigured: ['true', '1', 'yes', 'on'].includes(
                        String(notifications.value || '').trim().toLowerCase()
                    ),
                };
            } catch (error) {
                this.setupStateError = error.message || 'Setup status could not be loaded.';
            } finally {
                this.setupStateLoading = false;
                this.setupStateLoaded = true;
            }
        },
        async loadGuidanceProfile() {
            if (!this.guidedMailHealthUiAvailable || !this.singleUserMode) return;
            try {
                const response = await fetch('/api/v1/workspaces/guidance');
                if (!response.ok) return;
                const data = await response.json();
                this.guidanceInterviewCompleted = Boolean(data.interview_completed);
                this.guidanceDepth = data.depth || 'guided';
                this.installationGoals = Array.isArray(data.installation_goals)
                    ? data.installation_goals.filter(goal => Boolean(this.guidanceUiGoals[goal]))
                    : [];
                this.selectedGoal = this.guidedGoalForProfile(data);
                if (!this.installationGoals.length && this.selectedGoal) {
                    this.installationGoals = [this.guidanceGoalIds[this.selectedGoal]];
                }
                this.sovereigntyPreference = data.sovereignty_preference || 'not_sure';
                this.notificationPosture = data.notification_posture || 'actionable_only';
                this.mailContext = data.mail_context && typeof data.mail_context === 'object'
                    ? data.mail_context
                    : {};
                this.interviewStep = Number(this.mailContext.interview_step || 1);
                this.interviewDomain = Array.isArray(this.mailContext.domains)
                    ? String(this.mailContext.domains[0] || '')
                    : '';
                this.interviewControlsDns = typeof this.mailContext.controls_dns === 'boolean'
                    ? String(this.mailContext.controls_dns)
                    : '';
                this.interviewDomainSendsMail = typeof this.mailContext.domain_sends_mail === 'boolean'
                    ? String(this.mailContext.domain_sends_mail)
                    : '';
                this.interviewBounceAvailable = Boolean(this.mailContext.bounce_available);
                this.interviewLowVolume = Boolean(this.mailContext.low_volume);
                this.interviewRecipientProvider = this.mailContext.symptom_recipient_provider || '';
                this.interviewFirstObserved = this.mailContext.symptom_first_observed || '';
                await this.loadDiagnosticPlan();
            } catch (_) {
                // The setup path remains usable when optional guidance is unavailable.
            }
        },
        guidedGoalForProfile(data) {
            const legacyGoal = data && typeof data.goal === 'string' ? data.goal : '';
            const primaryGoal = data && Array.isArray(data.installation_goals)
                ? data.installation_goals[0]
                : '';
            const profileGoal = primaryGoal || this.guidanceGoalIds[legacyGoal] || legacyGoal;
            return this.guidanceUiGoals[profileGoal] || '';
        },
        isSecondaryGoalSelected(goal) {
            return this.installationGoals.slice(1).some(
                profileGoal => this.guidanceUiGoals[profileGoal] === goal
            );
        },
        async toggleSecondaryGoal(goal) {
            if (this.savingGoal || !this.selectedGoal) return;
            const profileGoal = this.guidanceGoalIds[goal];
            if (!profileGoal) return;
            const primaryGoal = this.installationGoals[0] || this.guidanceGoalIds[this.selectedGoal];
            const secondaryGoals = this.installationGoals.slice(1).filter(item => item !== profileGoal);
            if (!this.isSecondaryGoalSelected(goal)) secondaryGoals.push(profileGoal);
            this.installationGoals = [primaryGoal, ...secondaryGoals];
            await this.saveWorkspaceGuidanceProfile(false, false);
        },
        async saveGoal(goal) {
            if (this.savingGoal) return;
            this.savingGoal = true;
            this.goalError = '';
            this.goalSaved = false;
            try {
                const preference = await this.savePersonalGuidancePreference();
                const previousGoals = [...this.installationGoals];
                const preserveSpecialistGoal = this.selectedGoal === goal && previousGoals.length > 0;
                this.selectedGoal = goal;
                if (!preserveSpecialistGoal) {
                    const primaryGoal = this.guidanceGoalIds[goal];
                    this.installationGoals = [
                        primaryGoal,
                        ...previousGoals.filter(item => this.guidanceUiGoals[item] !== goal),
                    ];
                }
                this.guidanceDepth = preference.depth || this.guidanceDepth;
                await this.saveWorkspaceGuidanceProfile(true, false);
                this.goalSaved = true;
            } catch (error) {
                this.goalError = error.message || 'Your setup goal could not be saved.';
            } finally {
                this.savingGoal = false;
            }
        },
        async savePersonalGuidancePreference() {
            const preferenceResponse = await fetch('/api/v1/workspaces/guidance/preferences', {
                method: 'PUT',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    depth: this.guidanceDepth,
                    context: 'watch',
                    teaching_hints_enabled: this.guidanceDepth === 'guided',
                }),
            });
            const preference = await preferenceResponse.json().catch(() => ({}));
            if (!preferenceResponse.ok) {
                throw new Error(preference.detail || 'Your explanation preference could not be saved.');
            }
            this.guidanceDepth = preference.depth || this.guidanceDepth;
            return preference;
        },
        async continueGoalInterview() {
            if (!this.selectedGoal) return;
            await this.advanceInterview(2);
        },
        interviewMailContext() {
            const context = {...this.mailContext};
            context.interview_step = this.interviewStep;
            if (this.interviewDomain.trim()) context.domains = [this.normalizeDomain(this.interviewDomain)];
            else delete context.domains;
            if (['true', 'false'].includes(this.interviewControlsDns)) {
                context.controls_dns = this.interviewControlsDns === 'true';
            } else delete context.controls_dns;
            if (['true', 'false'].includes(this.interviewDomainSendsMail)) {
                context.domain_sends_mail = this.interviewDomainSendsMail === 'true';
            } else delete context.domain_sends_mail;
            context.bounce_available = Boolean(this.interviewBounceAvailable);
            context.low_volume = Boolean(this.interviewLowVolume);
            if (this.interviewRecipientProvider.trim()) {
                context.symptom_recipient_provider = this.interviewRecipientProvider.trim();
            } else delete context.symptom_recipient_provider;
            if (this.interviewFirstObserved) context.symptom_first_observed = this.interviewFirstObserved;
            else delete context.symptom_first_observed;
            return context;
        },
        async saveWorkspaceGuidanceProfile(throwOnFailure, completed) {
            throwOnFailure = throwOnFailure === true;
            if (typeof completed !== 'boolean') completed = this.guidanceInterviewCompleted;
            if (!this.selectedGoal) return;
            const installationGoals = this.installationGoals.filter(goal => Boolean(this.guidanceUiGoals[goal]));
            if (!installationGoals.length) {
                const selectedGoal = this.guidanceGoalIds[this.selectedGoal];
                if (!selectedGoal) return;
                installationGoals.push(selectedGoal);
            }
            try {
                const response = await fetch('/api/v1/workspaces/guidance/workspace-profile', {
                    method: 'PUT',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        installation_goals: installationGoals,
                        sovereignty_preference: this.sovereigntyPreference,
                        notification_posture: this.notificationPosture,
                        mail_context: this.interviewMailContext(),
                        interview_version: 1,
                        interview_completed: completed,
                    }),
                });
                const data = await response.json().catch(() => ({}));
                if (!response.ok) throw new Error(data.detail || 'Your setup preferences could not be saved.');
                this.guidanceInterviewCompleted = Boolean(data.interview_completed);
                this.mailContext = data.mail_context && typeof data.mail_context === 'object'
                    ? data.mail_context
                    : this.interviewMailContext();
                this.installationGoals = Array.isArray(data.installation_goals)
                    ? data.installation_goals.filter(goal => Boolean(this.guidanceUiGoals[goal]))
                    : installationGoals;
                this.sovereigntyPreference = data.sovereignty_preference || this.sovereigntyPreference;
            } catch (error) {
                this.goalError = error.message || 'Your setup preferences could not be saved.';
                if (throwOnFailure) throw error;
            }
        },
        async advanceInterview(nextStep) {
            if (this.savingGoal) return;
            this.savingGoal = true;
            this.goalError = '';
            try {
                this.interviewStep = Math.min(4, Math.max(1, Number(nextStep) || 1));
                await this.saveWorkspaceGuidanceProfile(true, false);
            } catch (error) {
                this.goalError = error.message || 'Your setup progress could not be saved.';
            } finally {
                this.savingGoal = false;
            }
        },
        async finishInterview() {
            if (this.savingGoal || !this.selectedGoal) return;
            this.savingGoal = true;
            this.goalError = '';
            try {
                this.interviewStep = 4;
                await this.savePersonalGuidancePreference();
                await this.saveWorkspaceGuidanceProfile(true, true);
                this.editingGuidance = false;
                this.goalSaved = true;
                await this.loadDiagnosticPlan();
            } catch (error) {
                this.goalError = error.message || 'Your diagnostic plan could not be saved.';
            } finally {
                this.savingGoal = false;
            }
        },
        async loadDiagnosticPlan() {
            if (!this.guidedMailHealthUiAvailable || !this.singleUserMode) return;
            this.diagnosticPlanLoading = true;
            this.diagnosticPlanError = '';
            try {
                const response = await fetch('/api/v1/workspaces/guidance/diagnostic-plan');
                const data = await response.json().catch(() => ({}));
                if (!response.ok) throw new Error(data.detail || 'Your next step could not be loaded.');
                this.diagnosticPlan = data;
                if (!this.interviewDomain && data.domain) this.interviewDomain = data.domain;
            } catch (error) {
                this.diagnosticPlanError = error.message || 'Your next step could not be loaded.';
            } finally {
                this.diagnosticPlanLoading = false;
            }
        },
        draftFields() {
            return [
                'organizationName',
                'workspaceName',
                'workspaceDescription',
                'domain',
                'dnsProvider',
                'reportMailbox',
                'mailSourcePath',
                'imapServer',
                'imapUsername',
            ];
        },
        normalizeDomain(value) {
            return value.trim().replace(/^\.+|\.+$/g, '').toLowerCase();
        },
        payload() {
            const domain = this.normalizeDomain(this.form.domain);
            const fallbackName = domain || 'Default workspace';
            const workspaceName = this.singleUserMode
                ? fallbackName
                : this.form.workspaceName.trim() || this.form.organizationName.trim() || fallbackName;
            const organizationName = this.singleUserMode
                ? workspaceName
                : this.form.organizationName.trim() || workspaceName;
            const reportMailbox = this.form.reportMailbox.trim() || (domain ? `dmarc@${domain}` : '');
            const templateId = this.form.mailSourcePath === 'dns_only' ? 'dns_only_assessment' : 'standard_monitoring';
            const variables = {
                domain,
                workspace_name: workspaceName,
                dns_provider: this.form.dnsProvider,
                report_mailbox: reportMailbox,
            };
            if (templateId === 'standard_monitoring') {
                variables.imap_server = this.form.imapServer.trim();
                variables.imap_username = this.form.imapUsername.trim() || reportMailbox;
                variables.imap_password = this.form.imapPassword;
            }
            return {
                template_id: templateId,
                organization: { name: organizationName },
                workspace: {
                    name: workspaceName,
                    description: this.form.workspaceDescription.trim() || null,
                },
                variables,
            };
        },
        previewSignature() {
            return JSON.stringify(this.payload());
        },
        validate() {
            if (!this.normalizeDomain(this.form.domain)) {
                throw new Error('Domain is required.');
            }
            if (
                this.multiWorkspaceUiEnabled &&
                !this.form.workspaceName.trim() &&
                !this.form.organizationName.trim()
            ) {
                throw new Error('Organization or workspace name is required.');
            }
        },
        async previewPlan() {
            await this.submit('/api/v1/onboarding/preview', 'preview');
        },
        async applyPlan() {
            if (!this.canApplySetup) {
                this.error = this.applyDisabledReason;
                return;
            }
            await this.submit('/api/v1/onboarding/apply', 'apply');
        },
        async submit(url, mode) {
            this.error = '';
            this.success = '';
            this.result = null;
            try {
                this.validate();
            } catch (err) {
                this.error = err.message;
                return;
            }
            this.previewing = mode === 'preview';
            this.applying = mode === 'apply';
            try {
                const response = await fetch(url, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(this.payload()),
                });
                const data = await response.json().catch(() => ({}));
                if (!response.ok) {
                    throw new Error(this.errorMessage(data.detail) || 'Onboarding request failed.');
                }
                if (mode === 'preview') {
                    this.plan = data.plan;
                    this.tasks = this.normalizeTasks(data.plan?.tasks);
                    this.lastPreviewSignature = this.currentPreviewSignature;
                    this.success = this.singleUserMode
                        ? 'Preview is ready. Review the task list before applying setup.'
                        : 'Preview is ready. Review the task list before creating the workspace.';
                } else {
                    this.result = data.result;
                    this.tasks = this.normalizeTasks(data.result?.tasks);
                    this.success = this.singleUserMode
                        ? 'Mail health setup was applied.'
                        : 'Workspace onboarding was applied.';
                    this.persistAppliedWorkspace(data.result);
                    this.draftDirty = false;
                    await this.loadSetupState();
                }
                this.persistDraft();
            } catch (err) {
                this.error = err.message || 'Onboarding request failed.';
            } finally {
                this.previewing = false;
                this.applying = false;
            }
        },
        errorMessage(detail) {
            if (Array.isArray(detail)) {
                return detail.join(', ');
            }
            if (detail && typeof detail === 'object') {
                if (detail.errors) return this.errorMessage(detail.errors);
                if (detail.message) return detail.message;
                return JSON.stringify(detail);
            }
            return detail || '';
        },
        normalizeTasks(tasks) {
            return (tasks || []).map((task) => ({
                ...task,
                url: task.href || '#',
            }));
        },
        persistAppliedWorkspace(result) {
            if (!this.multiWorkspaceUiEnabled) return;
            const workspaceId = result?.workspace?.id;
            if (!workspaceId) return;
            localStorage.setItem('dmarq.selectedWorkspaceId', String(workspaceId));
            window.dispatchEvent(new CustomEvent('dmarq:workspace-changed', {
                detail: { workspaceId: String(workspaceId) },
            }));
        },
        persistDraft() {
            this.draftFields().forEach((field) => {
                localStorage.setItem(`dmarq.onboarding.${field}`, this.form[field] || '');
            });
            localStorage.setItem('dmarq.onboarding.draftDirty', String(this.draftDirty));
        },
    };
}

if (typeof document !== 'undefined') {
    document.addEventListener('alpine:init', () => {
        Alpine.data('workspaceOnboarding', workspaceOnboarding);
    });
}
