import json
import re
import shutil
import subprocess
import textwrap
from html.parser import HTMLParser
from pathlib import Path

import pytest
from jinja2 import Environment, FileSystemLoader, select_autoescape


def _read_project_file(*parts: str) -> str:
    return (Path(__file__).resolve().parents[1].joinpath(*parts)).read_text()


def _render_template(name: str, **context: object) -> str:
    template_dir = Path(__file__).resolve().parents[1] / "templates"
    env = Environment(
        loader=FileSystemLoader(template_dir),
        autoescape=select_autoescape(("html", "xml")),
    )
    return env.get_template(name).render(**context)


def _has_script_src(markup: str, src: str) -> bool:
    return bool(
        re.search(
            rf"<script\b(?=[^>]*\ssrc=[\"']{re.escape(src)}[\"'])[^>]*>",
            markup,
            re.IGNORECASE,
        )
    )


def _has_inline_script(markup: str) -> bool:
    return bool(re.search(r"<script\b(?![^>]*\ssrc\s*=)[^>]*>", markup, re.IGNORECASE))


class _InlineStyleDetector(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.has_inline_style = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        inline_style_attrs = {"style", ":style", "x-bind:style"}
        if any(name.lower() in inline_style_attrs for name, _value in attrs):
            self.has_inline_style = True

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)


def _has_inline_style(markup: str) -> bool:
    parser = _InlineStyleDetector()
    parser.feed(markup)
    return parser.has_inline_style


TEMPLATE_DIR = Path(__file__).resolve().parents[1] / "templates"
ALL_TEMPLATE_NAMES = tuple(
    sorted(str(path.relative_to(TEMPLATE_DIR)) for path in TEMPLATE_DIR.rglob("*.html"))
)


def _template_section_between_markers(template: str, start_marker: str, end_marker: str) -> str:
    start_match = re.search(rf"^[ \t]*{re.escape(start_marker)}", template, re.MULTILINE)
    assert start_match, f"{start_marker!r} marker missing from template"
    section = template[start_match.start() :]
    end_match = re.search(rf"^[ \t]*{re.escape(end_marker)}", section, re.MULTILINE)
    assert end_match, f"{end_marker!r} marker missing after {start_marker!r}"
    return section[: end_match.start()]


def _has_alpine_handler_call(template: str, event: str, function_name: str) -> bool:
    return bool(
        re.search(
            rf"@{re.escape(event)}(?:\.[\w:-]+)*\s*=\s*(['\"])\s*{re.escape(function_name)}\s*\(\s*\)\s*\1",
            template,
        )
    )


@pytest.mark.parametrize("template_name", ALL_TEMPLATE_NAMES)
def test_templates_do_not_reintroduce_csp_blocking_inline_markup(template_name: str):
    template = _read_project_file("templates", *template_name.split("/"))

    assert not _has_inline_script(template)
    assert not _has_inline_style(template)
    assert "x-html" not in template


def _dashboard_template() -> str:
    return _read_project_file("templates", "index.html")


def _dashboard_script() -> str:
    return _read_project_file("static", "js", "dashboard-page.js")


def _mail_sources_template() -> str:
    return _read_project_file("templates", "mail_sources.html")


def _mail_sources_script() -> str:
    return _read_project_file("static", "js", "mail-sources-page.js")


def _run_dashboard_script(runner_body: str, *args: str) -> str:
    node = shutil.which("node")
    if not node:
        pytest.skip("node is required to execute dashboard-page.js behavior tests")

    script_path = Path(__file__).resolve().parents[1] / "static" / "js" / "dashboard-page.js"
    runner = textwrap.dedent(f"""
        const fs = require('fs');
        const script = fs.readFileSync(process.argv[1], 'utf8');
        const dashboardAppFactory = new Function(`${{script}}\\nreturn dashboardApp;`)();
        {runner_body}
        """)
    result = subprocess.run(
        [node, "-e", runner, str(script_path), *args],
        check=True,
        text=True,
        capture_output=True,
    )
    return result.stdout


def _run_dashboard_poll_summary(payload: dict[str, object]) -> str:
    runner_body = """
        const payload = JSON.parse(process.argv[2]);
        process.stdout.write(dashboardAppFactory().summarizePollResults(payload));
        """
    return _run_dashboard_script(runner_body, json.dumps(payload))


def _run_dashboard_expression(expression: str) -> str:
    runner_body = """
        const expression = process.argv[2];
        const app = dashboardAppFactory();
        process.stdout.write(String(new Function('app', `return ${expression};`)(app)));
        """
    return _run_dashboard_script(runner_body, expression)


def _operations_template() -> str:
    return _read_project_file("templates", "operations.html")


def _operations_script() -> str:
    return _read_project_file("static", "js", "operations-page.js")


def _provider_demo_template() -> str:
    return _read_project_file("templates", "provider_demo.html")


def _provider_demo_script() -> str:
    return _read_project_file("static", "js", "provider-demo-page.js")


def _reports_template() -> str:
    return _read_project_file("templates", "reports.html")


def _reports_script() -> str:
    return _read_project_file("static", "js", "reports-page.js")


def _legacy_login_script() -> str:
    return _read_project_file("static", "js", "login.js")


def _main_stylesheet() -> str:
    return _read_project_file("static", "css", "styles.css")


def _domains_template() -> str:
    return _read_project_file("templates", "domains.html")


def _domains_script() -> str:
    return _read_project_file("static", "js", "domains-page.js")


def _upload_template() -> str:
    return _read_project_file("templates", "upload.html")


def _upload_script() -> str:
    return _read_project_file("static", "js", "upload-page.js")


def _profile_template() -> str:
    return _read_project_file("templates", "profile.html")


def _profile_script() -> str:
    return _read_project_file("static", "js", "profile-page.js")


def _settings_template() -> str:
    return _read_project_file("templates", "settings.html")


def _settings_script() -> str:
    return _read_project_file("static", "js", "settings-page.js")


def _onboarding_template() -> str:
    return _read_project_file("templates", "onboarding.html")


def _onboarding_script() -> str:
    return _read_project_file("static", "js", "onboarding-page.js")


def _forensic_reports_template() -> str:
    return _read_project_file("templates", "forensic_reports.html")


def _forensic_reports_script() -> str:
    return _read_project_file("static", "js", "forensic-reports-page.js")


def _forensic_report_detail_template() -> str:
    return _read_project_file("templates", "forensic_report_detail.html")


def _forensic_report_detail_script() -> str:
    return _read_project_file("static", "js", "forensic-report-detail-page.js")


def _tls_reports_template() -> str:
    return _read_project_file("templates", "tls_reports.html")


def _tls_reports_script() -> str:
    return _read_project_file("static", "js", "tls-reports-page.js")


def _report_detail_template() -> str:
    return _read_project_file("templates", "report_detail.html")


def _report_detail_script() -> str:
    return _read_project_file("static", "js", "report-detail-page.js")


def _run_report_detail_expression(payload: dict[str, object], expression: str) -> object:
    node = shutil.which("node")
    if not node:
        pytest.skip("node is required to execute report-detail-page.js behavior tests")

    script_path = Path(__file__).resolve().parents[1] / "static" / "js" / "report-detail-page.js"
    runner = textwrap.dedent("""
        const fs = require('fs');
        const script = fs.readFileSync(process.argv[1], 'utf8');
        const reportDetailFactory = new Function(`${script}\nreturn reportDetailApp;`)();
        const app = reportDetailFactory('report-id');
        app.report = { records: JSON.parse(process.argv[2]) };
        const result = new Function('app', `return ${process.argv[3]};`)(app);
        process.stdout.write(JSON.stringify(result));
        """)
    result = subprocess.run(
        [node, "-e", runner, str(script_path), json.dumps(payload["records"]), expression],
        check=True,
        text=True,
        capture_output=True,
    )
    return json.loads(result.stdout)


def test_settings_cloudflare_oauth_uses_popup_with_full_window_fallback():
    template = _settings_template()
    script = _settings_script()

    assert "Request scopes:" in template
    assert "Cloudflare client permissions:" in template
    assert "selectedCloudflareOAuthDescription()" in template
    assert "selectedCloudflareOAuthScopes()" in template
    assert "selectedCloudflareOAuthHasWarning()" in template
    assert "selectedCloudflareOAuthPermissions()" in template
    assert "selectedCloudflareOAuthProfile()" in script
    assert "selectedCloudflareOAuthPermissions()" in script
    assert "selectedCloudflareOAuthDescription()" in script
    assert "selectedCloudflareOAuthScopes()" in script
    assert "selectedCloudflareOAuthHasWarning()" in script
    assert "Requesting Cloudflare OAuth scopes:" in script
    assert "window.open(" in script
    assert "'dmarq-cloudflare-oauth'" in script
    assert "popup=yes" in script
    assert "noopener,noreferrer" not in script
    assert "popup.opener = null" in script
    assert "window.location.href = data.authorization_url" in script
    assert "loadCloudflareOAuthStatus(true)" in script
    assert "Cloudflare status refresh failed:" in script


def _domain_details_template() -> str:
    return _read_project_file("templates", "domain_details.html")


def _domain_details_script() -> str:
    return _read_project_file("static", "js", "domain-details-page.js")


def test_dashboard_domain_table_uses_safe_dom_rendering():
    """Domain names and counts come from report data and must not be HTML-rendered."""
    script = _dashboard_script()
    populate_start = script.index("populateDomainsTable(domains)")
    helper_start = script.index("createDomainNameCell(domainName)")
    populate_body = script[populate_start:helper_start]

    assert "innerHTML" not in populate_body
    assert ".textContent" in populate_body
    assert "createDomainNameCell" in populate_body
    assert "createDetailsCell" in populate_body


def test_dashboard_domain_details_links_are_encoded():
    script = _dashboard_script()

    assert "encodeURIComponent(domainId)" in script


def test_dashboard_empty_state_leads_with_report_mailbox_without_hiding_upload():
    template = _dashboard_template()
    script = _dashboard_script()

    assert "Start by connecting your report mailbox" in template
    assert 'button_link(href="/mail-sources", variant="primary")' in template
    assert "Other import options" in template
    assert 'href="/upload"' in template
    assert ':disabled="triggerPollRunning || !hasEnabledMailSources"' in template
    assert 'class="btn btn-outline btn-sm w-full sm:w-auto"' in template
    assert "hasEnabledMailSources: false" in script
    assert "this.hasEnabledMailSources = (data.enabled_sources || 0) > 0" in script
    assert "hasReportData: false" in script
    assert "this.hasReportData = Number(data.total_reports || 0) > 0" in script
    assert "!hasReportData" in template
    assert "Report intake is the next step." in template


def test_dashboard_remediation_completion_avoids_csp_unsafe_optional_chaining():
    template = _dashboard_template()
    script = _dashboard_script()

    assert "?." not in template
    assert "??" not in template
    assert "remediationCompletion().next_step" in template
    assert "remediationCompletion()" in script
    assert "pathValue(source, path, fallback = null)" in script


def test_domain_details_nested_values_are_csp_safe_without_hiding_features():
    template = _domain_details_template()
    script = _domain_details_script()

    assert "?." not in template
    assert "??" not in template
    assert "pathValue(source, path, fallback = null)" in script
    assert "=>" not in template
    assert ".filter(Boolean)" not in template
    assert "pathValue(remediationQueue, 'loop.next_action'" in template
    assert "pathValue(migrationImport, 'preview.sample_rows', [])" in template
    assert "pathValue(source, 'geo.country_code', 'ZZ')" in template


def test_dashboard_exposes_workspace_health_history():
    template = _dashboard_template()
    script = _dashboard_script()

    assert "Score Trend" in template
    assert "health-trend-chart" in template
    assert "action.evidence" in template
    assert "item.label.replaceAll('_', ' ')" in template
    assert "/api/v1/domains/summary/health/history" in script
    assert "fetchWorkspaceHealthHistory" in script


def test_dashboard_remediation_cards_deep_link_to_domain_queue():
    template = _dashboard_template()
    script = _dashboard_script()

    assert ':href="domainActionHref(action)"' in template
    assert ':href="domainRemediationHref(item.domain)"' in template
    assert "Open remediation queue" in template
    assert "domainActionHref(action)" in script
    assert "domainRemediationHref(domainName)" in script
    assert "#remediation-queue" in script
    assert "encodeURIComponent(action.domain)" in script
    assert "encodeURIComponent(domainName)" in script


def test_dashboard_remediation_loop_uses_resolved_language():
    template = _dashboard_template()

    assert "Resolved" in template
    assert "Operator-marked resolved items" in template
    assert "remediationLoop().resolved || remediationLoop().fixed || 0" in template
    assert "Verified fixed" in template
    assert "Resolved items no longer observed" in template
    assert "remediationLoop().verified_fixed || 0" in template


def test_dashboard_remediation_cards_show_owner_and_completion_context():
    template = _dashboard_template()
    script = _dashboard_script()

    assert "Owner" in template
    assert "Done when" in template
    assert "Next verification" in template
    assert 'x-text="item.owner"' in template
    assert 'x-text="item.completion_criteria"' in template
    assert 'x-text="item.verification_next_check"' in template
    assert "remediationTrackLabel(item.remediation_track)" in template
    assert "remediationRiskClass(item.risk_level)" in template
    assert "item.priority_band || 'watch'" in template
    assert "item.operator_decision_summary" in template
    assert "Repair previews ready" in template
    assert "Notifications ready" in template
    assert "Operator notification profiles prepared" in template
    assert "remediationLoop().notification_profile_ready || 0" in template
    assert "remediationLoop().notification_approval_required || 0" in template
    assert "remediationLoop().notification_action_required || 0" in template
    assert "manual action" in template
    assert "remediationLoop().notification_investigation_required || 0" in template
    assert "remediationLoop().notification_profiles || 0" in template
    assert "remediationLoop().notification_summary_only || 0" in template
    assert "Aging follow-up" in template
    assert "dashboardRemediationFilterCount('aging_follow_up')" in template
    assert "Need fresh evidence" in template
    assert "Waiting on operator" in template
    assert "Remediation loop completion" in template
    assert "remediationCompletionLabel(remediationLoop().completion)" in template
    assert "remediationCompletionClass(remediationLoop().completion)" in template
    assert "remediationCompletionLabel(completion)" in script
    assert "remediationCompletionClass(completion)" in script
    assert "Blocked before repair" in template
    assert "remediationLoop().next_action" in template
    assert (
        "remediationLoopStatusClass(remediationLoopEffectiveStatus(remediationLoop()))" in template
    )
    assert (
        "remediationLoopStatusLabel(remediationLoopEffectiveStatus(remediationLoop()))" in template
    )
    assert "remediationIncidentLabel(remediationLoop().top_incident_type)" in template
    assert "data-dashboard-refresh" in template
    assert "data-dashboard-refresh" in script
    assert "data-dashboard-remediation-refresh" in template
    assert "data-dashboard-remediation-refresh" in script
    assert "dashboardRemediationFilterOptions" in script
    assert "{ value: 'fresh_evidence', label: 'Fresh evidence' }" in script
    assert "{ value: 'approval_verification', label: 'Approval' }" in script
    assert "{ value: 'notify_ready', label: 'Ready to notify' }" in script
    assert "{ value: 'dispatched', label: 'Dispatched' }" in script
    assert "{ value: 'follow_up', label: 'Follow-up' }" in script
    assert "{ value: 'aging_follow_up', label: 'Aging follow-up' }" in script
    assert "{ value: 'dispatch_blocked', label: 'Dispatch blocked' }" in script
    assert "{ value: 'stuck', label: 'Stuck' }" in script
    assert "{ value: 'sender_review', label: 'Sender review' }" in script
    assert "{ value: 'report_evidence', label: 'Report evidence' }" in script
    assert "{ value: 'stale_evidence', label: 'Stale evidence' }" in script
    assert "dashboardRemediationSort: 'priority'" in script
    assert "showAllDashboardRemediationItems" in script
    assert "data-dashboard-remediation-sort" in template
    assert "data-dashboard-remediation-sort" in script
    assert '<option value="dispatch">Dispatch follow-up</option>' in template
    assert "data-dashboard-remediation-filter" in template
    assert "data-dashboard-remediation-filter" in script
    assert ':class="dashboardRemediationFilterClass(filter.value)"' in template
    assert ':title="dashboardRemediationFilterTitle(filter.value)"' in template
    assert ':aria-label="dashboardRemediationFilterTitle(filter.value)"' in template
    assert "formatLargeNumber(dashboardRemediationFilterCount(filter.value))" in template
    assert "dashboardRemediationFilterClass(filter)" in script
    assert "dashboardRemediationFilterTitle(filter)" in script
    assert "dashboardRemediationEmptyStateTitle()" in script
    assert "dashboardRemediationEmptyStateText()" in script
    assert "dashboardRemediationEmptyStateMeta()" in script
    assert "resetDashboardRemediationFilter()" in script
    assert "dashboardRemediationEmptyStateTitle()" in template
    assert "dashboardRemediationEmptyStateText()" in template
    assert "dashboardRemediationEmptyStateMeta()" in template
    assert "data-dashboard-remediation-reset-filter" in template
    assert "data-dashboard-remediation-reset-filter" in script
    assert '@click="resetDashboardRemediationFilter()"' not in template
    assert "Show all remediation cards" in template
    assert "dashboardRemediationNextActionText(item)" in script
    assert "dashboardRemediationStuckText(item)" in script
    assert "dashboardRemediationFollowUpAgeText(item)" in script
    assert "dashboardRemediationFollowUpAgeClass(item)" in script
    assert "dashboardRemediationFollowUpAgeDays(item)" in script
    assert "relativeAgeText(value)" in script
    assert "Next action:" in template
    assert "dashboardRemediationFollowUpAgeText(item)" in template
    assert ':class="dashboardRemediationFollowUpAgeClass(item)"' in template
    assert "dashboardRemediationFilterCounts()" in script
    assert "data-dashboard-remediation-toggle-all" in template
    assert "data-dashboard-remediation-toggle-all" in script
    assert "visibleDashboardRemediationItems()" in template
    assert "visibleDashboardRemediationItems()" in script
    assert "dashboardRemediationFilterCount(filter.value)" in template
    assert "dashboardRemediationFilteredCount()" in template
    assert "dashboardRemediationTotalCount()" in template
    assert "dashboardRemediationFilterLabel()" in template
    assert "dashboardRemediationHiddenCount()" in template
    assert "Show all matching cards" in template
    assert "Show compact cards" in template
    assert "Fresh evidence path" in template
    assert "evidenceRefreshLabel(workload.primary.evidence_refresh)" in script
    assert "Evidence: provider value required" in script
    assert "remediationRefreshRunning" in script
    assert "dashboardRefreshError" in script
    assert "Showing the previously loaded dashboard data." in script
    assert "fetchDomainSummary({ refresh: true })" in script
    assert "dashboardLoading = !refresh || !this.hasDomainData" in script
    assert "remediationRefreshRunning ? 'Refreshing...' : 'Refresh queue'" in template
    assert "Dashboard refresh failed" in template
    assert "dashboardRefreshError && hasReportData" in template
    assert '@click="fetchDomainSummary()"' not in template
    assert "domainSummaryLoadedAt" in script
    assert "domainSummaryLoadedAtLabel" in script
    assert "domainSummaryLoadedAtLabel" in template
    assert "No active remediation work queued" in template
    assert "Keep importing reports and refreshing DNS evidence" in template
    assert 'x-show="!hasRemediationLoopItems()"' in template
    assert (
        "remediationLoop().repair_ready_for_preview || remediationLoop().repair_preview_ready || 0"
        in template
    )
    assert "remediationLoop().provider_preview_available || 0" in template
    assert "remediationLoop().provider_apply_after_approval || 0" in template
    assert "remediationLoop().provider_apply_history || 0" in template
    assert "remediationLoop().provider_apply_verified || 0" in template
    assert "Dispatch activity" in template
    assert "remediationLoop().dispatch_enqueued || 0" in template
    assert "remediationLoop().operator_follow_up || 0" in template
    assert "domains need follow-up" in template
    assert "remediationLoop().repair_needs_evidence || 0" in template
    assert "remediationLoop().repair_waiting_on_operator || 0" in template
    assert (
        "remediationLoop().repair_readiness_blocked || remediationLoop().repair_blocked || 0"
        in template
    )
    assert "remediationLoop().provider_apply_blocked || 0" in template
    assert "remediationLoop().verification_pending_operator_approval || 0" in template
    assert "remediationLoop().verification_pending_report_evidence || 0" in template
    assert "remediationLoop().verification_pending_sender_review || 0" in template
    assert "remediationLoop().verification_pending_reputation_review || 0" in template
    assert "remediationLoop().verification_blocked_by_prerequisite || 0" in template
    assert "provider values required" in template
    assert "Repair gate" in template
    assert "repairProgressionClass(item.repair_progression)" in template
    assert "repairProgressionLabel(item.repair_progression)" in template
    assert "repairProgressionNextStep(item.repair_progression)" in template
    assert "repairProgressionNextSafeAction(item.repair_progression)" in template
    assert "repairReadinessReason(item.repair_progression)" in template
    assert "repairReadinessBlockedText(item.repair_progression)" in template
    assert "Next safe action" in template
    assert "pathValue(item, 'verification_plan.freshness_requirement'" in template
    assert "pathValue(item, 'verification_plan.closure_gate'" in template
    assert "verificationPlanStatusClass(item.verification_plan)" in template
    assert "verificationPlanStatusLabel(item.verification_plan)" in template
    assert "verificationPlanFailureMode(item.verification_plan)" in template
    assert "verificationPlanEvidenceNeededText(item.verification_plan)" in template
    assert "dashboardRemediationDispatchText(item)" in template
    assert "dashboardRemediationDispatchRank(item)" in script
    assert "dashboardRemediationActivity(item)" in script
    assert "repairReadinessClass(item.repair_progression)" in template
    assert "repairReadinessLabel(item.repair_progression)" in template
    assert "repairReadinessScore(item.repair_progression)" in template
    assert "remediationRiskClass(risk)" in script
    assert "remediationTrackLabel(track)" in script
    assert "remediationLoopStatusLabel(status)" in script
    assert "remediationLoopStatusClass(status)" in script
    assert "remediationLoopEffectiveStatus(loop)" in script
    assert "approval_ready: 'Needs approval'" in script
    assert "state === 'approval_ready' || state === 'needs_approval'" in script
    assert "remediationIncidentLabel(value)" in script
    assert "remediationLoopItemRank(item)" in script
    assert "[...items].sort" in script
    assert "this.remediationLoopItemRank(a) - this.remediationLoopItemRank(b)" in script
    assert "dashboardRemediationFilterMatches(item, filterValue)" in script
    assert "verificationStatus === 'pending_operator_approval'" in script
    assert "{ value: 'provider_apply', label: 'Provider apply' }" in script
    assert "{ value: 'apply_blocked', label: 'Apply blocked' }" in script
    assert "{ value: 'provider_history', label: 'Provider history' }" in script
    assert "filterValue === 'provider_apply'" in script
    assert "filterValue === 'apply_blocked'" in script
    assert "filterValue === 'provider_history'" in script
    assert "progression.provider_apply_after_approval" in script
    assert "progression.provider_preview_available" in script
    assert "progression.provider_apply_blocked" in script
    assert "progression.provider_apply_history" in script
    assert "progression.provider_apply_verified" in script
    assert "verificationStatus === 'pending_sender_review'" in script
    assert "verificationStatus === 'pending_report_evidence'" in script
    assert "dashboardRemediationEvidenceRank(item)" in script
    assert "remediationSeverityWeight(severity)" in script
    assert "remediationStaleEvidenceText(item)" in script
    assert "domainEvidenceHref(item)" in script
    assert "rawAnchor.startsWith('#')" in script
    assert ':href="domainEvidenceHref(item)"' in template
    assert "Open evidence section" in template
    assert "repairProgressionClass(progression)" in script
    assert "repairProgressionLabel(progression)" in script
    assert "repairProgressionNextStep(progression)" in script
    assert "repairProgressionNextSafeAction(progression)" in script
    assert "repairReadinessReason(progression)" in script
    assert "repairReadinessBlockedText(progression)" in script
    assert "repairReadinessClass(progression)" in script
    assert "repairReadinessLabel(progression)" in script
    assert "repairReadinessScore(progression)" in script
    assert "verificationPlanStatusLabel(plan)" in script
    assert "pending_reputation_review: 'Reputation review'" in script
    assert "verificationPlanStatusClass(plan)" in script
    assert "verificationPlanFailureMode(plan)" in script
    assert "verificationPlanEvidenceNeededText(plan)" in script


def test_dashboard_remediation_filters_and_sorts_cards():
    result = _run_dashboard_expression("""(() => {
            app.healthSummary = { remediation_loop: { items: [
                {
                    domain: 'manual.example',
                    state: 'manual_action',
                    remediation_track: 'manual_dns',
                    priority_score: 5,
                    severity: 'low',
                    repair_progression: {
                        readiness_level: 'manual_repair',
                        readiness_score: 40
                    },
                    evidence_refresh: {
                        required: true,
                        refresh_key: 'dns',
                        safe_to_run: true
                    }
                },
                {
                    domain: 'blocked.example',
                    state: 'approval_ready',
                    remediation_track: 'blocked_by_prerequisite',
                    priority_score: 9,
                    severity: 'high',
                    repair_progression: {
                        readiness_level: 'blocked',
                        readiness_score: 10,
                        blocked_by: ['provider value'],
                        provider_apply_blocked: true,
                        provider_value_missing: true
                    },
                    evidence_refresh: {
                        required: true,
                        refresh_key: 'provider_value',
                        safe_to_run: false
                    },
                    verification_plan: { status: 'blocked_by_prerequisite' }
                },
                {
                    domain: 'reputation.example',
                    state: 'investigate',
                    remediation_track: 'reputation_review',
                    priority_score: 4,
                    severity: 'medium',
                    repair_progression: {
                        readiness_level: 'needs_reputation_review',
                        stage: 'reputation_review',
                        readiness_score: 30
                    },
                    evidence_refresh: {
                        required: true,
                        refresh_key: 'source_reputation',
                        safe_to_run: true
                    },
                    verification_plan: { status: 'pending_reputation_review' }
                },
                {
                    domain: 'approval.example',
                    state: 'needs_approval',
                    priority_score: 5,
                    severity: 'high',
                    repair_progression: {
                        readiness_level: 'ready_for_preview',
                        stage: 'preview_ready',
                        readiness_score: 90,
                        provider_preview_available: true,
                        provider_apply_after_approval: true,
                        provider_apply_blocked: false
                    },
                    evidence_refresh: {
                        required: true,
                        refresh_key: 'dns',
                        safe_to_run: true
                    },
                    verification_plan: { status: 'pending_operator_approval' }
                },
                {
                    domain: 'provider-history.example',
                    state: 'needs_approval',
                    priority_score: 7,
                    severity: 'medium',
                    repair_progression: {
                        readiness_level: 'ready_for_preview',
                        stage: 'preview_ready',
                        readiness_score: 85,
                        provider_preview_available: true,
                        provider_apply_after_approval: false,
                        provider_apply_blocked: false,
                        provider_apply_history: 1,
                        provider_apply_verified: 1
                    },
                    verification_plan: { status: 'pending_operator_approval' }
                },
                {
                    domain: 'sender.example',
                    state: 'investigate',
                    remediation_track: 'sender_classification',
                    priority_score: 3,
                    severity: 'medium',
                    repair_progression: {
                        readiness_level: 'needs_classification',
                        stage: 'classification_required',
                        readiness_score: 20
                    },
                    verification_plan: { status: 'pending_sender_review' }
                },
                {
                    domain: 'report.example',
                    state: 'manual_action',
                    remediation_track: 'manual_dns',
                    priority_score: 2,
                    severity: 'low',
                    repair_progression: {
                        readiness_level: 'manual_repair',
                        stage: 'manual_repair',
                        readiness_score: 45
                    },
                    verification_plan: { status: 'pending_report_evidence' }
                },
                {
                    domain: 'dispatch.example',
                    state: 'manual_action',
                    remediation_track: 'manual_dns',
                    priority_score: 8,
                    severity: 'high',
                    repair_progression: {
                        readiness_level: 'manual_repair',
                        stage: 'operator_review',
                        readiness_score: 50
                    },
                    verification_plan: { status: 'pending_report_evidence' },
                    notification: {
                        dispatch: {
                            enabled: true,
                            eligible: false,
                            blocked_reasons: [
                                'No enabled webhook endpoint is subscribed to this event.'
                            ]
                        }
                    }
                }
            ] } };
            app.domains = [
                {
                    domain_name: 'dispatch.example',
                    remediation: {
                        dispatch_enqueued: 2,
                        needs_operator_follow_up: true
                    }
                }
            ];
            app.dashboardRemediationFilter = 'fresh_evidence';
            app.dashboardRemediationSort = 'freshness';
            return [
                app.dashboardRemediationFilterCount('blocked'),
                app.dashboardRemediationFilterCount('reputation'),
                app.dashboardRemediationFilterCount('approval_verification'),
                app.dashboardRemediationFilterCount('provider_apply'),
                app.dashboardRemediationFilterCount('apply_blocked'),
                app.dashboardRemediationFilterCount('provider_history'),
                app.dashboardRemediationFilterCount('notify_ready'),
                app.dashboardRemediationFilterCount('dispatched'),
                app.dashboardRemediationFilterCount('follow_up'),
                app.dashboardRemediationFilterCount('dispatch_blocked'),
                app.dashboardRemediationFilterCount('sender_review'),
                app.dashboardRemediationFilterCount('report_evidence'),
                app.dashboardRemediationFilteredCount(),
                app.visibleDashboardRemediationItems()[0].domain
            ].join('|');
        })()""")

    assert result == "1|1|2|2|1|1|0|1|1|1|1|2|4|blocked.example"


def test_dashboard_remediation_dispatch_activity_filters_and_labels():
    result = _run_dashboard_expression("""(() => {
            app.healthSummary = { remediation_loop: { items: [
                {
                    domain: 'follow.example',
                    state: 'manual_action',
                    priority_score: 7,
                    severity: 'high',
                    notification: {
                        state: 'action_required',
                        dispatch: {
                            enabled: true,
                            eligible: false,
                            blocked_reasons: ['No enabled webhook endpoint is subscribed to this event.']
                        }
                    }
                },
                {
                    domain: 'ready.example',
                    state: 'needs_approval',
                    priority_score: 9,
                    severity: 'medium',
                    notification: { dispatch: { enabled: true, eligible: true } }
                },
                {
                    domain: 'profile.example',
                    state: 'needs_approval',
                    priority_score: 8,
                    severity: 'high',
                    notification: { state: 'approval_required' }
                },
                {
                    domain: 'blocked.example',
                    state: 'investigate',
                    priority_score: 6,
                    severity: 'medium',
                    notification: {
                        dispatch: {
                            enabled: true,
                            eligible: false,
                            blocked_reasons: [
                                'No enabled webhook endpoint is subscribed to this event.'
                            ]
                        }
                    }
                }
            ] } };
            app.domains = [
                {
                    domain_name: 'follow.example',
                    remediation: {
                        dispatch_enqueued: 3,
                        needs_operator_follow_up: true
                    }
                }
            ];
            app.dashboardRemediationFilter = 'follow_up';
            app.dashboardRemediationSort = 'dispatch';
            return [
                app.dashboardRemediationFilterCount('notify_ready'),
                app.dashboardRemediationFilterCount('dispatched'),
                app.dashboardRemediationFilterCount('follow_up'),
                app.dashboardRemediationFilterCount('dispatch_blocked'),
                app.visibleDashboardRemediationItems()[0].domain,
                app.dashboardRemediationDispatchText(app.visibleDashboardRemediationItems()[0]),
                app.dashboardRemediationDispatchText(app.healthSummary.remediation_loop.items[2])
            ].join('|');
        })()""")

    assert result == (
        "2|1|1|2|follow.example|"
        "3 notifications dispatched · operator follow-up needed · dispatch blocked|"
        "notification profile ready"
    )


def test_dashboard_remediation_dispatch_sort_prioritizes_old_follow_up():
    result = _run_dashboard_expression("""(() => {
            const nowMs = Date.parse('2026-07-06T09:00:00Z');
            const oldLatest = new Date(nowMs - (6 * 24 * 60 * 60 * 1000)).toISOString();
            const freshLatest = new Date(nowMs - (2 * 60 * 60 * 1000)).toISOString();
            app.healthSummary = { remediation_loop: { items: [
                { domain: 'fresh.example', state: 'needs_approval', priority_score: 10, severity: 'high' },
                { domain: 'old.example', state: 'needs_approval', priority_score: 3, severity: 'medium' }
            ] } };
            app.domains = [
                {
                    domain_name: 'fresh.example',
                    remediation: {
                        latest_at: freshLatest,
                        needs_operator_follow_up: true
                    }
                },
                {
                    domain_name: 'old.example',
                    remediation: {
                        latest_at: oldLatest,
                        needs_operator_follow_up: true
                    }
                }
            ];
            app.dashboardRemediationFilter = 'follow_up';
            app.dashboardRemediationSort = 'dispatch';
            return [
                app.visibleDashboardRemediationItems()[0].domain,
                app.visibleDashboardRemediationItems()[1].domain,
                app.dashboardRemediationFollowUpAgeMs(app.visibleDashboardRemediationItems()[0], nowMs) >
                    app.dashboardRemediationFollowUpAgeMs(app.visibleDashboardRemediationItems()[1], nowMs)
            ].join('|');
        })()""")

    assert result == "old.example|fresh.example|true"


def test_dashboard_remediation_filter_chips_explain_empty_states():
    result = _run_dashboard_expression("""(() => {
            app.healthSummary = { remediation_loop: { items: [
                {
                    domain: 'ready.example',
                    state: 'needs_approval',
                    priority_score: 9,
                    severity: 'medium',
                    repair_progression: { readiness_level: 'ready_for_preview' }
                }
            ] } };
            app.dashboardRemediationFilter = 'preview_ready';
            return [
                app.dashboardRemediationFilterClass('preview_ready'),
                app.dashboardRemediationFilterClass('reputation'),
                app.dashboardRemediationFilterClass('all'),
                app.dashboardRemediationFilterTitle('preview_ready'),
                app.dashboardRemediationFilterTitle('reputation'),
                app.dashboardRemediationFilterTitle('all')
            ].join('|');
        })()""")

    assert result == (
        "border-[#2f9da5] bg-[#f2fbf9] text-[#1f7c83]|"
        "border-[#ece9e7] bg-[#fbfaf9] text-[#9a96a8]|"
        "border-[#e6e3e1] bg-white text-[#5f5c78] hover:border-[#2f9da5]|"
        "1 preview ready remediation card|"
        "No reputation remediation cards in the current workspace summary|"
        "1 all remediation card"
    )


def test_dashboard_remediation_empty_state_copy_matches_selected_filter():
    result = _run_dashboard_expression("""(() => {
            app.healthSummary = { remediation_loop: { items: [
                {
                    domain: 'ready.example',
                    state: 'needs_approval',
                    priority_score: 9,
                    severity: 'medium',
                    repair_progression: { readiness_level: 'ready_for_preview' }
                }
            ] } };
            app.dashboardRemediationFilter = 'dispatch_blocked';
            return [
                app.hasVisibleDashboardRemediationItems(),
                app.dashboardRemediationEmptyStateTitle(),
                app.dashboardRemediationEmptyStateText(),
                app.dashboardRemediationEmptyStateMeta()
            ].join('|');
        })()""")

    assert result == (
        "false|No dispatch blocked remediation cards|"
        "No remediation notification is blocked by dispatch settings or webhook routing.|"
        "1 remediation card exists outside the Dispatch blocked view."
    )


def test_dashboard_remediation_empty_state_copy_has_default_fallback():
    result = _run_dashboard_expression("""(() => {
            app.dashboardRemediationFilter = 'unknown_future_filter';
            return [
                app.dashboardRemediationEmptyStateTitle(),
                app.dashboardRemediationEmptyStateText()
            ].join('|');
        })()""")

    assert result == (
        "No remediation cards|"
        "Choose another queue view or refresh after new evidence is available."
    )


def test_dashboard_remediation_empty_state_reset_shows_all_cards():
    result = _run_dashboard_expression("""(() => {
            app.healthSummary = { remediation_loop: { items: [
                {
                    domain: 'ready.example',
                    state: 'needs_approval',
                    priority_score: 9,
                    severity: 'medium',
                    repair_progression: { readiness_level: 'ready_for_preview' }
                }
            ] } };
            app.dashboardRemediationFilter = 'dispatch_blocked';
            app.showAllDashboardRemediationItems = true;
            const before = app.visibleDashboardRemediationItems().length;
            app.resetDashboardRemediationFilter();
            return [
                before,
                app.dashboardRemediationFilter,
                app.visibleDashboardRemediationItems().length,
                app.dashboardRemediationFilterCountCache === null,
                app.showAllDashboardRemediationItems
            ].join('|');
        })()""")

    assert result == "0|all|1|true|false"


def test_dashboard_remediation_stuck_filter_and_next_action_text():
    result = _run_dashboard_expression("""(() => {
            const item = {
                domain: 'blocked.example',
                state: 'needs_approval',
                priority_score: 9,
                severity: 'medium',
                evidence_refresh: {
                    required: true,
                    refresh_key: 'provider_value',
                    safe_to_run: false,
                    recommended_action: 'Select a DNS provider connection first.'
                },
                repair_progression: {
                    provider_apply_blocked: true,
                    blocked_by: ['provider_value']
                }
            };
            app.healthSummary = { remediation_loop: { items: [item] } };
            return [
                app.dashboardRemediationFilterCount('stuck'),
                app.dashboardRemediationNextActionText(item),
                app.dashboardRemediationStuckText(item)
            ].join('|');
        })()""")

    assert result == (
        "1|Select a DNS provider connection first.|"
        "Waiting on a provider value before DMARQ can refresh or prepare the repair."
    )


def test_dashboard_remediation_follow_up_age_text_uses_activity_timestamp():
    result = _run_dashboard_expression("""(() => {
            const latest = new Date(Date.now() - (2 * 24 * 60 * 60 * 1000)).toISOString();
            app.domains = [{
                domain_name: 'follow.example',
                remediation: {
                    latest_at: latest,
                    needs_operator_follow_up: true
                }
            }];
            return app.dashboardRemediationFollowUpAgeText({ domain: 'follow.example' });
        })()""")

    assert result == "Follow-up waiting since 2 days ago"


def test_dashboard_remediation_aging_follow_up_filter_and_class():
    result = _run_dashboard_expression("""(() => {
            const latest = new Date(Date.now() - (8 * 24 * 60 * 60 * 1000)).toISOString();
            const item = { domain: 'old.example' };
            app.domains = [{
                domain_name: 'old.example',
                remediation: {
                    latest_at: latest,
                    needs_operator_follow_up: true
                }
            }];
            app.healthSummary = { remediation_loop: { items: [item] } };
            return [
                app.dashboardRemediationFilterCount('aging_follow_up'),
                app.dashboardRemediationFollowUpAgeDays(item),
                app.dashboardRemediationFollowUpAgeClass(item)
            ].join('|');
        })()""")

    assert result == "1|8|border-[#ffcfbd] bg-[#fff2ec] text-[#8a2d0d]"


def test_dashboard_remediation_follow_up_age_class_handles_unknown_age():
    result = _run_dashboard_expression("""(() => {
            const future = new Date(Date.now() + (10 * 60 * 1000)).toISOString();
            return [
                app.dashboardRemediationFollowUpAgeClass({
                    latest_at: future,
                    needs_operator_follow_up: true
                }),
                app.dashboardRemediationFollowUpAgeClass({
                    latest_at: 'not-a-date',
                    needs_operator_follow_up: true
                })
            ].join('|');
        })()""")

    assert result == (
        "border-[#f5dfbd] bg-[#fff8ed] text-[#7a4a00]|"
        "border-[#f5dfbd] bg-[#fff8ed] text-[#7a4a00]"
    )


def test_dashboard_remediation_follow_up_age_text_ignores_future_timestamp():
    result = _run_dashboard_expression("""(() => {
            const latest = new Date(Date.now() + (10 * 60 * 1000)).toISOString();
            return app.dashboardRemediationFollowUpAgeText({
                latest_at: latest,
                needs_operator_follow_up: true
            });
        })()""")

    assert result == "Follow-up is waiting for operator review"


def test_dashboard_remediation_stale_evidence_links_to_evidence_anchor():
    result = _run_dashboard_expression("""(() => {
            const item = {
                domain: 'mail.example/a b',
                evidence_refresh: {
                    required: true,
                    refresh_key: 'dns',
                    ui_anchor: '#dns-records',
                    stale_warning: 'DNS evidence is older than the TTL window.'
                }
            };
            app.healthSummary = { remediation_loop: { items: [item] } };
            return [
                app.dashboardRemediationFilterCount('stale_evidence'),
                app.domainEvidenceHref(item),
                app.remediationStaleEvidenceText(item)
            ].join('|');
        })()""")

    assert (
        result
        == "1|/domains/mail.example%2Fa%20b#dns-records|DNS evidence is older than the TTL window."
    )


def test_domain_list_remediation_cell_shows_provider_workload_summary():
    result = _run_dashboard_expression("""(() => {
            global.document = {
                createElement: (tagName) => {
                    const element = {
                        tagName,
                        className: '',
                        children: [],
                        _textContent: '',
                        appendChild(child) {
                            this.children.push(child);
                            return child;
                        },
                        set textContent(value) {
                            this._textContent = String(value);
                        },
                        get textContent() {
                            return [
                                this._textContent,
                                ...this.children.map((child) => child.textContent || '')
                            ].join('');
                        }
                    };
                    return element;
                }
            };
            const cell = app.createRemediationCell(
                {
                    status: 'dispatched',
                    latest_label: 'Dispatch enqueued',
                    latest_at: new Date(Date.now() - (2 * 24 * 60 * 60 * 1000)).toISOString(),
                    dispatch_enqueued: 1,
                    needs_operator_follow_up: true
                },
                {
                    total_open: 3,
                    provider_preview_available: 2,
                    provider_apply_after_approval: 1,
                    provider_apply_blocked: 1,
                    provider_apply_history: 2,
                    provider_apply_verified: 1,
                    notification_profile_ready: 3,
                    notification_approval_required: 1,
                    notification_action_required: 1,
                    notification_investigation_required: 1,
                    notification_profiles: 4,
                    notification_summary_only: 1,
                    primary: {
                        state: 'needs_approval',
                        remediation_track: 'provider_preview',
                        repair_progression: {
                            readiness_label: 'Ready for preview'
                        },
                        title: 'Review provider repair'
                    }
                }
            );
            return cell.textContent.replace(/\\s+/g, ' ').trim();
        })()""")

    assert "3 open" in result
    assert "2 provider preview" in result
    assert "1 apply-ready" in result
    assert "1 apply blocked" in result
    assert "2 apply history" in result
    assert "1 verified" in result
    assert "3 notify-ready" in result
    assert "1 approval" in result
    assert "1 action" in result
    assert "1 investigate" in result
    assert "4 profiles" in result
    assert "1 summary-only" in result
    assert "1 dispatched" in result
    assert "1 follow-up" in result
    assert "1 aging follow-up" in result
    assert "Dispatch enqueued" in result
    assert "Open the remediation queue" in result
    assert "Follow-up waiting since" in result


def test_domain_details_remediation_queue_shows_verification_context():
    template = _domain_details_template()
    script = _domain_details_script()

    assert '<details id="posture-dashboard"' in template
    assert "Advanced remediation and posture" in template
    assert "Technical workflow details" in template
    assert 'x-text="verifiedItemsTotalCount()"' in template
    assert "verified_items_total" in script
    assert "verifiedItemsHiddenCount()" in template
    assert "visibleVerifiedItems()" in template
    assert "data-domain-detail-remediation-refresh" in template
    assert "data-domain-detail-verified-repairs-toggle" in template
    assert "fetchRemediationQueue({ refresh: true })" in script
    assert "remediationQueueRefreshing" in script
    assert "remediationQueueRefreshError" in script
    assert "remediationQueueRefreshMessage" in script
    assert "remediationQueueRefreshMessage" in template
    assert "Remediation queue refreshed." in script
    assert "remediationQueueEmptyStateTitle()" in script
    assert "remediationQueueEmptyStateText()" in script
    assert "remediationQueueEmptyStateTitle()" in template
    assert "remediationQueueEmptyStateText()" in template
    assert "hasRemediationQueueData()" in script
    assert "keepExistingQueueVisible" in script
    assert "Remediation queue refresh failed. Keeping the current queue visible." in script
    assert "remediationQueueRefreshing ? 'Refreshing...' : 'Refresh queue'" in template
    assert "remediationQueueRefreshError" in template
    assert "remediationQueueFilterOptions" in script
    assert "remediationQueueFilter: 'all'" in script
    assert "{ value: 'notify_ready', label: 'Ready to notify' }" in script
    assert "{ value: 'waiting_operator', label: 'Waiting' }" in script
    assert "{ value: 'fresh_evidence', label: 'Fresh evidence' }" in script
    assert "{ value: 'stale_evidence', label: 'Stale evidence' }" in script
    assert "{ value: 'provider_value', label: 'Provider value' }" in script
    assert "remediationQueueSort: 'priority'" in script
    assert "sortedRemediationQueueItems(items)" in script
    assert "remediationEvidenceRefreshRank(item)" in script
    assert "remediationEvidenceAnchorHref(item)" in script
    assert "rawAnchor.startsWith('#')" in script
    assert ':href="remediationEvidenceAnchorHref(item)"' in template
    assert "visibleRemediationQueueItems()" in script
    assert "filteredRemediationQueueItems(filterValue)" in script
    assert "remediationQueueFilterMatches(item, filter)" in script
    assert "filter === 'notify_ready'" in script
    assert "filter === 'waiting_operator'" in script
    assert "filter === 'fresh_evidence'" in script
    assert "filter === 'stale_evidence'" in script
    assert "filter === 'provider_value'" in script
    assert "item.notification?.dispatch?.eligible" in script
    assert "remediationQueueFilterCount(filter)" in script
    assert "remediationQueueFilterClass(filter)" in script
    assert "remediationQueueFilterTitle(filter)" in script
    assert "remediationQueueFilteredCount()" in script
    assert "remediationQueueTotalCount()" in script
    assert "showAllRemediationQueueItems" in script
    assert "remediationQueueHiddenCount()" in script
    assert "remediationQueueFilterLabel()" in script
    assert "remediationQueueFilterOptions" in template
    assert 'x-model="remediationQueueSort"' in template
    assert "Repair readiness" in template
    assert "Fresh evidence" in template
    assert "Remediation queue sort" in template
    assert "data-domain-detail-remediation-filter" in template
    assert "aria-pressed" in template
    assert ':class="remediationQueueFilterClass(filter.value)"' in template
    assert ':title="remediationQueueFilterTitle(filter.value)"' in template
    assert ':aria-label="remediationQueueFilterTitle(filter.value)"' in template
    assert 'role="group"' in template
    assert 'aria-label="Remediation queue filters"' in template
    assert 'role="status"' in template
    assert "domainDetailRemediationFilter" in script
    assert "remediationQueueFilterCount(filter.value)" in template
    assert "remediationQueueFilteredCount()" in template
    assert "remediationQueueTotalCount()" in template
    assert "remediationQueueFilterLabel()" in template
    assert "visibleRemediationQueueItems()" in template
    assert "data-domain-detail-remediation-toggle-all" in template
    assert "Show all matching items" in template
    assert "Show compact queue" in template
    assert "remediationQueueHiddenCount()" in template
    assert "No remediation items match this filter" in template
    assert "showAllVerifiedRemediationItems = !this.showAllVerifiedRemediationItems" in script
    assert "remediationQueueLoadedAt" in template
    assert "formatIsoDate(remediationQueueLoadedAt)" in template
    assert "remediationQueueLoadedAt" in script
    assert "verified.verification_method" in template
    assert "verified.verification_status" in template
    assert "verified.next_check" in template
    assert "item.action_plan.operator_decision_summary" in template
    assert "item.action_plan.risk_level" in template
    assert "remediationRiskClass(item.action_plan.risk_level || 'medium')" in template
    assert "item.priority_band" in template
    assert "item.verification_plan.verification_method" in template
    assert "item.verification_plan.freshness_requirement" in template
    assert "item.verification_plan.failure_mode" in template
    assert "Repair progression" in template
    assert "remediationQueue.summary.repair_preview_ready" in template
    assert "'loop.repair_ready_for_preview'" in template
    assert "'loop.repair_waiting_on_operator'" in template
    assert "'loop.repair_readiness_blocked'" in template
    assert "'loop.repair_readiness_score'" in template
    assert "item.repair_progression.readiness_reasons" in template
    assert "item.repair_progression.blocked_by" in template
    assert "remediationQueue.summary.repair_needs_evidence" in template
    assert "'loop.repair_blocked'" in template
    assert "item.repair_progression.next_gate" in template
    assert "repairProgressionPreviewLabel(item.repair_progression)" in template
    assert "repairProgressionVerificationLabel(item.repair_progression)" in template
    assert "Repair gate" in template
    assert "primaryRepairProgressionText" in template
    assert "remediationRiskClass(value)" in script
    assert "repairProgressionClass(progression)" in script
    assert "repairProgressionLabel(progression)" in script
    assert "repairProgressionPreviewLabel(progression)" in script
    assert "repairProgressionVerificationLabel(progression)" in script
    assert "repairProgressionNextStep(progression)" in script
    assert "repair_preview_ready: 0" in script
    assert "repair_needs_evidence: 0" in script
    assert "verifiedItemsTotalCount()" in script
    assert "verifiedItemsHiddenCount()" in script
    assert "hasMoreVisibleVerifiedItems()" in script
    assert "VERIFIED_ITEMS_COMPACT_LIMIT = 4" in script


def test_dashboard_remediation_queue_href_encodes_domain_and_anchor():
    assert (
        _run_dashboard_expression("app.domainRemediationHref('mail.example/a b')")
        == "/domains/mail.example%2Fa%20b#remediation-queue"
    )


def test_dashboard_clears_all_chart_instances():
    script = _dashboard_script()
    clear_start = script.index("        clearDashboardCharts()")
    helper_start = script.index("formatLargeNumber(value)", clear_start)
    clear_body = script[clear_start:helper_start]

    assert "volumeTrendChart.destroy()" in clear_body
    assert "complianceTrendChart.destroy()" in clear_body
    assert "healthTrendChart.destroy()" in clear_body
    assert "this.healthTrendChart = null" in clear_body


def test_dashboard_uses_external_page_script_for_csp_migration():
    template = _dashboard_template()
    script = _dashboard_script()
    styles = _read_project_file("static", "css", "styles.css")

    assert 'src="/static/js/chart.umd.min.js"' in template
    assert 'src="/static/js/dashboard-page.js"' in template
    assert 'x-data="dashboardApp"' in template
    assert "dashboardApp()" not in template
    assert "Alpine.data('dashboardApp', dashboardApp)" in script
    assert "cdn.tailwindcss.com" not in template
    assert "enforcement-gauge-bg" in template
    assert ".enforcement-gauge-bg" in styles
    assert '@change="handleDateIntervalChange()"' not in template
    assert '@click="fetchDashboardStats(); fetchWorkspaceHealthHistory()"' not in template
    assert '@change="updateDnsHealth()"' not in template
    assert '@click="triggerPollNow()"' not in template
    assert '@keydown.escape.window="closeDemoTour()"' not in template
    assert '@click="closeDemoTour()"' not in template
    assert '@click="previousDemoTourStep()"' not in template
    assert '@click="nextDemoTourStep()"' not in template
    assert "data-dashboard-date-interval" in template
    assert "data-dashboard-custom-apply" in template
    assert "data-dashboard-dns-health-domain" in template
    assert "data-dashboard-trigger-poll" in template
    assert "data-dashboard-demo-tour-close" in template
    assert "data-dashboard-demo-tour-previous" in template
    assert "data-dashboard-demo-tour-next" in template
    assert "bindControls()" in script
    assert "data-dashboard-date-interval" in script
    assert "data-dashboard-custom-apply" in script
    assert "data-dashboard-dns-health-domain" in script
    assert "data-dashboard-trigger-poll" in script
    assert "dashboardNextAction" in script
    assert "severityDotClass(severity)" in script
    assert "Report-backed domains only" in script
    assert "Scheduled checks active" in script
    assert "/api/v1/domains/summary?include_empty=false" in script
    assert "Analytics window" in template
    assert "Analytics and evidence" in template
    assert "Traffic-weighted health" in template
    assert "Weighted by message volume." in template
    assert 'id="dashboard-next-action-heading"' in template
    assert "data-dashboard-demo-tour-close" in script
    assert "ownerDocument.addEventListener('keydown'" in script
    assert "removeEventListener('keydown'" in script
    assert not _has_inline_style(template)
    assert not re.search(r"<script\b(?![^>]*\bsrc=)[^>]*>", template, re.IGNORECASE)


def test_operations_uses_external_page_script_for_csp_migration():
    template = _operations_template()
    script = _operations_script()

    assert 'src="/static/js/operations-page.js"' in template
    assert 'x-data="operationsHealth"' in template
    assert "Alpine.data('operationsHealth', operationsHealth)" in script
    assert 'x-init="load()"' not in template
    assert '@click="load"' not in template
    assert "data-operations-refresh" in template
    assert "data-operations-refresh" in script
    assert "/api/v1/health/operations" in script
    assert "Health details could not be loaded." in script
    assert "statusClass" in template
    assert "databaseClass" in template
    assert "mailSourcesLabel" in template
    assert "hasMailboxRecovery" in template
    assert "normalizeHealth" in script
    assert not re.search(r"<script\b(?![^>]*\bsrc=)[^>]*>", template, re.IGNORECASE)


def test_alert_component_uses_external_close_control_for_csp_migration():
    template = _read_project_file("templates", "components", "ui", "alert.html")
    script = _read_project_file("static", "js", "pages.js")

    assert 'x-on:click="close()"' not in template
    assert 'x-data="alertComponent"' in template
    assert "alertComponent()" not in template
    assert "Alpine.data('alertComponent'" in script
    assert "data-alert-close" in template
    assert "data-alert-close" in script
    assert "bindControls()" in script
    assert "close()" in script


def test_reports_uses_external_page_script_for_csp_migration():
    template = _reports_template()
    script = _reports_script()

    assert 'src="/static/js/reports-page.js"' in template
    assert 'x-data="reportsApp" x-cloak' in template
    assert "Alpine.data('reportsApp', reportsApp)" in script
    assert '@click="deleteReport' not in template
    assert "data-report-delete" in template
    assert "data-report-delete" in script
    assert "data-report-refresh" in template
    assert "data-report-refresh" in script
    assert "bindPageControls()" in script
    assert "event.target instanceof Element" in script
    assert "Number.isNaN(date.getTime())" in script
    assert "/api/v1/reports" in script
    assert "deleteReport(domain, reportId)" in script
    assert "resetFilters()" in script
    assert '@click="' not in template
    assert not re.search(r"<script\b(?![^>]*\bsrc=)[^>]*>", template, re.IGNORECASE)


def test_reports_page_distinguishes_loading_error_and_empty_states():
    template = _reports_template()
    script = _reports_script()

    assert "Checking report index..." in template
    assert "Reports could not be loaded." in script
    assert "No reports match this filter" in script
    assert "Connect report mailbox" in template
    assert "Trigger report refresh" in template
    assert "primaryReportCtaLabel" in template
    assert "primaryReportCtaHref" in template
    assert "Retry loading reports" in template
    assert "Showing the last loaded reports." in script
    assert 'x-if="showWarning"' in template
    assert "warning: ''" in script
    assert '@click="fetchReports()"' not in template
    assert '@click="resetFilters()"' not in template
    assert "data-report-retry-load" in template
    assert "data-report-retry-load" in script
    assert "data-report-reset-filters" in template
    assert "data-report-reset-filters" in script
    assert 'x-show="showError"' in template
    assert 'x-show="loading"' not in template
    assert "visibleReports" in template
    assert "filteredReportCount" in template
    assert "loading: true" in script
    assert "throw new Error('Reports could not be loaded." in script


def test_domains_uses_external_page_script_for_csp_migration():
    template = _domains_template()
    script = _domains_script()

    assert 'src="/static/js/domains-page.js"' in template
    assert 'x-data="domainsApp" x-cloak' in template
    assert "Alpine.data('domainsApp', domainsApp)" in script
    assert "/api/v1/domains/summary" in script
    assert "/api/v1/domains/domains" in script
    assert "createDomain()" in script
    assert "normalizeDomain(domain)" in script
    assert "detail_url" in script
    assert "encodeURIComponent(normalized.name)" in script
    assert "domain.detail_url" in template
    assert "domain.dmarc_status_class" in template
    assert "domain.spf_status_class" in template
    assert "domain.dkim_status_class" in template
    assert "openEditDialog(domain)" not in template
    assert "openEditDialog(domain)" in script
    assert "bindPageControls()" in script
    assert "data-domain-refresh" in template
    assert "data-domain-refresh" in script
    assert "data-domain-toggle-empty" in template
    assert "data-domain-toggle-empty" in script
    assert "showEmptyDomains" in script
    assert "visibleDomains()" in script
    assert "hiddenEmptyDomainCount()" in script
    assert "emptyDomainToggleLabel()" in script
    assert 'x-text="emptyDomainToggleLabel()"' in template
    assert "`Show ${hiddenEmptyDomainCount()} empty`" not in template
    assert "showEmptyDomainHint()" in script
    assert "dnsStateLabel(domain)" in script
    assert "dnsStateClass(domain)" in script
    assert "dnsCheckedLabel(domain)" in script
    assert "dns_lookup_status" in script
    assert "dns_lookup_error" in script
    assert "visibleDomains()" in template
    assert "without reports or volume hidden" in template
    assert "Show empty domains" in template
    assert (
        "All monitored domains are hidden because no report or mail volume has been observed yet."
        in template
    )
    assert "visibleDomains().length === 0 ? 'hidden md:block' : 'block'" in template
    assert "domain.dns_state_label" in template
    assert "domain.dns_state_class" in template
    assert "domain.dns_checked_label" in template
    assert "domain.dns_lookup_error" in template
    assert "data-domain-create-open" in template
    assert "data-domain-create-open" in script
    assert "data-domain-create-dialog" in template
    assert "data-domain-create-form" in template
    assert "data-domain-create-form" in script
    assert "data-domain-create-close" in template
    assert "data-domain-create-close" in script
    assert "data-domain-edit" in template
    assert "data-domain-edit" in script
    assert "data-domain-edit-dialog" in template
    assert "data-domain-edit-form" in template
    assert "data-domain-edit-form" in script
    assert "data-domain-edit-close" in template
    assert "data-domain-edit-close" in script
    assert "Edit monitored domain" in template
    assert "updateDomain()" in script
    assert "method: 'PATCH'" in script
    assert "DMARC report mailbox override" in template
    assert "dmarc_report_mailbox" in script
    assert 'inputmode="email"' in template
    assert 'type="email" placeholder="Use global default mailbox"' not in template
    assert "data-domain-edit-mailbox" in template
    assert "data-domain-edit-mailbox" in script
    assert "editDmarcReportMailboxLoaded" in script
    assert "Use global default mailbox" in template
    assert "editError" in template
    assert "data-domains-page" in template
    assert "dnsStatusClass(domain" not in template
    assert "'/domains/' + domain.name" not in template
    assert '@submit.prevent="createDomain' not in template
    assert '@submit.prevent="updateDomain' not in template
    assert '@click="closeCreate' not in template
    assert '@click="closeEdit' not in template
    assert "@click=" not in template
    assert "formatCount(domain.reports_count, 'report')" in template
    assert "formatCount(domain.emails_count, 'message')" in template
    assert "formatCount(value, noun)" in script
    assert not re.search(r"<script\b(?![^>]*\bsrc=)[^>]*>", template, re.IGNORECASE)


def test_domains_page_distinguishes_loading_error_and_empty_states():
    template = _domains_template()
    script = _domains_script()

    assert "Loading monitored domains..." in template
    assert "Domains could not be loaded." in script
    assert "Domain refresh failed; showing the last loaded domain data." in script
    assert "if (!refresh || this.domains.length === 0)" in script
    assert "No domains found. Add a domain to get started." in template
    assert "Retry loading domains" in template
    assert "All monitored domains are currently hidden" in template
    assert "has_activity" in script
    assert "reports_count" in script
    assert "emails_count" in script
    assert '@click="fetchDomains()"' not in template
    assert '@click="fetchDomains({ refresh: true })"' not in template
    assert "data-domain-retry-load" in template
    assert "data-domain-retry-load" in script
    assert 'x-if="!loading && loadError"' in template
    assert (
        'x-if="!loading && !loadError && domains.length === 0 && hiddenEmptyDomainCount() === 0"'
        in template
    )


def test_upload_uses_external_page_script_for_csp_migration():
    template = _upload_template()
    script = _upload_script()

    assert 'src="/static/js/upload-page.js"' in template
    assert 'x-data="uploadForm"' in template
    assert "uploadForm()" not in template
    assert "Alpine.data('uploadForm', uploadForm)" in script
    assert "/api/v1/reports/upload" in script
    assert "bindControls()" in script
    assert "get hasFiles()" in script
    assert "get isProcessed()" in script
    assert "get isAllSuccess()" in script
    assert 'x-show="hasFiles"' in template
    assert 'x-show="isProcessed"' in template
    assert 'x-if="isAllSuccess"' in template
    assert "data-upload-dropzone" in template
    assert "data-upload-dropzone" in script
    assert "data-upload-file-input" in template
    assert "data-upload-file-input" in script
    assert "data-upload-clear" in template
    assert "data-upload-clear" in script
    assert "data-upload-remove-index" in template
    assert "data-upload-remove-index" in script
    assert 'x-on:dragover.prevent="dragover = true"' not in template
    assert 'x-on:dragleave.prevent="dragover = false"' not in template
    assert 'x-on:drop.prevent="handleDrop($event)"' not in template
    assert 'x-on:change="handleFileSelect($event)"' not in template
    assert 'x-on:click="clearAll()"' not in template
    assert 'x-on:click="removeFile(index)"' not in template
    assert "AbortController" in script
    assert "UPLOAD_TIMEOUT_MS" in script
    assert "this.isUploading = false" in script
    assert "dmarq:refresh-data" in script
    assert not re.search(r"<script\b(?![^>]*\bsrc=)[^>]*>", template, re.IGNORECASE)


def test_profile_uses_external_page_script_for_csp_migration():
    template = _profile_template()
    script = _profile_script()

    assert 'src="/static/js/profile-page.js"' in template
    assert 'x-data="profileApp"' in template
    assert "profileApp()" not in template
    assert "Alpine.data('profileApp', profileApp)" in script
    assert "data-profile-page" in template
    assert "/api/v1/auth/me" in script
    assert "Failed to load user profile" in script
    assert "get avatarInitial()" in script
    assert "get authProviderText()" in script
    assert 'x-text="avatarInitial"' in template
    assert 'x-text="authProviderText"' in template
    assert 'x-init="init()"' not in template
    assert not re.search(r"<script\b(?![^>]*\bsrc=)[^>]*>", template, re.IGNORECASE)


def test_login_error_banner_uses_registered_component_for_csp_migration():
    template = _read_project_file("templates", "login.html")
    script = _read_project_file("static", "js", "login-page.js")

    assert 'src="/static/js/login-page.js"' in template
    assert 'x-data="loginErrorBanner"' in template
    assert "loginErrorBanner()" not in template
    assert "Alpine.data('loginErrorBanner'" in script
    assert "get hasError()" in script
    assert "get errorMessage()" in script
    assert 'x-show="hasError"' in template
    assert 'x-text="errorMessage"' in template
    assert "error === 'callback_failed'" not in template
    assert not re.search(r"<script\b(?![^>]*\bsrc=)[^>]*>", template, re.IGNORECASE)


def test_profile_renders_external_page_script_for_csp_migration():
    rendered = _render_template(
        "profile.html",
        app_name="DMARQ",
        auth_configured=False,
        auth_disabled=False,
        auth_provider="logto",
        auth_provider_label="Logto",
        logto_configured=False,
    )

    assert _has_script_src(rendered, "/static/js/profile-page.js")
    assert not _has_script_src(
        '<script data-src="/static/js/profile-page.js"></script>',
        "/static/js/profile-page.js",
    )


def test_forensic_reports_uses_external_page_script_for_csp_migration():
    template = _forensic_reports_template()
    script = _forensic_reports_script()

    assert 'src="/static/js/forensic-reports-page.js"' in template
    assert 'x-data="forensicReportsApp"' in template
    assert "Alpine.data('forensicReportsApp', forensicReportsApp)" in script
    assert "/api/v1/forensics?" in script
    assert "/api/v1/forensics/analysis?" in script
    assert "/api/v1/forensics/upload" in script
    assert "Unable to load forensic reports" in script
    assert "normalizeReport(report)" in script
    assert "normalizeAnalysisGroup(group)" in script
    assert "domain_url" in script
    assert "detail_url" in script
    assert "encodeURIComponent(domain)" in script
    assert "encodeURIComponent(report.id)" in script
    assert "uploadDisabled" in template
    assert "uploadIdle" in template
    assert "uploadMessageClass" in template
    assert "analysisEmpty" in template
    assert "hasAnalysisGroups" in template
    assert "visibleAnalysisGroups" in template
    assert "group.priority_class" in template
    assert "group.visible_recommendations" in template
    assert "group.sample_count_label" in template
    assert "filteredReportsCount" in template
    assert "report.arrival_label" in template
    assert "report.domain_url" in template
    assert "report.domain_label" in template
    assert "report.detail_url" in template
    assert "forensicReportsApp()" not in template
    assert "priorityClass(group.priority)" not in template
    assert "analysis.groups.slice(0, 3)" not in template
    assert "group.recommendations.slice(0, 2)" not in template
    assert "formatDate(report.arrival_date" not in template
    assert "'/domains/' + encodeURIComponent" not in template
    assert "'/forensics/' + report.id" not in template
    assert not _has_alpine_handler_call(template, "change", "fetchReports")
    assert not _has_alpine_handler_call(template, "submit", "uploadReport")
    assert not _has_alpine_handler_call(template, "click", "resetFilters")
    assert "data-forensic-domain-filter" in template
    assert "data-forensic-auth-filter" in template
    assert "data-forensic-result-filter" in template
    assert "data-forensic-upload-form" in template
    assert "data-forensic-upload-file" in template
    assert "data-forensic-reset" in template
    assert "data-forensic-reports-page" in template
    assert "data-forensic-reset" in script
    assert "bindControls()" in script
    assert "event.target instanceof Element" in script
    assert 'x-init="init()"' not in template
    assert not re.search(r"<script\b(?![^>]*\bsrc=)[^>]*>", template, re.IGNORECASE)


def test_forensic_report_detail_uses_external_page_script_for_csp_migration():
    template = _forensic_report_detail_template()
    script = _forensic_report_detail_script()

    assert 'src="/static/js/forensic-report-detail-page.js"' in template
    assert 'x-data="forensicReportDetailApp"' in template
    assert "forensicReportDetailApp(" not in template
    assert "Alpine.data('forensicReportDetailApp', forensicReportDetailApp)" in script
    assert "/api/v1/forensics/${this.reportId}" in script
    assert "Forensic report not found" in script
    assert "feedbackHeaderEntries" in script
    assert "showReport" in template
    assert "showError" in template
    assert "domainUrl" in template
    assert "priorityBadgeClass" in template
    assert "authenticationResultsLabel" in template
    assert "hasNoFeedbackHeaderEntries" in template
    assert "report.domain || report.reported_domain" not in template
    assert "report.analysis?." not in template
    assert "encodeURIComponent" not in template
    assert "feedbackHeaderEntries.length === 0" not in template
    assert "data-forensic-report-detail-page" in template
    assert "data-report-id" in template
    assert 'x-init="init()"' not in template
    assert not re.search(r"<script\b(?![^>]*\bsrc=)[^>]*>", template, re.IGNORECASE)


def test_tls_reports_uses_external_page_script_for_csp_migration():
    template = _tls_reports_template()
    script = _tls_reports_script()

    assert 'src="/static/js/tls-reports-page.js"' in template
    assert 'x-data="tlsReportsApp"' in template
    assert "Alpine.data('tlsReportsApp', tlsReportsApp)" in script
    assert "/api/v1/tls-reports/summary?" in script
    assert "/api/v1/tls-reports/upload" in script
    assert "Unable to load TLS report summary" in script
    assert not _has_alpine_handler_call(template, "click", "refresh")
    assert not _has_alpine_handler_call(template, "change", "refresh")
    assert not _has_alpine_handler_call(template, "input", "refresh")
    assert not _has_alpine_handler_call(template, "submit", "uploadReport")
    assert "data-tls-refresh" in template
    assert "data-tls-days-filter" in template
    assert "data-tls-domain-filter" in template
    assert "data-tls-upload-form" in template
    assert "data-tls-upload-file" in template
    assert "data-tls-reports-page" in template
    assert "data-tls-refresh" in script
    assert "Showing the last loaded TLS report summary." in script
    assert "hasSummaryData(summary)" in script
    assert 'x-if="showWarning"' in template
    assert "bindControls()" in script
    assert "normalizeSummary" in script
    assert "event.target instanceof Element" in script
    assert 'x-init="init()"' not in template
    assert 'x-effect="$el.style.width' not in template
    assert "trendSuccessWidth(day)" not in template
    assert "trendFailureWidth(day)" not in template
    assert 'x-text="day.failed_label"' in template
    assert 'x-text="failure.affected_domains_label"' in template
    assert 'x-text="failure.receiving_mx_hostnames_label"' in template
    assert ':href="item.domain_url"' in template
    assert 'viewBox="0 0 100 6"' in template
    assert not _has_inline_style(template)
    assert not re.search(r"<script\b(?![^>]*\bsrc=)[^>]*>", template, re.IGNORECASE)


def test_report_detail_uses_external_page_script_for_csp_migration():
    template = _report_detail_template()
    script = _report_detail_script()

    assert 'src="/static/js/report-detail-page.js"' in template
    assert "reportDetailApp" in template
    assert '@click="deleteReport' not in template
    assert "data-report-delete" in template
    assert "data-report-delete" in script
    assert "data-report-retry-load" in template
    assert "data-report-retry-load" in script
    assert "data-report-refresh-reputation" in template
    assert "data-report-refresh-reputation" in script
    assert "refresh_reputation=true" in script
    assert "reputationRefreshing" in template
    assert "reputationRefreshError" in template
    assert (
        "if (!refreshReputation) {\n                        this.reputationRefreshError = '';"
        in script
    )
    assert "Reputation refresh timed out. Please try again in a moment." in script
    assert (
        "const detail = typeof data.detail === 'string' ? data.detail : data.detail?.message;"
        in script
    )
    assert "bindPageControls()" in script
    assert "event.target instanceof Element" in script
    assert "/api/v1/reports/${encodeURIComponent(this.reportId)}" in script
    assert "deleteReport(domain, reportId)" in script
    assert "sourceLocation(record)" in script
    assert 'x-data="reportDetailApp"' in template
    assert "reportDetailApp(" not in template
    assert "Alpine.data('reportDetailApp', reportDetailApp)" in script
    assert "data-report-detail-page" in template
    assert "data-report-id" in template
    assert "x-cloak" in template
    assert '@click="fetchReport()"' not in template
    assert "this.loading = true;" in script
    assert "this.report = null;" in script
    assert "record.reputation.feed_status" in template
    assert "record.reputation.feed_summary" in template
    assert "recordRiskFilter" in template
    assert "filteredRecords" in template
    assert "visibleFilteredRecords" in template
    assert "recordRiskCounts" in template
    assert "recordRiskMatches(record, this.recordRiskFilter)" in script
    assert "recordRiskLabel()" in template
    assert "reputationAgeLabel(record.reputation)" in template
    assert "reputationNextSteps(record.reputation)" in template
    assert "recordSenderName(record)" in template
    assert "recordSenderStatus(record)" in template
    assert "recordSenderProvider(record)" in template
    assert "recordSenderConfidence(record)" in template
    assert "recordSenderEvidence(record)" in template
    assert "recordSenderRemediationHint(record)" in template
    assert "seenLabel(record.reputation.last_seen)" in template
    assert "Use Recalculate reputation" in template
    assert "reputationFeedClass" in script
    assert "Investigation summary" in template
    assert "Sending source clusters" in template
    assert "Raw record evidence" in template
    assert "senderClusters" in script
    assert "investigationCounts" in script
    assert "data-report-risk-filter" in template
    assert "data-report-risk-filter" in script
    assert "data-report-show-more-records" in template
    assert "data-report-show-more-records" in script
    assert "reputationLabel" in script
    assert "reputationEvidencePreview" in script
    assert "senderStatusClass" in script
    assert "normalizeReport" in script
    assert "reportDomainUrl" in script
    assert "?." not in template
    assert "??" not in template
    assert "encodeURIComponent" not in template
    assert not re.search(r"<script\b(?![^>]*\bsrc=)[^>]*>", template, re.IGNORECASE)


def test_settings_exposes_provider_agnostic_dns_import_without_html_injection():
    template = _settings_template()
    script = _settings_script()

    assert "data-settings-page" in template
    assert 'x-data="settingsApp"' in template
    assert "settingsApp()" not in template
    assert "Alpine.data('settingsApp', settingsApp)" in script
    assert "DNS Provider Connectors" in template
    assert 'id="provider-integrations"' in template
    assert 'aria-label="Settings navigation"' in template
    assert "DMARC defaults" in template
    assert "Connect report mailbox" in template
    assert 'href="#account-readiness-settings"' in template
    assert "Account and access diagnostics" in template
    assert '<details id="account-readiness-settings"' in template
    assert "Forensic reports" in template
    assert "TLS reports" in template
    assert "Setup assistant" in template
    assert 'id="dmarc-defaults-section"' in template
    assert 'id="dns-resolver-settings"' in template
    assert 'id="mail-service-imports"' in template
    assert "Provider Domain Discovery" in template
    assert "dns-provider-import-select" in template
    assert 'src="/static/js/settings-page.js"' in template
    assert "loadDNSProviders" in script
    assert "dnsImportProviders()" in script
    assert "/api/v1/domains/dns/providers" in script
    assert "discoverDNSProviderZones" in script
    assert "importDNSProviderZones" in script
    assert "selectedDnsProviderAuthHint" in script
    assert "selectedDnsProviderSetupHint" in script
    assert "selectedDnsProviderDocsUrl" in script
    assert "selectedDnsProviderConnectionStatus" in script
    assert "selectedDnsProviderConnectionLabel" in script
    assert "selectedDnsProviderConnectionHint" in script
    assert "selectedDnsProviderConnectionClass" in script
    assert "resetDnsProviderImportState" in script
    assert "bindProviderControls" in script
    assert re.search(r"\bx-init\s*=", template) is None
    assert re.search(
        r"\binit\s*\(\s*\)\s*\{[^}]*\breturn\s+this\.initSettingsPage\s*\(\s*\)",
        script,
        re.DOTALL,
    )
    assert "data-settings-cloudflare-connect" in template
    assert "data-settings-toggle-cf-token" in template
    assert "data-settings-dns-provider-select" in template
    assert "data-settings-discover-dns-zones" in template
    assert "data-settings-import-dns-zones" in template
    assert "data-settings-toggle-postmark-token" in template
    assert "data-settings-discover-mail-domains" in template
    assert "data-settings-import-mail-domains" in template
    assert '@click="connectCloudflare()"' not in template
    assert '@click="showCfToken = !showCfToken"' not in template
    assert '@change="resetDnsProviderImportState()"' not in template
    assert '@click="discoverDNSProviderZones()"' not in template
    assert '@click="importDNSProviderZones()"' not in template
    assert '@click="showPostmarkToken = !showPostmarkToken"' not in template
    assert '@click="discoverMailServiceDomains()"' not in template
    assert '@click="importMailServiceDomains()"' not in template
    assert "dnsProviderImportError" in template
    assert "dnsProviderImportSummary" in template
    assert "selectedDnsProviderConnectionLabel()" in template
    assert "selectedDnsProviderConnectionHint()" in template
    assert "providerErrorDetail" in script
    assert "dnsProviderNoImportableZonesTitle()" in template
    assert "dnsProviderImportErrorTitle()" in template
    assert "returned no importable zones" in script
    assert "discovery needs attention" in script
    assert "Provider setup docs" in template
    assert "/api/v1/domains/dns/import/${encodeURIComponent(providerId)}/preview" in script
    assert "/api/v1/domains/dns/import/${encodeURIComponent(providerId)}" in script
    assert "discoverCloudflareZones()" in script
    assert "importCloudflareZones()" in script
    assert "x-html" not in template
    assert not re.search(r"<script\b(?![^>]*\bsrc=)[^>]*>", template, re.IGNORECASE)


def test_settings_controls_are_bound_from_external_script():
    template = _settings_template()
    script = _settings_script()

    assert "Account and Access Milestone" in template
    assert "Finish the next safe setup step" in template
    assert "Advanced privacy settings" in template
    assert "Advanced webhook delivery" in template
    assert "Advanced AI and agent automation" in template
    assert "Save this section after changing product name" in template
    assert "Save token or OAuth profile changes before discovering provider zones." in template
    assert 'data-settings-action="load_account_readiness"' in template
    assert "accountReadiness.remaining_slices" in template
    assert "accountReadiness.setup_gates" in template
    assert "loadAccountReadiness" in script
    assert "accountReadinessStatusClass" in script
    assert "accountReadinessStatusLabel" in script
    assert "/api/v1/settings/account-readiness" in script
    assert "data-settings-save-category" in template
    assert "data-settings-save-automation" in template
    assert "data-settings-create-webhook" in template
    assert "data-settings-boolean-key" in template
    assert "data-settings-action" in template
    assert "data-settings-webhook-action" in template
    assert "data-settings-ai-provider-select" in template
    assert "data-settings-toggle-ai-key" in template
    assert "handleSettingsAction" in script
    assert "handleWebhookAction" in script
    assert "const numericEndpointId = Number(endpointId)" in script
    assert "Number.isInteger(numericEndpointId)" in script
    assert "this.testWebhook(numericEndpointId)" in script
    assert "this.disableWebhook(numericEndpointId)" in script
    assert "data-settings-save-category" in script
    assert "data-settings-boolean-key" in script
    assert "data-settings-ai-provider-select" in script
    assert "@click" not in template
    assert "@submit" not in template
    assert "@change" not in template
    assert "showAIKey = !showAIKey" not in template
    assert "testWebhook(hook.id)" not in template
    assert "x-html" not in template
    assert not re.search(r"<script\b(?![^>]*\bsrc=)[^>]*>", template, re.IGNORECASE)


def test_mail_sources_list_actions_are_bound_from_external_script():
    template = _mail_sources_template()
    script = _mail_sources_script()

    assert _has_script_src(template, "/static/js/mail-sources-page.js")
    assert "data-mail-sources-page" in template
    assert 'x-data="mailSourcesApp"' in template
    assert "mailSourcesApp()" not in template
    assert "Alpine.data('mailSourcesApp', mailSourcesApp)" in script
    assert "data-mail-source-add" in template
    assert "data-mail-source-toggle" in template
    assert "data-mail-source-edit" in template
    assert "data-mail-source-test" in template
    assert "data-mail-source-fetch" in template
    assert "data-mail-source-backfill" in template
    assert "data-mail-source-history" in template
    assert "data-mail-source-delete" in template
    assert "data-mail-source-history-close" in template
    assert "data-mail-source-backfill-refresh" in template
    assert "data-mail-source-backfill-cancel" in template
    assert "data-mail-source-backfill-retry" in template
    assert "data-mail-source-backfill-close" in template
    assert "data-mail-source-backfill-run" in template
    assert "data-mail-source-backfill-modal" in template
    assert "data-backfill-days" in template
    assert "bindPageControls" in script
    assert "feedback.type === 'warning'" in template
    assert "already imported report" in script
    assert "review Import History" in script
    assert "sourceById" in script
    assert "data-mail-source-toggle" in script
    assert "event.key !== 'Escape'" in script
    assert "data-mail-source-backfill-modal" in script
    assert 'x-on:click="openAddForm()"' not in template
    assert 'x-on:change="toggleSource(source.id)"' not in template
    assert 'x-on:click="openEditForm(source)"' not in template
    assert 'x-on:click="testSource(source.id)"' not in template
    assert 'x-on:click="fetchSource(source)"' not in template
    assert 'x-on:click="loadImportHistory(source)"' not in template
    assert 'x-on:click="confirmDelete(source)"' not in template
    assert 'x-on:click.stop="openBackfill(source)"' not in template
    assert 'x-on:click.stop="loadBackfills(source)"' not in template
    assert 'x-on:click.stop="cancelBackfill(source, latestBackfill(source))"' not in template
    assert 'x-on:click.stop="retryBackfill(source, latestBackfill(source))"' not in template
    assert 'x-on:click="backfillDays = 7"' not in template
    assert 'x-on:click="backfillDays = 30"' not in template
    assert 'x-on:click="backfillDays = 90"' not in template
    assert 'x-on:click="runBackfill()"' not in template
    assert 'x-on:keydown.escape.window="closeBackfill()"' not in template
    assert "x-html" not in template
    assert not re.search(r"<script\b(?![^>]*\bsrc=)[^>]*>", template, re.IGNORECASE)


def test_mail_sources_form_actions_are_bound_from_external_script():
    template = _mail_sources_template()
    script = _mail_sources_script()

    assert "data-mail-source-form-modal" in template
    assert "data-mail-source-form" in template
    assert "data-mail-source-form-close" in template
    assert "data-mail-source-password-toggle" in template
    assert "data-mail-source-m365-folder-select" in template
    assert "data-mail-source-m365-load-folders" in template
    assert "data-mail-source-m365-manual-folder" in template
    assert "data-mail-source-test-adhoc" in template
    assert "data-mail-source-connect-gmail" in template
    assert "data-mail-source-connect-m365" in template
    assert "data-mail-source-delete-modal" in template
    assert "data-mail-source-delete-cancel" in template
    assert "data-mail-source-delete-confirm" in template
    assert "data-mail-source-form" in script
    assert "data-mail-source-form-close" in script
    assert "data-mail-source-password-toggle" in script
    assert "data-mail-source-m365-folder-select" in script
    assert "data-mail-source-m365-load-folders" in script
    assert "data-mail-source-m365-manual-folder" in script
    assert "data-mail-source-test-adhoc" in script
    assert "data-mail-source-connect-gmail" in script
    assert "data-mail-source-connect-m365" in script
    assert "data-mail-source-delete-cancel" in script
    assert "data-mail-source-delete-confirm" in script
    assert "data-mail-source-form-modal" in script
    assert "data-mail-source-delete-modal" in script
    assert 'x-on:keydown.escape.window="closeForm()"' not in template
    assert 'x-on:click="closeForm()"' not in template
    assert 'x-on:submit.prevent="saveSource()"' not in template
    assert 'x-on:click="showPassword = !showPassword"' not in template
    assert 'x-on:change="applyM365FolderSelection($event.target.value)"' not in template
    assert 'x-on:click="loadM365Folders()"' not in template
    assert "x-on:input=\"form.m365_folder_id = ''\"" not in template
    assert 'x-on:click="testAdHoc()"' not in template
    assert 'x-on:click="connectGmail()"' not in template
    assert 'x-on:click="connectM365()"' not in template
    assert 'x-on:click="deleteTarget = null"' not in template
    assert 'x-on:click="deleteSource()"' not in template
    assert "x-html" not in template
    assert not re.search(r"<script\b(?![^>]*\bsrc=)[^>]*>", template, re.IGNORECASE)


def test_domain_details_exposes_health_history_without_html_injection():
    template = _domain_details_template()
    script = _domain_details_script()

    assert "Health Score Trend" in template
    assert "/posture/history?capture_current=false" in script
    assert "/posture/evidence/export?capture_current=false" in script
    assert "encodeURIComponent(this.domainId)" in script
    assert 'x-data="domainDetailsApp"' in template
    assert "domainDetailsApp(" not in template
    assert "Alpine.data('domainDetailsApp', domainDetailsApp)" in script
    assert "data-domain-id" in template
    assert "health-score-chart" in template
    assert "x-html" not in template
    assert _has_script_src(template, "/static/js/domain-details-page.js")
    assert not _has_inline_script(template)


def test_domain_details_exposes_volume_scale_controls_without_html_injection():
    template = _domain_details_template()
    script = _domain_details_script()

    assert "Volume scale" in template
    assert 'role="group" aria-label="Volume scale"' in template
    assert "data-domain-detail-page" in template
    assert 'data-domain-detail-volume-scale="logarithmic"' in template
    assert 'data-domain-detail-volume-scale="linear"' in template
    assert "data-domain-detail-volume-scale" in script
    assert "bindPageControls()" in script
    assert "setVolumeScale('logarithmic')" not in template
    assert "setVolumeScale('linear')" not in template
    assert ":aria-pressed=\"effectiveVolumeScale() === 'logarithmic'\"" in template
    assert ":aria-pressed=\"effectiveVolumeScale() === 'linear'\"" in template
    assert ':disabled="!hasObservedVolume"' in template
    assert "dmarq:domain-volume-scale" in script
    assert "effectiveVolumeScale()" in template
    assert "const volumeScale =" in script
    assert "type: volumeScale" in script
    assert "Messages (log scale)" in script
    assert "Messages (linear scale)" in script
    assert "context.parsed.y === null" in script
    assert "no observed mail volume" in script
    assert "x-html" not in template


def test_domain_details_exposes_migration_readiness_without_html_injection():
    template = _domain_details_template()
    script = _domain_details_script()

    assert "Migration Readiness" in template
    assert "/migration/readiness" in script
    assert "migration.error" in template
    assert "Migration readiness could not be loaded." in script
    assert "parallel_reporting_days" in template
    assert "migration.export_links" in template
    assert "migration.checklist" in template
    assert "Migration Parity" in template
    assert "/migration/parity" in script
    assert "migrationParity.metrics" in template
    assert "migrationBaseline" in script
    assert "Historical Export Preview" in template
    assert "/migration/import/preview" in script
    assert "loadMigrationImportSample" in script
    assert "previewMigrationImport" in script
    assert "applyMigrationPreviewBaseline" in script
    assert "pathValue(migrationImport, 'preview.sample_rows', [])" in template
    assert "migrationToolsEnabled" in template
    assert "I am migrating data" in template
    assert "data-domain-detail-migration-action" in template
    assert "handleMigrationAction" in script
    assert '@click="enableMigrationTools()"' not in template
    assert '@click="previewMigrationImport"' not in template
    assert '@click="loadMigrationImportSample"' not in template
    assert '@click="applyMigrationPreviewBaseline"' not in template
    assert '@click="compareMigrationBaseline"' not in template
    assert "x-html" not in template


def test_domain_details_exposes_ownership_and_delete_controls_without_html_injection():
    template = _domain_details_template()
    script = _domain_details_script()

    assert "Domain Ownership" in template
    assert '<details id="domain-ownership"' in template
    assert "data-domain-detail-reload" in template
    assert "data-domain-detail-refresh-dns" in template
    assert "data-domain-detail-delete" in template
    assert "data-domain-detail-verify-ownership" in template
    assert "data-domain-detail-verify-cloudflare" in template
    assert "data-domain-detail-reload" in script
    assert "data-domain-detail-refresh-dns" in script
    assert "refreshDNSData" in script
    assert "data-domain-detail-delete" in script
    assert "data-domain-detail-verify-ownership" in script
    assert "data-domain-detail-verify-cloudflare" in script
    assert "/ownership" in script
    assert "/ownership/verify" in script
    assert "Report mailbox access is enough" not in template
    assert "deleteDomain()" in script
    assert '@click="reloadPageData()"' not in template
    assert '@click="refreshDNSData()"' not in template
    assert '@click="deleteDomain()"' not in template
    assert '@click="verifyDomainOwnership()"' not in template
    assert '@click="verifyDomainOwnershipCloudflare()"' not in template
    assert "Type the domain name to confirm" in script
    assert "sourcesLoading" in template


def test_domain_details_externalizes_detail_actions_without_inline_handlers():
    template = _domain_details_template()
    script = _domain_details_script()

    assert "data-domain-detail-remediation-action" in template
    assert "handleRemediationAction" in script
    assert "findRemediationItem" in script
    assert "data-domain-detail-selector-add" in template
    assert "data-domain-detail-selector-delete" in template
    assert "data-domain-detail-selector-input" in template
    assert "data-domain-detail-copy-value" in template
    assert "data-domain-detail-dns-action" in template
    assert "handleDnsPlanAction" in script
    assert "findDnsPlan" in script
    assert "copyValue" in script
    assert "@click=" not in template
    assert "@keydown" not in template
    assert "navigator.clipboard.writeText" not in template
    assert "x-html" not in template
    assert "sourceEvidenceCount" in template
    assert "x-html" not in template


def test_domain_details_exposes_dns_provider_repair_context_without_html_injection():
    template = _domain_details_template()
    script = _domain_details_script()

    assert 'id="mail-auth-wizard"' in template
    assert "Mail authentication wizard" in template
    assert "mailAuthWizardSteps" in template
    assert "targetRecordByCode" in script
    assert "target_dmarc" in script
    assert "target_spf" in script
    assert "target_dkim" in script
    assert "Provider repair readiness" in template
    assert "Before apply" in template
    assert "After apply" in template
    assert "item.provider_repair_plan.pre_apply_checks" in template
    assert "item.provider_repair_plan.post_apply_checks" in template
    assert "item.provider_repair_plan.operator_warning" in template
    assert "Apply confirmation" in template
    assert "Attempt history" in template
    assert "remediationQueue.summary.provider_apply_verified" in template
    assert "remediationQueue.summary.provider_apply_attempts" in template
    assert "providerRepairPlanHasChecks" in script
    assert "plan?.kind !== 'dns_provider_repair'" in script
    assert "providerRepairConfirmationText" in script
    assert "providerRepairAttemptHistoryText" in script
    assert "providerRepairAttemptEntries" in script
    assert "formatIsoDate(entry.created_at)" in script
    assert "provider-attempt-" in template
    assert "{ value: 'provider_checks', label: 'Provider checks' }" in script
    assert "filter === 'provider_checks'" in script
    assert "{ value: 'provider_history', label: 'Provider history' }" in script
    assert "filter === 'provider_history'" in script
    assert "remediationQueue.summary.provider_pre_apply_checks" in template
    assert "providerContextStatusLabel" in script
    assert "providerContextSummary" in script
    assert "providerContextSteps" in script
    assert "providerContextCtaHref" in script
    assert "/settings#provider-integrations" not in template
    assert "x-html" not in template


def test_domain_details_exposes_remediation_action_plans_without_html_injection():
    template = _domain_details_template()
    script = _domain_details_script()

    assert "Remediation Queue" in template
    assert "Action plan" in template
    assert "item.confidence" in template
    assert "item.action_plan.owner" in template
    assert "item.action_plan.prerequisites" in template
    assert "item.action_plan.steps" in template
    assert "item.action_plan.completion_criteria" in template
    assert "item.action_plan.safe_to_automate" in template
    assert "Decision checkpoints" in template
    assert "item.action_plan.decision_checkpoints" in template
    assert "item.action_plan.requires_fresh_evidence" in template
    assert "item.action_plan.rollback_plan" in template
    assert "Loop completion gate" in template
    assert "remediationCompletionLabel(remediationQueue.completion)" in template
    assert "remediationCompletionClass(remediationQueue.completion)" in template
    assert "remediationCompletionLabel(completion)" in script
    assert "remediationCompletionClass(completion)" in script
    assert "remediationQueue.summary.closure_gate_required" in template
    assert "remediationQueue.summary.rollback_guidance" in template
    assert "'loop.closure_gate_required'" in template
    assert "'loop.rollback_guidance'" in template
    assert "item.repair_progression" in template
    assert "repairProgressionNextStep(item.repair_progression)" in template
    assert "repairProgressionClass(item.repair_progression)" in template
    assert "Verification" in template
    assert "item.verification_plan.status" in template
    assert "item.verification_plan.evidence_needed" in template
    assert "item.verification_plan.next_check" in template
    assert "Closure gate" in template
    assert "item.verification_plan.closure_gate" in template
    assert "item.verification_plan.stale_evidence_warning" in template
    assert "Notification dispatch" in template
    assert "item.notification.dispatch.blocked_reasons" in template
    assert "(reason, index) in item.notification.dispatch.blocked_reasons" in template
    assert "'-dispatch-blocker-' + index" in template
    assert "blocked_reasons[0]" not in template
    assert "Remediation loop" in template
    assert (
        "remediationLoopStatusLabel(remediationLoopEffectiveStatus(remediationQueue.loop))"
        in template
    )
    assert "remediationLoopEffectiveStatus(loop)" in script
    assert "remediationIncidentLabel" in template
    assert "remediationTrackLabel" in template
    assert "visibleRemediationDecisions(item)" in template
    assert "Dispatch" in template
    assert ':data-domain-detail-remediation-action="decision"' in template
    assert 'data-domain-detail-remediation-action="dispatch"' in template
    assert "recordRemediationLifecycle(item, 'previewed')" not in template
    assert "recordRemediationLifecycle(item, 'acknowledged')" not in template
    assert "recordRemediationLifecycle(item, 'resolved')" not in template
    assert "dispatchRemediationNotification(item)" not in template
    assert "handleRemediationAction" in script
    assert "remediationDecisionLabel" in script
    assert "remediationActionNote(action)" in script
    assert "remediationEvidenceRefreshError(key)" in script
    assert "Evidence refresh incomplete:" in script
    assert "approve_after_preview" in script
    assert "mark_unknown" in script
    assert "humanizeToken" in script
    assert "/remediation/notifications/audit" in script
    assert "/remediation/notifications/dispatch" in script
    assert "note" in script
    assert "payload.note = note" in script
    assert "trimmed ? trimmed.slice(0, 500) : undefined" in script
    assert "No DNS changes were made" in script
    assert "x-html" not in template


def test_domain_details_investigation_actions_include_rejection_option():
    """The UI should expose every investigation lifecycle decision from the API."""
    script = _domain_details_script()
    investigate_start = script.index("investigate: [")
    investigate_end = script.index("],", investigate_start)
    investigate_actions = script[investigate_start:investigate_end]

    assert "'mark_legitimate'" in investigate_actions
    assert "'convert_to_manual_action'" in investigate_actions
    assert "'rejected'" in investigate_actions


def test_domain_details_distinguishes_evidence_verified_repairs_without_html_injection():
    template = _domain_details_template()
    script = _domain_details_script()

    assert "Evidence-verified repairs" in template
    assert (
        "These items were marked resolved by an operator and are no longer present "
        "in the current remediation queue."
    ) in template
    assert "Keep monitoring this repair; no DNS or mail settings were changed" in template
    assert "const visible = (this.remediationQueue.verified_items || []).length" in script
    assert "dispatch_verified_fixed_hidden" in script
    assert "this.verifiedItemsTotalCount() - visible" in script
    assert "visibleVerifiedItems()" in template
    assert "hasMoreVisibleVerifiedItems()" in template
    assert "showAllVerifiedRemediationItems" in template
    assert "Show compact view" in template
    assert "Show all visible repairs" in template
    assert "items.slice(0, VERIFIED_ITEMS_COMPACT_LIMIT)" in script
    assert "verified.item_id" in template
    assert "verified.label" in template
    assert "verified.freshness_label" in template
    assert "verifiedFreshnessClass(verified)" in template
    assert "verifiedFreshnessWarning(verified)" in template
    assert "verifiedFreshnessClass(verified)" in script
    assert "verifiedFreshnessWarning(verified)" in script
    assert "verifiedFreshnessCounts()" in template
    assert "verifiedFreshnessCounts()" in script
    assert "unknown age" in template
    assert "Freshness gate" in template
    assert "Refresh the remediation queue and evidence before relying on this repair" in script
    assert "verified.detail" in template
    assert "Closure gate" in template
    assert "verified.closure_gate" in template
    assert "Next safe action" in template
    assert "verified.next_safe_action" in template
    assert "verified.operator_note" in template
    assert "formatIsoDate(verified.recorded_at)" in template
    assert "verified.actor_type" in template
    assert "x-html" not in template


def test_domain_details_exposes_source_ip_intelligence_without_html_injection():
    template = _domain_details_template()
    script = _domain_details_script()

    assert "IP Intelligence" in template
    assert "PTR unavailable" in template
    assert "sourceGeoSummary(source)" in script
    assert "String(value).trim().toLowerCase() !== 'unknown'" in script
    assert "Geo unavailable" in script
    assert "pathValue(source, 'geo.country_code', 'ZZ')" in template
    assert "pathValue(source, 'geo.country')" in template
    assert "source.geo?.region" in script
    assert "source.geo?.asn" in script
    assert "source.geo?.network" in script
    assert "source.geo?.bgp_prefix" in script
    assert "source.geo?.registry" in script
    assert "source.geo?.allocated" in script
    assert "source.geo?.network_source" in script
    assert "source.first_seen" in template
    assert "source.last_seen" in template
    assert "source.active_days" in template
    assert "source.report_count" in template
    assert "pathValue(source, 'volume_history.length', 0)" in template
    assert "data-domain-detail-refresh-reputation" in template
    assert "data-domain-detail-refresh-reputation" in script
    assert "refreshSourceReputation" in script
    assert "sourceReputationRefreshing" in template
    assert "sourceReputationRefreshError" in template
    assert "this.sourceReputationRefreshError = '';" in script
    assert "keepExistingSourcesVisible" in script
    assert "this.sourcesLoading = !keepExistingSourcesVisible;" in script
    assert "Showing the last loaded sending sources." in script
    assert "const hasExistingSources = (this.sources || []).length > 0;" in script
    assert "if (!options.preserveOnFailure || !hasExistingSources) {" in script
    assert "if (options.preserveOnFailure && hasExistingSources) {" in script
    assert "sourceSeenLabel" in script
    assert "sourceVolumeBars" in script
    assert "source.reputation.status" in template
    assert "source.reputation.feed_status" in template
    assert "source.reputation.feed_summary" in template
    assert "reputationRiskLabel" in script
    assert "pathValue(source, 'reputation.listings.length', 0)" in template
    assert "reputationStatusClass" in script
    assert "reputationFeedClass" in script
    assert "reputationLabel" in script
    assert "reputationEvidencePreview" in script
    assert "Use Refresh reputation" in template
    assert 'colspan="9"' in template
    assert "x-effect=\"$el.style.height = point.height + '%'" not in template
    assert 'aria-label="Recent sending volume"' in template
    assert ":viewBox=\"'0 0 ' + point.width + ' 100'\"" in template
    assert '<template x-for="point in sourceVolumeBars(source)"' in template
    assert "point.y" in template
    assert "point.width" in template
    assert '<svg class="h-8 w-full overflow-visible"' not in template
    assert "x-html" not in template
    assert not _has_inline_style(template)


def test_domain_details_distinguishes_loading_error_and_empty_states():
    template = _domain_details_template()
    script = _domain_details_script()

    assert "loadInitialData()" in script
    assert "async fetchWithTimeout" in script
    assert "Promise.allSettled" in script
    assert (
        "const response = await this.fetchWithTimeout(\n                    `/api/v1/domains/${this.domainId}/stats`"
        in script
    )
    assert "The request timed out. Reload data or try again in a moment." in script
    assert "dnsRecordsLoading" in template
    assert "Checking DMARC record..." in template
    assert "DNS records could not be loaded." in script
    assert "dnsEvidenceUnavailable" in template
    assert "DNS evidence unavailable. Reload DNS to retry the live lookup." in script
    assert "dnsLookupStaleCache" in script
    assert "dnsLookupFallback" in script
    assert "dnsLookupNoticeVisible" in template
    assert "dnsLookupNoticeText" in template
    assert "dnsRecordText" in template
    assert "DNS lookup failed; cached or report evidence may be incomplete." in script
    assert "reportsLoading" in template
    assert "Loading recent reports..." in template
    assert "Recent reports could not be loaded." in script
    assert "sourceIntelligence.loading" in template
    assert "Loading source intelligence..." in template
    assert "Source intelligence could not be loaded." in script
    assert "sourceIntelligenceRefreshError" in script
    assert "sourceIntelligenceRefreshError" in template
    assert "Showing the last loaded source intelligence." in script
    assert "preserveOnFailure: true" in script
    assert "remediationQueueLoading" in script
    assert "remediationQueueError" in script
    assert "primaryRemediationItem" in script
    assert "primaryRemediationNextStep" in script
    assert "primaryRemediationNextSafeAction" in script
    assert "primaryRemediationScopeNote" in script
    assert "primaryRemediationReadinessContext" in script
    assert "primaryRemediationBlockedText" in script
    assert "primaryRemediationDispatchText" in script
    assert "primaryRemediationFreshnessText" in script
    assert "primaryRemediationClosureGateText" in script
    assert "primaryRemediationStaleWarningText" in script
    assert "primaryRemediationEvidenceHref" in script
    assert "primaryRemediationCtaLabel" in script
    assert "primaryRemediationCtaHref" in script
    assert "primaryRemediationVerificationStatusLabel" in script
    assert "primaryRemediationVerificationStatusClass" in script
    assert "primaryRemediationEvidenceNeededText" in script
    assert "primaryRemediationFailureModeText" in script
    assert "remediationStateLabel(state)" in script
    assert "needs_approval: 'Needs approval'" in script
    assert "verificationPlanStatusLabel(plan)" in script
    assert "verificationPlanStatusClass(plan)" in script
    assert "verificationPlanEvidenceNeededText(plan)" in script
    assert "Next remediation" in template
    assert "Loading next remediation..." in template
    assert "Next remediation could not be loaded." in template
    assert "No remediation queued" in template
    assert "remediationStateLabel(primaryRemediationItem.state)" in template
    assert "remediationStateLabel(item.state)" in template
    assert "primaryRemediationItem.state.split('_').join(' ')" not in template
    assert "item.state.split('_').join(' ')" not in template
    assert "repairReadinessLabel(primaryRemediationItem.repair_progression)" in template
    assert "repairReadinessScore(primaryRemediationItem.repair_progression)" in template
    assert "Next safe action" in template
    assert "primaryRemediationScopeNote" in template
    assert "Freshness required" in template
    assert "primaryRemediationFreshnessText" in template
    assert "primaryRemediationClosureGateText" in template
    assert "primaryRemediationStaleWarningText" in template
    assert "primaryRemediationEvidenceHref" in template
    assert "primaryRemediationVerificationStatusClass" in template
    assert "primaryRemediationVerificationStatusLabel" in template
    assert "primaryRemediationEvidenceNeededText" in template
    assert "primaryRemediationFailureModeText" in template
    assert "Evidence needed:" in template
    assert "If not fixed:" in template
    assert "Open evidence" in template
    assert "Show evidence" in template
    assert "More actions" in template
    assert "More queue signals" in template
    assert "data-domain-detail-remediation-refresh-evidence" in template
    assert (
        "remediationEvidenceRefreshActionLabel(primaryRemediationItem.evidence_refresh)" in template
    )
    assert "Repair readiness" in template
    assert "primaryRepairReadinessReasonText" in script
    assert "repairReadinessLabel(primaryRemediationItem.repair_progression)" in template
    assert "repairReadinessScore(primaryRemediationItem.repair_progression)" in template
    assert "repairReadinessReason(progression)" in script
    assert "repairReadinessBlockedText(progression)" in script
    assert 'href="#remediation-queue"' in template
    assert 'id="remediation-queue"' in template
    assert "Loading remediation queue..." in template
    assert "Remediation queue could not be loaded." in script
    assert "Retry remediation queue" in template
    assert "data-domain-detail-remediation-retry" in template
    assert 'x-show="!remediationQueueLoading && !remediationQueueError"' in template
    assert "flex flex-wrap items-center gap-2 text-xs" in template
    assert "remediationQueue.summary.total" in template
    assert "remediationQueue.summary.approval_ready" in template
    assert "remediationQueue.summary.manual_action" in template
    assert "remediationQueue.summary.provider_preview_available" in template
    assert "No sending sources match this filter." in template
    assert "filters.sourceRiskFilter" in template
    assert "sourceRiskCounts" in template
    assert "sourceRiskMatches(source, this.filters.sourceRiskFilter)" in script
    assert "sourceActivityLabel(source)" in template
    assert "sourceActivityClass(source)" in template
    assert "reputationAgeLabel(source.reputation)" in template
    assert "Math.log10(count + 1)" in script
    assert (
        "(!sourceIntelligence.loading && !sourceIntelligence.error ? sourceIntelligence.regions.slice(0, 4) : [])"
        in template
    )
    assert (
        "(!sourceIntelligence.loading && !sourceIntelligence.error ? sourceIntelligence.anomalies.slice(0, 4) : [])"
        in template
    )
    assert "(!sourcesLoading && !sourcesError ? filteredSources : [])" in template
    assert "(!reportsLoading && !reportsError ? reports : [])" in template
    assert (
        "(!remediationQueueLoading && !remediationQueueError ? visibleRemediationQueueItems() : [])"
        in template
    )
    assert (
        'x-if="!remediationQueueLoading && !remediationQueueError && remediationQueue.items.length === 0"'
        in template
    )
    assert "x-html" not in template


def test_domain_details_redirects_to_domain_management_after_delete_success():
    script = _domain_details_script()
    delete_body = _template_section_between_markers(
        script, "async deleteDomain()", "enableMigrationTools()"
    )

    assert "if (response.status === 204)" in delete_body
    redirect_idx = delete_body.index("window.location.href = '/domains';")
    alert_idx = delete_body.index("window.alert(data.detail")
    assert redirect_idx < alert_idx
    assert "return;" in delete_body[redirect_idx:alert_idx]


def test_report_detail_exposes_record_review_guidance_without_html_injection():
    template = (
        Path(__file__).resolve().parents[1] / "templates" / "report_detail.html"
    ).read_text()

    assert "record.review_status" in template
    assert "record.failure_reasons" in template
    assert "record.next_steps" in template
    assert "Needs review" in template
    assert "x-html" not in template


def test_report_detail_distinguishes_dmarc_failure_from_mixed_authentication():
    payload = {
        "records": [
            {
                "count": 1,
                "dkim_result": "fail",
                "spf_result": "fail",
                "disposition": "reject",
                "source_ip": "192.0.2.10",
                "source_details": {
                    "network": "Example Network",
                    "sender": {"provider": "Example Sender", "status": "known"},
                },
            },
            {
                "count": 2,
                "dkim_result": "fail",
                "spf_result": "pass",
                "disposition": "none",
                "source_ip": "192.0.2.11",
                "source_details": {
                    "network": "Example Network",
                    "sender": {"provider": "Example Sender", "status": "known"},
                },
            },
        ]
    }

    result = _run_report_detail_expression(
        payload,
        "({ counts: app.investigationCounts, title: app.investigationTitle, clusters: app.senderClusters })",
    )

    assert result["counts"] == {"failed": 1, "mixed": 2, "unknown": 0}
    assert result["title"] == "1 message needs authentication review"
    assert result["clusters"][0]["failures"] == 1
    assert result["clusters"][0]["mixed"] == 2


def test_report_detail_count_labels_handle_singular_and_plural():
    result = _run_report_detail_expression(
        {"records": []},
        "[app.countLabel(1, 'IP'), app.countLabel(2, 'IP'), app.countLabel(1, 'record')]",
    )

    assert result == ["1 IP", "2 IPs", "1 record"]


def test_members_template_uses_membership_api_without_html_injection():
    template = (Path(__file__).resolve().parents[1] / "templates" / "members.html").read_text()
    script = (Path(__file__).resolve().parents[1] / "static" / "js" / "members-page.js").read_text()

    assert _has_script_src(template, "/static/js/members-page.js")
    assert 'x-data="membershipApp"' in template
    assert "membershipApp()" not in template
    assert "Alpine.data('membershipApp', membershipApp)" in script
    assert 'x-init="init()"' not in template
    assert "/api/v1/organizations" in script
    assert "/api/v1/memberships/organizations/" in script
    assert "/api/v1/memberships/workspaces/" in script
    assert "/api/v1/organizations" not in template
    assert "/api/v1/memberships/organizations/" not in template
    assert "/api/v1/memberships/workspaces/" not in template
    assert "Billing & Plan" in template
    assert "currentBillingOwner().owner" in template
    assert "planLimitRows()" in template
    assert "limitTrackWidth(limit)" in template
    assert "limitTrackWidth" in script
    assert 'x-effect="$el.style.width' not in template
    assert "invoice_delivery_label" in template
    assert 'x-text="membership.user.email"' in template
    assert "@click" not in template
    assert "@change" not in template
    assert "@submit" not in template
    assert "data-members-page" in template
    assert "data-members-scope" in template
    assert "data-members-invite-form" in template
    assert "data-members-role-select" in template
    assert "bindPageControls()" in script
    assert "findMembershipByUserId" in script
    assert "data-members-role-select" in script
    assert '@change="updateMembership(membership, true)"' not in template
    assert "x-html" not in template
    assert not _has_inline_script(template)
    assert not _has_inline_style(template)
    assert _has_inline_script('<script data-src="/static/js/members-page.js"></script>')
    assert not _has_inline_style('<div data-style="ok" x-effect="$el.style.width = width"></div>')
    assert _has_inline_style('<div data-style="ok" :style="bad"></div>')
    assert _has_inline_style("<progress x-bind:style=\"{ width: progress + '%' }\" />")
    assert _has_inline_style("<div x-bind:style=\"{ width: progress + '%' }\"></div>")


def test_legacy_login_script_uses_css_class_instead_of_inline_style():
    script = _legacy_login_script()
    stylesheet = _main_stylesheet()

    assert "login-error-message" in script
    assert ".login-error-message" in stylesheet
    assert re.search(
        r'<div\b(?=[^>]*\bid="login-error")'
        r'(?=[^>]*\bclass="[^"]*\bhidden\b[^"]*\blogin-error-message\b)[^>]*>',
        script,
    )
    assert "style=" not in script


def test_base_template_propagates_selected_workspace_context():
    template = (
        Path(__file__).resolve().parents[1] / "templates" / "layouts" / "base.html"
    ).read_text()
    script = (Path(__file__).resolve().parents[1] / "static" / "js" / "base-layout.js").read_text()

    assert 'src="/static/js/base-layout.js"' in template
    assert "data-multi-workspace-ui" in template
    assert "data-demo-mode" in template
    assert 'x-data="userMenu"' in template
    assert "userMenu({" not in template
    assert "Alpine.data('userMenu', userMenu)" in script
    assert "multiWorkspaceUiEnabled" in script
    assert "/api/v1/workspaces" in script
    assert "dmarq.selectedWorkspaceId" in script
    assert "X-DMARQ-Workspace-ID" in script
    assert "withoutWorkspaceContext(input, init)" in script
    assert "headers.delete(workspaceHeaderName)" in script
    assert "dmarq:workspace-changed" in script
    assert "workspaces.length > 1" not in template
    assert "showWorkspaceSwitcher" in template
    assert "normalizeUser" in script
    assert "normalizeWorkspace" in script
    assert "localStorage.removeItem('dmarq.selectedWorkspaceId')" in script
    assert "input instanceof URL" in script
    assert 'x-init="loadUser()"' not in template
    assert '@change="selectWorkspace($event.target.value)"' not in template
    assert "data-user-menu" in template
    assert "data-workspace-switcher" in template
    assert "bindControls()" in script
    assert "data-workspace-switcher" in script
    assert "user.full_name || user.email" not in template
    assert "(user.full_name || user.email || '?')[0].toUpperCase()" not in template
    assert ':disabled="!workspace.active"' not in template
    assert ':disabled="workspace.disabled"' in template
    assert "onclick=" not in template
    assert "data-release-modal-trigger" in template
    assert 'aria-label="Show release notes for {{ release_info.label }}"' in template
    assert 'aria-label="Open account menu"' in template
    assert '<span class="text-[11px] font-semibold leading-tight">Provider</span>' in template
    assert '<span class="text-[11px] font-semibold leading-tight">Dashboard</span>' in template
    for rail_label in (
        "Domains",
        "Reports",
        "Mail Sources",
        "Members",
        "More",
        "Settings",
    ):
        assert (
            f'<span class="text-[11px] font-semibold leading-tight">{rail_label}</span>' in template
        )
    assert 'href="/forensics"' in template
    assert 'href="/tls-reports"' in template
    assert 'href="/onboarding"' in template
    assert 'href="/static/css/app.css"' in template
    assert "cdn.tailwindcss.com" not in template
    assert "Full changelog" in template
    assert "release_info.changelog_url" in template
    assert "release_info.environment" in template
    assert "release_info.build.image" in template
    assert "release_info.build.image_tag" in template
    assert "/api/v1/health/release" in template
    assert "bindReleaseModalTriggers" in script
    assert "dmarq-release-modal" in script
    assert 'src="/static/js/vendor/alpine.min.js"' in template
    assert "cdn.jsdelivr.net" not in template
    assert "data-demo-readonly-banner" in template
    assert "data-demo-readonly-toast" in script
    assert "Diese öffentliche Demo ist read-only" in script
    assert "mirrorDemoReadOnlyError" in script
    assert "event.target" in script
    assert "target instanceof Element" in script
    assert "!modal.open" in script
    assert "current_path.startswith('/members')" in template


def test_theme_scripts_use_the_configured_dark_theme_name():
    root = Path(__file__).resolve().parents[1]
    files = [
        root / "templates" / "layouts" / "base.html",
        root / "static" / "js" / "base-layout.js",
        root / "static" / "js" / "login-page.js",
        root / "static" / "js" / "setup-page.js",
    ]
    contents = [path.read_text() for path in files]

    assert all("dmarqdark" not in content for content in contents)
    assert all("'data-theme', 'dark'" in content for content in contents[1:])


def test_base_template_hides_workspace_controls_in_single_user_mode():
    rendered = _render_template("layouts/base.html", multi_workspace_ui_enabled=False)

    assert 'data-multi-workspace-ui="false"' in rendered
    assert 'id="workspace-switcher"' not in rendered
    assert 'href="/members"' not in rendered
    assert 'aria-label="Members"' not in rendered
    assert "Members</a>" not in rendered


def test_base_template_shows_demo_read_only_banner_when_demo_mode_enabled():
    rendered = _render_template("layouts/base.html", demo_mode=True)

    assert 'data-demo-mode="true"' in rendered
    assert "Öffentliche Demo - read-only" in rendered
    assert "Änderungen werden nicht gespeichert." in rendered


def test_base_template_shows_workspace_controls_when_multi_workspace_enabled():
    rendered = _render_template("layouts/base.html", multi_workspace_ui_enabled=True)

    assert 'data-multi-workspace-ui="true"' in rendered
    assert 'id="workspace-switcher"' in rendered
    assert 'href="/members"' in rendered
    assert 'aria-label="Members"' in rendered
    assert "Members</a>" in rendered


def test_base_template_uses_provider_console_navigation_for_provider_demo():
    rendered = _render_template(
        "layouts/base.html",
        multi_workspace_ui_enabled=False,
        provider_demo_enabled=True,
        provider_console_page=True,
    )

    assert 'aria-label="DMARQ Provider Console"' in rendered
    assert 'href="/provider-demo"' in rendered
    assert "Kundenkonten" in rendered
    assert "Billing offen" in rendered
    assert "Single-user-Demo" in rendered
    assert "Öffentliche Demo - read-only" not in rendered
    assert 'href="/members"' not in rendered


def test_onboarding_template_uses_single_user_setup_story_by_default():
    rendered = _render_template("onboarding.html", multi_workspace_ui_enabled=False)
    template = _onboarding_template()
    script = _onboarding_script()

    assert "Mail health setup" in rendered
    assert "Setup path" in rendered
    assert "Connect Gmail or IMAP" in rendered
    assert 'x-text="applyButtonLabel"' in rendered
    assert "Apply setup" in script
    assert "One monitored domain with DMARC report and DNS setup tasks." in rendered
    assert 'data-multi-workspace-ui="false"' in rendered
    assert 'src="/static/js/onboarding-page.js"' in template
    assert "data-onboarding-page" in template
    assert 'x-data="workspaceOnboarding"' in template
    assert "workspaceOnboarding({" not in template
    assert "Alpine.data('workspaceOnboarding', workspaceOnboarding)" in script
    assert "/api/v1/onboarding/preview" in script
    assert "/api/v1/onboarding/apply" in script
    assert "draftFields()" in script
    assert "normalizeDomain(value)" in script
    assert "normalizeTasks(tasks)" in script
    assert "canApplySetup" in script
    assert "applyButtonLabel" in script
    assert "previewSignature()" in script
    assert "Preview setup tasks before applying" in template
    assert "dmarq.selectedWorkspaceId" in script
    assert "bindControls()" in script
    assert "data-onboarding-preview" in template
    assert "data-onboarding-preview" in script
    assert "data-onboarding-apply" in template
    assert "data-onboarding-apply" in script
    assert "data-onboarding-mail-path" in template
    assert "data-onboarding-mail-path" in script
    assert '@click="previewPlan"' not in template
    assert '@click="applyPlan"' not in template
    assert '@click="form.mailSourcePath = ' not in template
    assert "result?.workspace" not in template
    assert "form.mailSourcePath ===" not in template
    assert "tasks.length ?" not in template
    assert "!tasks.length" not in template
    assert "task.href || '#'" not in template
    assert "showWorkspaceSwitchSuccess" in template
    assert "taskPreviewLabel" in template
    assert "showNoTasks" in template
    assert "Current setup" in template
    assert "setupStatusItems" in script
    assert "loadSetupState()" in script
    assert "/api/v1/domains/summary?include_empty=true" in script
    assert "/api/v1/mail-sources" in script
    assert "data-onboarding-reconfigure" in template
    assert "data-onboarding-reconfigure" in script
    assert "data-onboarding-form" in template
    assert "data-onboarding-form" in script
    assert "Unsaved setup changes" in template
    assert 'x-init="init()"' not in template
    assert not re.search(r"<script\b(?![^>]*\bsrc=)[^>]*>", template, re.IGNORECASE)
    assert "Account boundary" not in rendered
    assert "Owner ready" not in rendered
    assert "Starter plan entitlement records" not in rendered


def test_onboarding_template_keeps_workspace_story_for_multi_workspace_mode():
    rendered = _render_template("onboarding.html", multi_workspace_ui_enabled=True)
    script = _onboarding_script()

    assert "Workspace onboarding" in rendered
    assert "Account boundary" in rendered
    assert 'x-text="applyButtonLabel"' in rendered
    assert "Create workspace" in script
    assert "Organization and workspace" in rendered
    assert "Starter plan entitlement records" in rendered
    assert 'data-multi-workspace-ui="true"' in rendered


def test_dashboard_hides_multi_user_demo_mode_controls():
    template = _dashboard_template()

    assert "Deployment Zoom" not in template
    assert "Demo experience" not in template
    assert "Start tour" not in template
    assert "View as" not in template
    assert "Open operator data" not in template
    assert "Impersonate" not in template
    assert "tenant-workspace-drilldown" not in template
    assert "Provider billing samples" not in template
    assert "/api/v1/operator/demo/multi-user" not in template
    assert "x-html" not in template


def test_provider_demo_is_separate_from_dashboard_controls():
    template = _provider_demo_template()
    script = _provider_demo_script()
    dashboard = _dashboard_template()

    assert "data-provider-demo" in template
    assert "/api/v1/operator/provider-console" in script
    assert "/api/v1/operator/support-session" in script
    assert "/api/v1/operator/demo/provider-console" not in script
    assert "/api/v1/operator/demo/support-session" not in script
    assert "/api/v1/operator/demo/multi-user" not in dashboard
    assert "/api/v1/operator/demo/support-session" not in dashboard
    assert "Kundenkonten verwalten" in template
    assert "Kundenkonten" in template
    assert "Kundenkonto anlegen" in template
    assert "Billing & Limits" in template
    assert "Benutzer einladen" in template
    assert "Single-user-Demo" in template
    assert "https://demo.dmarq.org/" in template
    assert "data-provider-impersonation-form" in template
    assert "data-provider-create-form" in template
    assert "data-provider-account-view" in template
    assert "data-provider-customer-view" not in template
    assert "data-provider-account-open" in template
    assert "data-provider-customer-tab" not in template
    assert "data-provider-demo-expression-error" in template
    assert "Alpine Expression Error" in script
    assert "workspace.domains.join" not in template
    assert "tenant.billing_status || tenant.billing_mode" not in template
    assert "selectedTenant.billing_status || selectedTenant.billing_mode" not in template
    assert "selectedTenant.monthly_charge_cents" not in template
    assert "fuer " not in template
    assert "oeffnen" not in template
    assert "Aender" not in template
    assert 'href="/members"' not in template
    assert "/domains/" not in template
    assert "Operator checklist" not in template
    assert "providerDemo" in script
    assert "createAccount" in script
    assert "saveBilling" in script
    assert "addUser" in script
    assert "startSupportSession" in script
    assert "x-html" not in template
    assert "innerHTML" not in script


def test_dashboard_distinguishes_loading_error_and_empty_states():
    template = _dashboard_template()
    script = _dashboard_script()

    assert "Loading dashboard data" in template
    assert "Dashboard could not be loaded" in template
    assert "dashboardLoading" in script
    assert "dashboardError" in script
    assert "dashboardRefreshError" in script
    assert "Dashboard data could not be loaded." in script
    assert 'x-show="!dashboardLoading && !dashboardError && !hasReportData"' in template


def test_dashboard_trigger_poll_uses_post_action_not_get_link():
    template = _dashboard_template()
    script = _dashboard_script()

    assert 'href="/api/v1/admin/trigger-poll"' not in template
    assert "data-dashboard-trigger-poll" in template
    assert "triggerPollNow()" in script
    assert "method: 'POST'" in script
    assert "Report Intake Status" in template
    assert "Gmail API" in script
    assert "summarizePollResults(data)" in script
    assert "aggregate report" in script
    assert "new domains:" in script
    assert "skipped" in script
    assert "failed" in script
    assert "triggerPollMessage" in script
    assert 'role="status"' in template
    assert 'aria-live="polite"' in template
    assert 'aria-atomic="true"' in template


def test_dashboard_poll_summary_reports_source_totals_and_outcomes():
    summary = _run_dashboard_poll_summary(
        {
            "sources_polled": 2,
            "source_methods": ["GMAIL_API", "M365_GRAPH"],
            "sources": [
                {
                    "processed": 3,
                    "reports_found": 2,
                    "forensic_reports_found": 1,
                    "new_domains": ["example.com", "example.net"],
                },
                {
                    "processed": 1,
                    "reports_found": 0,
                    "new_domains": ["example.com", "example.org", "example.edu"],
                    "skipped": True,
                    "success": False,
                },
            ],
        }
    )

    assert summary == (
        "Polling finished for 2 sources (Gmail API, Microsoft 365); "
        "4 emails processed; 2 aggregate reports found; 1 forensic report found; "
        "new domains: example.com, example.net, example.org +1 more; 1 skipped."
    )


def test_dashboard_poll_summary_uses_fallback_message_without_sources():
    assert (
        _run_dashboard_poll_summary({"sources_polled": 0, "message": "No mailbox configured."})
        == "No mailbox configured."
    )
