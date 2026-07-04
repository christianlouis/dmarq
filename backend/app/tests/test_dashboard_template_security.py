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


def _run_dashboard_poll_summary(payload: dict[str, object]) -> str:
    node = shutil.which("node")
    if not node:
        pytest.skip("node is required to execute dashboard-page.js behavior tests")

    script_path = Path(__file__).resolve().parents[1] / "static" / "js" / "dashboard-page.js"
    runner = textwrap.dedent("""
        const fs = require('fs');
        const script = fs.readFileSync(process.argv[1], 'utf8');
        const payload = JSON.parse(process.argv[2]);
        const dashboardAppFactory = new Function(`${script}\\nreturn dashboardApp;`)();
        process.stdout.write(dashboardAppFactory().summarizePollResults(payload));
        """)
    result = subprocess.run(
        [node, "-e", runner, str(script_path), json.dumps(payload)],
        check=True,
        text=True,
        capture_output=True,
    )
    return result.stdout


def _operations_template() -> str:
    return _read_project_file("templates", "operations.html")


def _operations_script() -> str:
    return _read_project_file("static", "js", "operations-page.js")


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


def _settings_template() -> str:
    return _read_project_file("templates", "settings.html")


def _settings_script() -> str:
    return _read_project_file("static", "js", "settings-page.js")


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


def test_dashboard_exposes_workspace_health_history():
    template = _dashboard_template()
    script = _dashboard_script()

    assert "Score Trend" in template
    assert "health-trend-chart" in template
    assert "action.evidence" in template
    assert "item.label.replaceAll('_', ' ')" in template
    assert "/api/v1/domains/summary/health/history" in script
    assert "fetchWorkspaceHealthHistory" in script


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

    assert "Loading DMARC reports..." in template
    assert "Reports could not be loaded." in script
    assert "No reports match this filter." in template
    assert "Retry loading reports" in template
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
    assert "showEmptyDomainHint()" in script
    assert "visibleDomains()" in template
    assert "without reports or volume hidden" in template
    assert "Show empty domains" in template
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
    assert "editError" in template
    assert "data-domains-page" in template
    assert "dnsStatusClass(domain" not in template
    assert "'/domains/' + domain.name" not in template
    assert '@submit.prevent="createDomain' not in template
    assert '@submit.prevent="updateDomain' not in template
    assert '@click="closeCreate' not in template
    assert '@click="closeEdit' not in template
    assert '@click=' not in template
    assert "formatCount(domain.reports_count, 'report')" in template
    assert "formatCount(domain.emails_count, 'message')" in template
    assert "formatCount(value, noun)" in script
    assert not re.search(r"<script\b(?![^>]*\bsrc=)[^>]*>", template, re.IGNORECASE)


def test_domains_page_distinguishes_loading_error_and_empty_states():
    template = _domains_template()
    script = _domains_script()

    assert "Loading monitored domains..." in template
    assert "Domains could not be loaded." in script
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
    assert 'x-if="!loading && !loadError && domains.length === 0"' in template


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
    assert "Use Recalculate reputation" in template
    assert "reputationFeedClass" in script
    assert "reputationLabel" in script
    assert "reputationEvidencePreview" in script
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
    assert "migrationImport.preview?.sample_rows" in template
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
    assert "item.action_plan.owner" in template
    assert "item.action_plan.steps" in template
    assert "item.action_plan.completion_criteria" in template
    assert "Notification dispatch" in template
    assert "Reviewed" in template
    assert "Acknowledge" in template
    assert "Resolve" in template
    assert "Dispatch" in template
    assert 'data-domain-detail-remediation-action="previewed"' in template
    assert 'data-domain-detail-remediation-action="acknowledged"' in template
    assert 'data-domain-detail-remediation-action="resolved"' in template
    assert 'data-domain-detail-remediation-action="dispatch"' in template
    assert "recordRemediationLifecycle(item, 'previewed')" not in template
    assert "recordRemediationLifecycle(item, 'acknowledged')" not in template
    assert "recordRemediationLifecycle(item, 'resolved')" not in template
    assert "dispatchRemediationNotification(item)" not in template
    assert "handleRemediationAction" in script
    assert "/remediation/notifications/audit" in script
    assert "/remediation/notifications/dispatch" in script
    assert "No DNS changes were made" in script
    assert "x-html" not in template


def test_domain_details_exposes_source_ip_intelligence_without_html_injection():
    template = _domain_details_template()
    script = _domain_details_script()

    assert "IP Intelligence" in template
    assert "PTR unavailable" in template
    assert "sourceGeoSummary(source)" in script
    assert "String(value).trim().toLowerCase() !== 'unknown'" in script
    assert "Geo unavailable" in script
    assert "source.geo?.country_code" in template
    assert "source.geo?.country" in template
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
    assert "source.volume_history" in template
    assert "data-domain-detail-refresh-reputation" in template
    assert "data-domain-detail-refresh-reputation" in script
    assert "refreshSourceReputation" in script
    assert "sourceReputationRefreshing" in template
    assert "sourceReputationRefreshError" in template
    assert "this.sourceReputationRefreshError = '';" in script
    assert "if (!options.preserveOnFailure) {\n                    this.sources = [];" in script
    assert "sourceSeenLabel" in script
    assert "sourceVolumeBars" in script
    assert "source.reputation.status" in template
    assert "source.reputation.feed_status" in template
    assert "source.reputation.feed_summary" in template
    assert "reputationRiskLabel" in script
    assert "source.reputation?.listings" in template
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
    assert "No sending sources match this filter." in template
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
    assert "event.target" in script
    assert "target instanceof Element" in script
    assert "!modal.open" in script


def test_base_template_hides_workspace_controls_in_single_user_mode():
    rendered = _render_template("layouts/base.html", multi_workspace_ui_enabled=False)

    assert 'data-multi-workspace-ui="false"' in rendered
    assert 'id="workspace-switcher"' not in rendered
    assert 'href="/members"' not in rendered
    assert 'aria-label="Members"' not in rendered
    assert "Members</a>" not in rendered


def test_base_template_shows_workspace_controls_when_multi_workspace_enabled():
    rendered = _render_template("layouts/base.html", multi_workspace_ui_enabled=True)

    assert 'data-multi-workspace-ui="true"' in rendered
    assert 'id="workspace-switcher"' in rendered
    assert 'href="/members"' in rendered
    assert 'aria-label="Members"' in rendered
    assert "Members</a>" in rendered


def test_onboarding_template_uses_single_user_setup_story_by_default():
    rendered = _render_template("onboarding.html", multi_workspace_ui_enabled=False)
    template = _onboarding_template()
    script = _onboarding_script()

    assert "Mail health setup" in rendered
    assert "Setup path" in rendered
    assert "Connect Gmail or IMAP" in rendered
    assert "Apply setup" in rendered
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
    assert 'x-init="init()"' not in template
    assert not re.search(r"<script\b(?![^>]*\bsrc=)[^>]*>", template, re.IGNORECASE)
    assert "Account boundary" not in rendered
    assert "Owner ready" not in rendered
    assert "Starter plan entitlement records" not in rendered


def test_onboarding_template_keeps_workspace_story_for_multi_workspace_mode():
    rendered = _render_template("onboarding.html", multi_workspace_ui_enabled=True)

    assert "Workspace onboarding" in rendered
    assert "Account boundary" in rendered
    assert "Create workspace" in rendered
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


def test_dashboard_distinguishes_loading_error_and_empty_states():
    template = _dashboard_template()
    script = _dashboard_script()

    assert "Loading dashboard data" in template
    assert "Dashboard could not be loaded" in template
    assert "dashboardLoading" in script
    assert "dashboardError" in script
    assert "Dashboard data could not be loaded." in script
    assert 'x-show="!dashboardLoading && !dashboardError && !hasDomainData"' in template


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
        "new domains: example.com, example.net, example.org +1 more; 1 skipped; 1 failed."
    )


def test_dashboard_poll_summary_uses_fallback_message_without_sources():
    assert (
        _run_dashboard_poll_summary({"sources_polled": 0, "message": "No mailbox configured."})
        == "No mailbox configured."
    )
