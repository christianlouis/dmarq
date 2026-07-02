import re
from pathlib import Path

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


def _dashboard_template() -> str:
    return _read_project_file("templates", "index.html")


def _dashboard_script() -> str:
    return _read_project_file("static", "js", "dashboard-page.js")


def _operations_template() -> str:
    return _read_project_file("templates", "operations.html")


def _operations_script() -> str:
    return _read_project_file("static", "js", "operations-page.js")


def _reports_template() -> str:
    return _read_project_file("templates", "reports.html")


def _reports_script() -> str:
    return _read_project_file("static", "js", "reports-page.js")


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

    assert 'src="/static/js/chart.umd.min.js"' in template
    assert 'src="/static/js/dashboard-page.js"' in template
    assert not re.search(r"<script\b(?![^>]*\bsrc=)[^>]*>", template, re.IGNORECASE)


def test_operations_uses_external_page_script_for_csp_migration():
    template = _operations_template()
    script = _operations_script()

    assert 'src="/static/js/operations-page.js"' in template
    assert "operationsHealth()" in template
    assert "/api/v1/health/operations" in script
    assert "Health details could not be loaded." in script
    assert not re.search(r"<script\b(?![^>]*\bsrc=)[^>]*>", template, re.IGNORECASE)


def test_reports_uses_external_page_script_for_csp_migration():
    template = _reports_template()
    script = _reports_script()

    assert 'src="/static/js/reports-page.js"' in template
    assert "reportsApp()" in template
    assert "/api/v1/reports" in script
    assert "deleteReport(domain, reportId)" in script
    assert not re.search(r"<script\b(?![^>]*\bsrc=)[^>]*>", template, re.IGNORECASE)


def test_domains_uses_external_page_script_for_csp_migration():
    template = _domains_template()
    script = _domains_script()

    assert 'src="/static/js/domains-page.js"' in template
    assert "domainsApp()" in template
    assert "/api/v1/domains/summary" in script
    assert "/api/v1/domains/domains" in script
    assert "createDomain()" in script
    assert not re.search(r"<script\b(?![^>]*\bsrc=)[^>]*>", template, re.IGNORECASE)


def test_upload_uses_external_page_script_for_csp_migration():
    template = _upload_template()
    script = _upload_script()

    assert 'src="/static/js/upload-page.js"' in template
    assert "uploadForm()" in template
    assert "/api/v1/reports/upload" in script
    assert "AbortController" in script
    assert "UPLOAD_TIMEOUT_MS" in script
    assert "this.isUploading = false" in script
    assert "dmarq:refresh-data" in script
    assert not re.search(r"<script\b(?![^>]*\bsrc=)[^>]*>", template, re.IGNORECASE)


def test_profile_uses_external_page_script_for_csp_migration():
    template = _profile_template()
    script = _profile_script()

    assert 'src="/static/js/profile-page.js"' in template
    assert "profileApp()" in template
    assert "/api/v1/auth/me" in script
    assert "Failed to load user profile" in script
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

    assert '<script src="/static/js/profile-page.js"></script>' in rendered


def test_domain_details_exposes_health_history_without_html_injection():
    template = (
        Path(__file__).resolve().parents[1] / "templates" / "domain_details.html"
    ).read_text()

    assert "Health Score Trend" in template
    assert "/posture/history?capture_current=false" in template
    assert "/posture/evidence/export?capture_current=false" in template
    assert "encodeURIComponent(this.domainId)" in template
    assert "health-score-chart" in template
    assert "x-html" not in template


def test_domain_details_exposes_migration_readiness_without_html_injection():
    template = (
        Path(__file__).resolve().parents[1] / "templates" / "domain_details.html"
    ).read_text()

    assert "Migration Readiness" in template
    assert "/migration/readiness" in template
    assert "migration.error" in template
    assert "Migration readiness could not be loaded." in template
    assert "parallel_reporting_days" in template
    assert "migration.export_links" in template
    assert "migration.checklist" in template
    assert "Migration Parity" in template
    assert "/migration/parity" in template
    assert "migrationParity.metrics" in template
    assert "migrationBaseline" in template
    assert "Historical Export Preview" in template
    assert "/migration/import/preview" in template
    assert "loadMigrationImportSample" in template
    assert "previewMigrationImport" in template
    assert "applyMigrationPreviewBaseline" in template
    assert "migrationImport.preview?.sample_rows" in template
    assert "migrationToolsEnabled" in template
    assert "I am migrating data" in template
    assert "x-html" not in template


def test_domain_details_exposes_ownership_and_delete_controls_without_html_injection():
    template = (
        Path(__file__).resolve().parents[1] / "templates" / "domain_details.html"
    ).read_text()

    assert "Domain Ownership" in template
    assert "/ownership" in template
    assert "/ownership/verify" in template
    assert "Report mailbox access is enough" not in template
    assert "deleteDomain()" in template
    assert "Type the domain name to confirm" in template
    assert "sourcesLoading" in template
    assert "sourceEvidenceCount" in template
    assert "x-html" not in template


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

    assert "/api/v1/organizations" in template
    assert "/api/v1/memberships/organizations/" in template
    assert "/api/v1/memberships/workspaces/" in template
    assert "Billing & Plan" in template
    assert "currentBillingOwner().owner" in template
    assert "planLimitRows()" in template
    assert "invoice_delivery_label" in template
    assert 'x-text="membership.user.email"' in template
    assert '@change="updateMembership(membership, membership.active)"' in template
    assert '@change="updateMembership(membership, true)"' not in template
    assert "x-html" not in template


def test_base_template_propagates_selected_workspace_context():
    template = (
        Path(__file__).resolve().parents[1] / "templates" / "layouts" / "base.html"
    ).read_text()
    script = (Path(__file__).resolve().parents[1] / "static" / "js" / "base-layout.js").read_text()

    assert 'src="/static/js/base-layout.js"' in template
    assert "/api/v1/workspaces" in script
    assert "dmarq.selectedWorkspaceId" in script
    assert "X-DMARQ-Workspace-ID" in script
    assert "dmarq:workspace-changed" in script
    assert "input instanceof URL" in script


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


def test_dashboard_trigger_poll_uses_post_action_not_get_link():
    template = _dashboard_template()
    script = _dashboard_script()

    assert 'href="/api/v1/admin/trigger-poll"' not in template
    assert "triggerPollNow()" in template
    assert "method: 'POST'" in script
    assert "triggerPollMessage" in script
    assert 'role="status"' in template
    assert 'aria-live="polite"' in template
    assert 'aria-atomic="true"' in template
