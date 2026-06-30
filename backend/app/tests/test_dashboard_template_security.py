from pathlib import Path


def test_dashboard_domain_table_uses_safe_dom_rendering():
    """Domain names and counts come from report data and must not be HTML-rendered."""
    template = (Path(__file__).resolve().parents[1] / "templates" / "index.html").read_text()
    populate_start = template.index("populateDomainsTable(domains)")
    helper_start = template.index("createDomainNameCell(domainName)")
    populate_body = template[populate_start:helper_start]

    assert "innerHTML" not in populate_body
    assert ".textContent" in populate_body
    assert "createDomainNameCell" in populate_body
    assert "createDetailsCell" in populate_body


def test_dashboard_domain_details_links_are_encoded():
    template = (Path(__file__).resolve().parents[1] / "templates" / "index.html").read_text()

    assert "encodeURIComponent(domainId)" in template


def test_dashboard_exposes_workspace_health_history():
    template = (Path(__file__).resolve().parents[1] / "templates" / "index.html").read_text()

    assert "Score Trend" in template
    assert "health-trend-chart" in template
    assert "/api/v1/domains/summary/health/history" in template
    assert "fetchWorkspaceHealthHistory" in template


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

    assert "/api/v1/workspaces" in template
    assert "dmarq.selectedWorkspaceId" in template
    assert "X-DMARQ-Workspace-ID" in template
    assert "dmarq:workspace-changed" in template
    assert "input instanceof URL" in template


def test_dashboard_renders_demo_billing_profiles_without_html_injection():
    template = (Path(__file__).resolve().parents[1] / "templates" / "index.html").read_text()

    assert "Deployment Zoom" in template
    assert "Demo experience" in template
    assert "Start tour" in template
    assert "selectedDemoUserEmail" in template
    assert "selectedDemoWorkspaceSlug" in template
    assert "Workspace drill-down" in template
    assert "tenant-workspace-drilldown" in template
    assert "hasLiveDomain(domainName)" in template
    assert "Demo-only" in template
    assert "demoImpersonationNotice()" in template
    assert "Provider billing samples" in template
    assert "billing_profile.display_name" in template
    assert "formatDemoUsage(organization, usage)" in template
    assert "formatMoney(demoMonthlyTotal())" in template
    assert "x-html" not in template
