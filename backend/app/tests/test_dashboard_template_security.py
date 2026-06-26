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


def test_members_template_uses_membership_api_without_html_injection():
    template = (Path(__file__).resolve().parents[1] / "templates" / "members.html").read_text()

    assert "/api/v1/organizations" in template
    assert "/api/v1/memberships/organizations/" in template
    assert "/api/v1/memberships/workspaces/" in template
    assert 'x-text="membership.user.email"' in template
    assert "x-html" not in template
