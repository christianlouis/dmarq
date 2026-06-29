"""Deterministic demo data for public DMARQ demo environments."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import date, datetime, time, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional

from app.services.report_store import ReportStore

DEMO_DOMAINS = ("dmarq.org", "dmarq.com")
DEMO_DAYS = 90
DEMO_MULTI_USER_ROLES = (
    "organization_owner",
    "billing_admin",
    "workspace_admin",
    "analyst",
    "auditor",
    "provider_operator",
)
DEMO_TLS_REPORT_PRIVACY_CONTROLS = {
    "retention": (
        "TLS reports store aggregate session counts, reporting organization metadata, "
        "policy domains, and grouped TLS failure details."
    ),
    "stored_fields": [
        "report id",
        "reporting organization",
        "contact info",
        "policy domain",
        "policy type",
        "report date range",
        "successful and failed session counts",
        "grouped result type and failed-session count",
        "receiving MX host/HELO/IP when supplied by the reporter",
        "failure reason code and additional grouped diagnostic text",
    ],
    "not_stored": [
        "message bodies",
        "message subjects",
        "sender or recipient addresses",
        "recipient local-parts",
        "raw uploaded attachments",
        "mailbox credentials or source message identifiers",
    ],
}


def build_demo_multi_user_deployment() -> Dict[str, Any]:
    """Return a rolling SaaS/ISP demo deployment model without real customers."""
    today = date.today()
    period_start = today - timedelta(days=29)
    prior_period_start = today - timedelta(days=59)
    quarter_start = today - timedelta(days=89)
    return {
        "generated_for": today.isoformat(),
        "window": {
            "current_period_start": period_start.isoformat(),
            "prior_period_start": prior_period_start.isoformat(),
            "historical_start": quarter_start.isoformat(),
            "period_days": 30,
            "retention_days": 90,
        },
        "roles": list(DEMO_MULTI_USER_ROLES),
        "default_viewer": "single-user-multiple-domains",
        "impersonation_policy": {
            "mode": "demo_only",
            "audit_label": "support impersonation audit event",
            "allowed_roles": ["organization_owner", "provider_operator"],
            "scope": (
                "Impersonation is shown as an explicit support workflow in the demo. "
                "A production deployment must permission-gate the action, record the "
                "operator, target user, organization, workspace, reason, and time, and "
                "keep the customer-facing view read-only unless elevated separately."
            ),
        },
        "journey_steps": [
            {
                "step": 1,
                "label": "Start in the daily domain view",
                "zoom_level": "workspace",
                "scenario_id": "single-user-multiple-domains",
                "organization_slug": "dmarq-foundation",
                "workspace_slug": "dmarq-org",
                "domain": "dmarq.org",
                "action": "Inspect dmarq.org and dmarq.com as one administrator.",
                "expected_takeaway": (
                    "DMARQ first explains normal domain posture, sender alignment, "
                    "and DNS actions for the account you own."
                ),
            },
            {
                "step": 2,
                "label": "Zoom out to the account",
                "zoom_level": "account",
                "scenario_id": "managed-service-analyst",
                "organization_slug": "dmarq-commercial",
                "workspace_slug": "dmarq-com",
                "domain": "dmarq.com",
                "action": "Compare account billing, users, workspaces, and plan limits.",
                "expected_takeaway": (
                    "Managed-service teams need account ownership, role boundaries, "
                    "and contract billing context next to DMARC evidence."
                ),
            },
            {
                "step": 3,
                "label": "Zoom out to provider operations",
                "zoom_level": "provider",
                "scenario_id": "isp-operator",
                "organization_slug": "northstar-isp",
                "workspace_slug": "lawfirm-example",
                "domain": "lawfirm.example",
                "action": "Review ISP customers, bundled billing, and usage export samples.",
                "expected_takeaway": (
                    "Providers can operate many customer workspaces while billing "
                    "through their existing monthly invoice systems."
                ),
            },
            {
                "step": 4,
                "label": "Impersonate a customer user",
                "zoom_level": "workspace",
                "scenario_id": "customer-admin",
                "organization_slug": "northstar-isp",
                "workspace_slug": "bakery-example",
                "domain": "bakery.example",
                "action": "Switch into a customer admin view and confirm visible workspaces.",
                "expected_takeaway": (
                    "Support impersonation is explicit demo state, scoped to visible "
                    "customer workspaces, and designed to be audited in production."
                ),
            },
            {
                "step": 5,
                "label": "Compare self-hosted operations",
                "zoom_level": "workspace",
                "scenario_id": "self-hosted-admin",
                "organization_slug": "studio-self-hosted",
                "workspace_slug": "studio-main",
                "domain": "studio.example",
                "action": "Open the self-hosted profile with local billing ownership.",
                "expected_takeaway": (
                    "The same report and DNS workflows work without provider billing "
                    "or hosted subscription ownership."
                ),
            },
        ],
        "zoom_levels": [
            {
                "level": "workspace",
                "label": "Single user, multiple domains",
                "description": (
                    "Default demo view: one administrator tracks dmarq.org and "
                    "dmarq.com before zooming out to accounts and billing."
                ),
            },
            {
                "level": "account",
                "label": "Account and team view",
                "description": "Organizations, users, workspaces, roles, and billing ownership.",
            },
            {
                "level": "provider",
                "label": "ISP / managed provider view",
                "description": (
                    "Provider operators see many customer workspaces and export usage "
                    "to external monthly billing."
                ),
            },
        ],
        "domain_showcase": [
            {
                "domain": "dmarq.org",
                "workspace_slug": "dmarq-org",
                "organization_slug": "dmarq-foundation",
                "posture": "quarantine with strict subdomain policy",
                "story": "Mostly healthy production mail with newsletter DKIM drift.",
            },
            {
                "domain": "dmarq.com",
                "workspace_slug": "dmarq-com",
                "organization_slug": "dmarq-foundation",
                "posture": "monitoring before enforcement",
                "story": "Commercial mail is still in p=none while senders are aligned.",
            },
        ],
        "billing_modes": [
            {
                "mode": "direct_stripe",
                "label": "DMARQaaS direct subscription",
                "invoice_owner": "DMARQ",
                "settlement": "Stripe subscription and hosted invoices",
            },
            {
                "mode": "manual_contract",
                "label": "Contracted managed service",
                "invoice_owner": "DMARQ",
                "settlement": "Contract invoice with optional purchase order reference",
            },
            {
                "mode": "provider_resale",
                "label": "ISP bundled subscription",
                "invoice_owner": "ISP",
                "settlement": "Usage and entitlement export for the ISP monthly bill",
            },
            {
                "mode": "provider_whmcs",
                "label": "Hosting-panel billing",
                "invoice_owner": "Hosting provider",
                "settlement": "Provisioning and usage sync through a hosting platform",
            },
            {
                "mode": "self_hosted_license",
                "label": "Self-hosted deployment",
                "invoice_owner": "Customer",
                "settlement": "Local license or no external billing integration",
            },
        ],
        "organizations": [
            {
                "slug": "dmarq-foundation",
                "name": "DMARQ Foundation",
                "deployment_model": "dmarq_cloud",
                "billing_mode": "direct_stripe",
                "demo_story": (
                    "The default demo account: one admin, two domains, normal SaaS billing, "
                    "and enough report history to inspect trends before enforcement."
                ),
                "default_persona": "single-user-multiple-domains",
                "plan": {
                    "code": "business",
                    "name": "Business",
                    "price": {"monthly": 12900, "annual": 129000, "currency": "EUR"},
                    "included": {
                        "domains": 15,
                        "users": 25,
                        "aggregate_messages": 1_000_000,
                        "retention_days": 400,
                    },
                },
                "billing": {
                    "status": "active",
                    "next_invoice_date": (today + timedelta(days=12)).isoformat(),
                    "current_period_total_cents": 12900,
                    "invoice_delivery_mode": "stripe_customer_portal",
                    "external_customer_id": "cus_demo_foundation",
                },
                "billing_profile": {
                    "profile_id": "bp-demo-foundation",
                    "display_name": "DMARQ Business via Stripe",
                    "invoice_owner": "DMARQ",
                    "billing_contact": "billing@dmarq.example",
                    "collection_model": "self_service_subscription",
                    "payment_rail": "card_on_file",
                    "invoice_reference": "DMQ-2026-00042",
                    "next_invoice_action": "renew_business_plan",
                },
                "entitlements": {
                    "domains": {"used": 2, "included": 15},
                    "users": {"used": 3, "included": 25},
                    "aggregate_messages": {"used": 197_430, "included": 1_000_000},
                    "retention_days": {"used": 90, "included": 400},
                },
                "workspaces": [
                    {
                        "slug": "dmarq-org",
                        "name": "dmarq.org Public Infrastructure",
                        "domains": ["dmarq.org"],
                        "health": "attention",
                        "primary_findings": [
                            "newsletter DKIM selector intermittently fails",
                            "legacy CRM source should be retired or isolated",
                        ],
                    },
                    {
                        "slug": "dmarq-com",
                        "name": "dmarq.com Commercial Mail",
                        "domains": ["dmarq.com"],
                        "health": "monitoring",
                        "primary_findings": [
                            "policy is still p=none while marketing sources are being aligned",
                            "unknown forwarder appears on low-volume days",
                        ],
                    },
                ],
                "users": [
                    {
                        "name": "Alex Morgan",
                        "email": "alex@dmarq.example",
                        "roles": ["organization_owner", "workspace_admin"],
                        "workspaces": ["dmarq-org", "dmarq-com"],
                        "demo_persona": "single-user-multiple-domains",
                        "can_impersonate": True,
                    },
                    {
                        "name": "Mira Chen",
                        "email": "mira@dmarq.example",
                        "roles": ["analyst"],
                        "workspaces": ["dmarq-org", "dmarq-com"],
                        "demo_persona": "domain-analyst",
                        "can_impersonate": True,
                    },
                    {
                        "name": "Sam Rivera",
                        "email": "sam.audit@dmarq.example",
                        "roles": ["auditor"],
                        "workspaces": ["dmarq-org", "dmarq-com"],
                        "demo_persona": "read-only-auditor",
                        "can_impersonate": True,
                    },
                ],
                "usage": [
                    {
                        "metric": "aggregate_messages",
                        "period_start": period_start.isoformat(),
                        "period_end": today.isoformat(),
                        "quantity": 197_430,
                        "unit": "messages",
                    },
                    {
                        "metric": "forensic_samples",
                        "period_start": period_start.isoformat(),
                        "period_end": today.isoformat(),
                        "quantity": 34,
                        "unit": "reports",
                    },
                ],
            },
            {
                "slug": "dmarq-commercial",
                "name": "DMARQ Commercial",
                "deployment_model": "managed_service",
                "billing_mode": "manual_contract",
                "demo_story": (
                    "A managed-service customer where DMARQ operations and customer staff "
                    "share visibility while invoicing remains contract based."
                ),
                "default_persona": "managed-service-analyst",
                "plan": {
                    "code": "enterprise",
                    "name": "Enterprise",
                    "price": {"monthly": 44900, "annual": 449000, "currency": "EUR"},
                    "included": {
                        "domains": 100,
                        "users": 100,
                        "aggregate_messages": 10_000_000,
                        "retention_days": 730,
                    },
                },
                "billing": {
                    "status": "active",
                    "next_invoice_date": (today + timedelta(days=4)).isoformat(),
                    "current_period_total_cents": 44900,
                    "invoice_delivery_mode": "contract_invoice",
                    "external_customer_id": "acct-demo-dmarq-commercial",
                },
                "billing_profile": {
                    "profile_id": "bp-demo-commercial",
                    "display_name": "Managed DMARC contract",
                    "invoice_owner": "DMARQ",
                    "billing_contact": "finance@dmarq.example",
                    "collection_model": "contract_invoice",
                    "payment_rail": "bank_transfer",
                    "invoice_reference": "PO-DEMO-7781",
                    "next_invoice_action": "review_quarterly_commit",
                },
                "entitlements": {
                    "domains": {"used": 8, "included": 100},
                    "users": {"used": 2, "included": 100},
                    "aggregate_messages": {"used": 121_820, "included": 10_000_000},
                    "retention_days": {"used": 90, "included": 730},
                },
                "workspaces": [
                    {
                        "slug": "dmarq-com",
                        "name": "dmarq.com Product Mail",
                        "domains": ["dmarq.com"],
                        "health": "monitoring",
                        "primary_findings": [
                            "policy is still p=none while marketing sources are being aligned",
                            "unknown forwarder appears on low-volume days",
                        ],
                    }
                ],
                "users": [
                    {
                        "name": "Jordan Lee",
                        "email": "jordan@dmarq.example",
                        "roles": ["organization_owner", "billing_admin"],
                        "workspaces": ["dmarq-com"],
                    },
                    {
                        "name": "Priya Shah",
                        "email": "priya@dmarq.example",
                        "roles": ["workspace_admin", "analyst"],
                        "workspaces": ["dmarq-com"],
                    },
                ],
                "usage": [
                    {
                        "metric": "aggregate_messages",
                        "period_start": period_start.isoformat(),
                        "period_end": today.isoformat(),
                        "quantity": 121_820,
                        "unit": "messages",
                    },
                    {
                        "metric": "dns_snapshots",
                        "period_start": period_start.isoformat(),
                        "period_end": today.isoformat(),
                        "quantity": 60,
                        "unit": "snapshots",
                    },
                ],
            },
            {
                "slug": "northstar-isp",
                "name": "Northstar ISP Demo",
                "deployment_model": "isp_resale",
                "billing_mode": "provider_resale",
                "demo_story": (
                    "An ISP operator can zoom across many customer workspaces, then open "
                    "one subaccount to experience what that customer sees."
                ),
                "default_persona": "isp-operator",
                "plan": {
                    "code": "provider-growth",
                    "name": "Provider Growth",
                    "price": {"monthly": 99000, "annual": None, "currency": "EUR"},
                    "included": {
                        "customer_workspaces": 250,
                        "users": 500,
                        "aggregate_messages": 50_000_000,
                        "retention_days": 400,
                    },
                },
                "billing": {
                    "status": "active",
                    "next_invoice_date": (today + timedelta(days=18)).isoformat(),
                    "current_period_total_cents": 118_500,
                    "invoice_delivery_mode": "provider_monthly_bill",
                    "external_customer_id": "isp-demo-northstar",
                },
                "billing_profile": {
                    "profile_id": "bp-demo-northstar",
                    "display_name": "Provider Growth reseller ledger",
                    "invoice_owner": "Northstar ISP",
                    "billing_contact": "partner-billing@northstar.example",
                    "collection_model": "provider_pass_through",
                    "payment_rail": "isp_monthly_invoice",
                    "invoice_reference": "NS-ISP-DEMO-2026-06",
                    "next_invoice_action": "sync_usage_to_provider_bill",
                },
                "entitlements": {
                    "customer_workspaces": {"used": 42, "included": 250},
                    "users": {"used": 86, "included": 500},
                    "aggregate_messages": {"used": 2_423_900, "included": 50_000_000},
                    "retention_days": {"used": 90, "included": 400},
                },
                "provider_integration": {
                    "type": "hosting_management",
                    "status": "mock_connected",
                    "external_provider_id": "northstar-panel-demo",
                    "scopes": [
                        "customer.read",
                        "domain.read",
                        "dns.read",
                        "subscription.usage.write",
                    ],
                },
                "workspaces": [
                    {
                        "slug": "bakery-example",
                        "name": "Bakery Example Customer",
                        "domains": ["bakery.example"],
                        "health": "healthy",
                        "primary_findings": ["ready to move from quarantine to reject"],
                    },
                    {
                        "slug": "lawfirm-example",
                        "name": "Law Firm Example Customer",
                        "domains": ["lawfirm.example"],
                        "health": "critical",
                        "primary_findings": [
                            "new mail platform sends without DKIM",
                            "SPF includes exceed the lookup budget",
                        ],
                    },
                    {
                        "slug": "retail-example",
                        "name": "Retail Chain Example",
                        "domains": ["retail.example", "shop.retail.example"],
                        "health": "warning",
                        "primary_findings": [
                            "legacy sender still aligned through SPF only",
                            "monitoring grace period expires next week",
                        ],
                    },
                ],
                "provider_customers": [
                    {
                        "external_customer_id": "ns-cust-10042",
                        "workspace_slug": "bakery-example",
                        "name": "Bakery Example Customer",
                        "billing_status": "included",
                        "subscription_tier": "DMARQ Protect",
                        "monthly_charge_cents": 1900,
                        "aggregate_messages": 64_300,
                        "domains": 1,
                    },
                    {
                        "external_customer_id": "ns-cust-10087",
                        "workspace_slug": "lawfirm-example",
                        "name": "Law Firm Example Customer",
                        "billing_status": "billable_addon",
                        "subscription_tier": "DMARQ Protect Plus",
                        "monthly_charge_cents": 3900,
                        "aggregate_messages": 142_700,
                        "domains": 3,
                    },
                    {
                        "external_customer_id": "ns-cust-10112",
                        "workspace_slug": "retail-example",
                        "name": "Retail Chain Example",
                        "billing_status": "grace_period",
                        "subscription_tier": "DMARQ Monitor",
                        "monthly_charge_cents": 900,
                        "aggregate_messages": 21_600,
                        "domains": 2,
                    },
                ],
                "users": [
                    {
                        "name": "Nora Patel",
                        "email": "nora.ops@northstar.example",
                        "roles": ["provider_operator"],
                        "workspaces": ["bakery-example", "lawfirm-example"],
                        "demo_persona": "isp-operator",
                        "can_impersonate": True,
                    },
                    {
                        "name": "Chris Becker",
                        "email": "chris.billing@northstar.example",
                        "roles": ["billing_admin"],
                        "workspaces": [],
                        "demo_persona": "provider-billing",
                        "can_impersonate": True,
                    },
                    {
                        "name": "Taylor Brooks",
                        "email": "taylor@bakery.example",
                        "roles": ["workspace_admin"],
                        "workspaces": ["bakery-example"],
                        "demo_persona": "customer-admin",
                        "can_impersonate": True,
                    },
                ],
                "usage": [
                    {
                        "metric": "customer_workspaces",
                        "period_start": period_start.isoformat(),
                        "period_end": today.isoformat(),
                        "quantity": 42,
                        "unit": "workspaces",
                    },
                    {
                        "metric": "aggregate_messages",
                        "period_start": period_start.isoformat(),
                        "period_end": today.isoformat(),
                        "quantity": 2_423_900,
                        "unit": "messages",
                    },
                    {
                        "metric": "provider_billable_addons",
                        "period_start": period_start.isoformat(),
                        "period_end": today.isoformat(),
                        "quantity": 7,
                        "unit": "customer_addons",
                    },
                ],
            },
            {
                "slug": "studio-self-hosted",
                "name": "Studio Self-Hosted",
                "deployment_model": "self_hosted",
                "billing_mode": "self_hosted_license",
                "demo_story": (
                    "A single-company installation with local users, no provider billing, "
                    "and multiple internal domains managed from one dashboard."
                ),
                "default_persona": "self-hosted-admin",
                "plan": {
                    "code": "community-self-hosted",
                    "name": "Self-hosted",
                    "price": {"monthly": 0, "annual": 0, "currency": "EUR"},
                    "included": {
                        "domains": 10,
                        "users": 10,
                        "aggregate_messages": 500_000,
                        "retention_days": 180,
                    },
                },
                "billing": {
                    "status": "local",
                    "next_invoice_date": None,
                    "current_period_total_cents": 0,
                    "invoice_delivery_mode": "not_applicable",
                    "external_customer_id": None,
                },
                "billing_profile": {
                    "profile_id": "bp-demo-self-hosted",
                    "display_name": "Self-hosted local deployment",
                    "invoice_owner": "Customer",
                    "billing_contact": "ops@studio.example",
                    "collection_model": "none",
                    "payment_rail": "not_applicable",
                    "invoice_reference": "local-demo",
                    "next_invoice_action": "renew_local_license_if_enabled",
                },
                "entitlements": {
                    "domains": {"used": 4, "included": 10},
                    "users": {"used": 4, "included": 10},
                    "aggregate_messages": {"used": 88_410, "included": 500_000},
                    "retention_days": {"used": 90, "included": 180},
                },
                "workspaces": [
                    {
                        "slug": "studio-main",
                        "name": "Studio Production Mail",
                        "domains": ["studio.example", "mail.studio.example"],
                        "health": "healthy",
                        "primary_findings": ["ready for reject after one more monitoring week"],
                    },
                    {
                        "slug": "studio-lab",
                        "name": "Studio Lab and Test Mail",
                        "domains": ["lab.studio.example", "alerts.studio.example"],
                        "health": "warning",
                        "primary_findings": [
                            "test sender has SPF alignment only",
                            "DKIM selector should be rotated before enforcement",
                        ],
                    },
                ],
                "users": [
                    {
                        "name": "Elena Weiss",
                        "email": "elena@studio.example",
                        "roles": ["organization_owner", "workspace_admin"],
                        "workspaces": ["studio-main", "studio-lab"],
                        "demo_persona": "self-hosted-admin",
                        "can_impersonate": True,
                    },
                    {
                        "name": "Mateo Klein",
                        "email": "mateo@studio.example",
                        "roles": ["analyst"],
                        "workspaces": ["studio-main"],
                        "demo_persona": "self-hosted-analyst",
                        "can_impersonate": True,
                    },
                    {
                        "name": "Iris Novak",
                        "email": "iris.audit@studio.example",
                        "roles": ["auditor"],
                        "workspaces": ["studio-main", "studio-lab"],
                        "demo_persona": "self-hosted-auditor",
                        "can_impersonate": True,
                    },
                ],
                "usage": [
                    {
                        "metric": "aggregate_messages",
                        "period_start": period_start.isoformat(),
                        "period_end": today.isoformat(),
                        "quantity": 88_410,
                        "unit": "messages",
                    },
                    {
                        "metric": "dns_snapshots",
                        "period_start": period_start.isoformat(),
                        "period_end": today.isoformat(),
                        "quantity": 96,
                        "unit": "snapshots",
                    },
                ],
            },
        ],
        "viewer_scenarios": [
            {
                "id": "single-user-multiple-domains",
                "label": "Single user, multiple domains",
                "email": "alex@dmarq.example",
                "visible_organizations": ["dmarq-foundation"],
                "default_workspace": "dmarq-org",
                "default_domain": "dmarq.org",
                "zoom_level": "workspace",
            },
            {
                "id": "managed-service-analyst",
                "label": "Managed-service analyst",
                "email": "priya@dmarq.example",
                "visible_organizations": ["dmarq-commercial"],
                "default_workspace": "dmarq-com",
                "default_domain": "dmarq.com",
                "zoom_level": "account",
            },
            {
                "id": "isp-operator",
                "label": "ISP operator",
                "email": "nora.ops@northstar.example",
                "visible_organizations": ["northstar-isp"],
                "default_workspace": "lawfirm-example",
                "default_domain": "lawfirm.example",
                "zoom_level": "provider",
            },
            {
                "id": "customer-admin",
                "label": "ISP customer admin",
                "email": "taylor@bakery.example",
                "visible_organizations": ["northstar-isp"],
                "default_workspace": "bakery-example",
                "default_domain": "bakery.example",
                "zoom_level": "workspace",
            },
            {
                "id": "self-hosted-admin",
                "label": "Self-hosted admin",
                "email": "elena@studio.example",
                "visible_organizations": ["studio-self-hosted"],
                "default_workspace": "studio-main",
                "default_domain": "studio.example",
                "zoom_level": "workspace",
            },
        ],
    }


_SOURCE_PROFILES = {
    "dmarq.org": [
        {
            "ip": "203.0.113.10",
            "name": "primary-saas",
            "base": 950,
            "spf": "pass",
            "dkim": "pass",
            "selector": "selector1",
        },
        {
            "ip": "203.0.113.44",
            "name": "newsletter",
            "base": 420,
            "spf": "pass",
            "dkim": "fail",
            "selector": "news",
        },
        {
            "ip": "198.51.100.23",
            "name": "ticketing",
            "base": 180,
            "spf": "fail",
            "dkim": "pass",
            "selector": "zendesk",
        },
        {
            "ip": "192.0.2.66",
            "name": "legacy-crm",
            "base": 55,
            "spf": "fail",
            "dkim": "fail",
            "selector": "legacy",
        },
    ],
    "dmarq.com": [
        {
            "ip": "203.0.113.75",
            "name": "workspace-mail",
            "base": 610,
            "spf": "pass",
            "dkim": "pass",
            "selector": "google",
        },
        {
            "ip": "198.51.100.88",
            "name": "marketing",
            "base": 260,
            "spf": "pass",
            "dkim": "mixed",
            "selector": "mailchimp",
        },
        {
            "ip": "192.0.2.114",
            "name": "billing",
            "base": 130,
            "spf": "fail",
            "dkim": "pass",
            "selector": "stripe",
        },
        {
            "ip": "198.51.100.199",
            "name": "unknown-forwarder",
            "base": 35,
            "spf": "fail",
            "dkim": "fail",
            "selector": "unknown",
        },
    ],
}


def _utc_timestamp(day: date, boundary: time) -> int:
    return int(datetime.combine(day, boundary, tzinfo=timezone.utc).timestamp())


def _utc_iso_from_timestamp(value: int) -> str:
    return (
        datetime.fromtimestamp(value, tz=timezone.utc)
        .replace(tzinfo=None)
        .isoformat(timespec="seconds")
    )


def _policy_for_domain(domain: str) -> Dict[str, str]:
    if domain == "dmarq.org":
        return {
            "p": "quarantine",
            "sp": "reject",
            "pct": "100",
            "adkim": "s",
            "aspf": "r",
            "fo": "1",
            "discovery_method": "author",
        }
    return {
        "p": "none",
        "sp": "quarantine",
        "pct": "100",
        "adkim": "r",
        "aspf": "r",
        "fo": "1:d",
        "testing": "y",
        "discovery_method": "treewalk",
    }


def _result_for(profile: Dict[str, Any], day_index: int, domain: str) -> tuple[str, str]:
    spf = str(profile["spf"])
    dkim = str(profile["dkim"])
    if dkim == "mixed":
        dkim = "pass" if day_index % 3 else "fail"
    if profile["name"] == "legacy-crm" and day_index % 14 == 0:
        return "pass", "fail"
    if profile["name"] == "unknown-forwarder" and day_index % 11 == 0:
        return "fail", "pass"
    if domain == "dmarq.com" and profile["name"] == "marketing" and day_index % 10 == 0:
        return "pass", "fail"
    return spf, dkim


def _count_for(profile: Dict[str, Any], day_index: int) -> int:
    base = int(profile["base"])
    weekly_wave = ((day_index % 7) - 3) * max(2, base // 28)
    incident = 0
    if profile["name"] in {"legacy-crm", "unknown-forwarder"} and day_index % 13 == 0:
        incident = base * 2
    if profile["name"] == "newsletter" and day_index % 7 in {1, 4}:
        incident = base // 2
    return max(1, base + weekly_wave + incident)


def _record(domain: str, profile: Dict[str, Any], day_index: int) -> Dict[str, Any]:
    spf_result, dkim_result = _result_for(profile, day_index, domain)
    count = _count_for(profile, day_index)
    dmarc_pass = spf_result == "pass" or dkim_result == "pass"
    policy = _policy_for_domain(domain)
    disposition = "none"
    if not dmarc_pass and policy["p"] in {"quarantine", "reject"}:
        disposition = policy["p"]
    if not dmarc_pass and domain == "dmarq.com":
        disposition = "none"
    return {
        "source_ip": profile["ip"],
        "count": count,
        "disposition": disposition,
        "dkim_result": dkim_result,
        "spf_result": spf_result,
        "header_from": domain,
        "envelope_from": f"bounce.{domain}",
        "envelope_to": f"recipient-{day_index % 5}.example.net",
        "dkim": [
            {
                "domain": domain,
                "selector": profile["selector"],
                "result": dkim_result,
                "human_result": (
                    "signature verified" if dkim_result == "pass" else "body hash did not verify"
                ),
            }
        ],
        "spf": [
            {
                "domain": f"bounce.{domain}",
                "scope": "mfrom",
                "result": spf_result,
                "human_result": (
                    "sender authorized" if spf_result == "pass" else "sender not authorized by SPF"
                ),
            }
        ],
        "extensions": {
            "demo:source": profile["name"],
            "demo:scenario": "corner-case" if not dmarc_pass else "normal",
        },
    }


def _summary(records: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    rows = list(records)
    total = sum(int(record["count"]) for record in rows)
    passed = sum(
        int(record["count"])
        for record in rows
        if record["spf_result"] == "pass" or record["dkim_result"] == "pass"
    )
    failed = total - passed
    return {
        "total_count": total,
        "passed_count": passed,
        "failed_count": failed,
        "pass_rate": round((passed / total) * 100, 1) if total else 0.0,
    }


def _auth_status_from_counts(pass_count: int, fail_count: int) -> str:
    if pass_count > 0 and fail_count > 0:
        return "mixed"
    if pass_count > 0:
        return "pass"
    if fail_count > 0:
        return "fail"
    return "none"


def _demo_today(today: Optional[date] = None) -> date:
    return today or datetime.now(timezone.utc).date()


def build_demo_reports(today: Optional[date] = None, days: int = DEMO_DAYS) -> List[Dict[str, Any]]:
    """Return rolling synthetic DMARC aggregate reports through *today*."""
    anchor = _demo_today(today)
    reports: List[Dict[str, Any]] = []
    start = anchor - timedelta(days=days - 1)
    for day_offset in range(days):
        report_day = start + timedelta(days=day_offset)
        day_index = (report_day - date(2026, 1, 1)).days
        for domain in DEMO_DOMAINS:
            records = [_record(domain, profile, day_index) for profile in _SOURCE_PROFILES[domain]]
            begin_ts = _utc_timestamp(report_day, time.min)
            end_ts = _utc_timestamp(report_day, time.max.replace(microsecond=0))
            reports.append(
                {
                    "domain": domain,
                    "report_id": f"demo-{domain}-{report_day.isoformat()}",
                    "org_name": "DMARQ Demo Receiver",
                    "email": "reports@demo.dmarq.org",
                    "extra_contact_info": "https://demo.dmarq.org",
                    "generator": "DMARQ demo data generator",
                    "variant": "rfc9990",
                    "schema_version": "1.0",
                    "xml_namespace": "urn:ietf:params:xml:ns:dmarc-2.0",
                    "begin_date": _utc_iso_from_timestamp(begin_ts),
                    "end_date": _utc_iso_from_timestamp(end_ts),
                    "begin_timestamp": begin_ts,
                    "end_timestamp": end_ts,
                    "policy": _policy_for_domain(domain),
                    "records": records,
                    "summary": _summary(records),
                    "extensions": {
                        "demo:rolling_window_days": str(days),
                        "demo:generated_for": anchor.isoformat(),
                    },
                }
            )
    return reports


def build_demo_dashboard_statistics(
    *,
    period_days: int = 30,
    domain: Optional[str] = None,
    today: Optional[date] = None,
) -> Dict[str, Any]:
    """Return dashboard statistics from the rolling aggregate demo reports."""
    period_days = max(1, int(period_days or 30))
    anchor = _demo_today(today)
    start = anchor - timedelta(days=period_days - 1)
    normalized_domain = domain.lower().strip(".") if domain else None
    reports = [
        report
        for report in build_demo_reports(today=anchor, days=max(DEMO_DAYS, period_days))
        if datetime.fromtimestamp(report["begin_timestamp"], tz=timezone.utc).date() >= start
        and (normalized_domain is None or report["domain"] == normalized_domain)
    ]

    total_emails = 0
    compliant_emails = 0
    daily: Dict[str, Dict[str, int]] = defaultdict(lambda: {"total": 0, "passed": 0})
    sources: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {
            "ip": "",
            "count": 0,
            "spf_pass_count": 0,
            "spf_fail_count": 0,
            "dkim_pass_count": 0,
            "dkim_fail_count": 0,
            "dmarc_pass_count": 0,
            "dmarc_fail_count": 0,
            "domains": set(),
        }
    )

    for report in reports:
        report_day = datetime.fromtimestamp(report["begin_timestamp"], tz=timezone.utc).date()
        day_key = report_day.isoformat()
        for record in report.get("records") or []:
            count = int(record.get("count") or 0)
            spf_pass = record.get("spf_result") == "pass"
            dkim_pass = record.get("dkim_result") == "pass"
            dmarc_pass = spf_pass or dkim_pass
            total_emails += count
            if dmarc_pass:
                compliant_emails += count
            daily[day_key]["total"] += count
            daily[day_key]["passed"] += count if dmarc_pass else 0

            source = sources[record.get("source_ip") or "unknown"]
            source["ip"] = record.get("source_ip") or "unknown"
            source["count"] += count
            source["spf_pass_count"] += count if spf_pass else 0
            source["spf_fail_count"] += 0 if spf_pass else count
            source["dkim_pass_count"] += count if dkim_pass else 0
            source["dkim_fail_count"] += 0 if dkim_pass else count
            source["dmarc_pass_count"] += count if dmarc_pass else 0
            source["dmarc_fail_count"] += 0 if dmarc_pass else count
            source["domains"].add(report["domain"])

    compliance_trend: List[Dict[str, Any]] = []
    for day_key in sorted(daily):
        total = daily[day_key]["total"]
        passed = daily[day_key]["passed"]
        failed = max(0, total - passed)
        compliance_rate = round((passed / total) * 100, 1) if total else 0.0
        compliance_trend.append(
            {
                "date": day_key,
                "total": total,
                "volume": total,
                "passed": passed,
                "failed": failed,
                "rate": compliance_rate,
                "compliance_rate": compliance_rate,
                "failure_rate": round((failed / total) * 100, 1) if total else 0.0,
            }
        )

    source_rows = []
    for source in sources.values():
        source_rows.append(
            {
                "ip": source["ip"],
                "count": source["count"],
                "spf_pass_count": source["spf_pass_count"],
                "spf_fail_count": source["spf_fail_count"],
                "dkim_pass_count": source["dkim_pass_count"],
                "dkim_fail_count": source["dkim_fail_count"],
                "dmarc_pass_count": source["dmarc_pass_count"],
                "dmarc_fail_count": source["dmarc_fail_count"],
                "spf": _auth_status_from_counts(source["spf_pass_count"], source["spf_fail_count"]),
                "dkim": _auth_status_from_counts(
                    source["dkim_pass_count"], source["dkim_fail_count"]
                ),
                "dmarc": _auth_status_from_counts(
                    source["dmarc_pass_count"], source["dmarc_fail_count"]
                ),
                "domains": sorted(source["domains"]),
            }
        )
    source_rows.sort(key=lambda item: item["count"], reverse=True)

    compliance_rate = round((compliant_emails / total_emails) * 100, 1) if total_emails else 0.0
    stats = {
        "total_emails": total_emails,
        "compliant_emails": compliant_emails,
        "compliance_rate": compliance_rate,
        "reports_processed": len(reports),
        "compliance_trend": compliance_trend,
        "change_summary": _demo_change_summary(source_rows, normalized_domain),
    }
    if normalized_domain:
        stats.update({"domain": normalized_domain, "sources": source_rows[:10]})
    else:
        stats.update(
            {
                "total_domains": len({report["domain"] for report in reports}),
                "top_sources": source_rows[:10],
            }
        )
    return stats


def _demo_change_summary(
    source_rows: List[Dict[str, Any]], domain: Optional[str] = None
) -> List[Dict[str, Any]]:
    by_ip = {row["ip"]: row for row in source_rows}
    changes = []
    if domain in {None, "dmarq.org"} and "203.0.113.44" in by_ip:
        row = by_ip["203.0.113.44"]
        changes.append(
            {
                "type": "auth_failure",
                "severity": "warning",
                "title": "Newsletter DKIM drift",
                "domain": "dmarq.org",
                "source_ip": row["ip"],
                "message_count": row["dkim_fail_count"],
                "detail": (
                    "The newsletter source passes SPF but has repeat DKIM body-hash failures."
                ),
                "action": (
                    "Rotate or re-publish the newsletter DKIM selector before enforcing reject."
                ),
            }
        )
    if domain in {None, "dmarq.com"} and "198.51.100.199" in by_ip:
        row = by_ip["198.51.100.199"]
        changes.append(
            {
                "type": "misaligned_source",
                "severity": "critical",
                "title": "Unknown forwarder is unauthenticated",
                "domain": "dmarq.com",
                "source_ip": row["ip"],
                "message_count": row["dmarc_fail_count"],
                "detail": "A low-volume forwarding path fails both SPF and DKIM alignment.",
                "action": "Confirm ownership before adding DNS includes or DKIM selectors.",
            }
        )
    if domain in {None, "dmarq.com"}:
        changes.append(
            {
                "type": "policy_gap",
                "severity": "info",
                "title": "Policy still in monitoring mode",
                "domain": "dmarq.com",
                "source_ip": None,
                "message_count": 0,
                "detail": "dmarq.com shows useful failure data while p=none prevents enforcement.",
                "action": (
                    "Fix the known senders, then move to quarantine with a staged percentage."
                ),
            }
        )
    return changes[:5]


def build_demo_tls_reports(
    today: Optional[date] = None, days: int = DEMO_DAYS
) -> List[Dict[str, Any]]:
    """Return rolling SMTP TLS Reporting data for the public demo."""
    anchor = _demo_today(today)
    reports: List[Dict[str, Any]] = []
    report_id = 1
    start = anchor - timedelta(days=max(1, days) - 1)
    failure_profiles = {
        "dmarq.org": [
            ("certificate-host-mismatch", "mx2.demo.dmarq.org", "mx.demo.dmarq.org", 3),
            ("certificate-expired", "legacy-mx.demo.dmarq.org", "legacy cert", 1),
        ],
        "dmarq.com": [
            ("starttls-not-supported", "mx1.demo.dmarq.com", "STARTTLS missing", 9),
            ("certificate-expired", "mx-old.demo.dmarq.com", "expired chain", 5),
            ("validation-failure", "mx3.demo.dmarq.com", "untrusted intermediate", 2),
        ],
    }

    for offset in range(max(1, days)):
        report_day = start + timedelta(days=offset)
        day_index = (report_day - date(2026, 1, 1)).days
        for domain in DEMO_DOMAINS:
            if day_index % 2 and domain == "dmarq.org":
                continue
            failures = []
            failed_sessions = 0
            for failure_index, (result_type, host, reason, base) in enumerate(
                failure_profiles[domain]
            ):
                if (day_index + failure_index) % (failure_index + 3) != 0:
                    continue
                count = base + (day_index % 4)
                failed_sessions += count
                failures.append(
                    {
                        "result_type": result_type,
                        "failed_session_count": count,
                        "sending_mta_ip": None,
                        "receiving_mx_hostname": host,
                        "receiving_mx_helo": host.split(".")[0],
                        "receiving_ip": None,
                        "failure_reason_code": reason,
                        "additional_information": (
                            "Synthetic demo TLS-RPT group; no message content is stored."
                        ),
                    }
                )
            successful_sessions = (
                1800 + (day_index % 9) * 45 if domain == "dmarq.org" else 900 + (day_index % 8) * 30
            )
            reports.append(
                {
                    "id": report_id,
                    "report_id": f"demo-tls-{domain}-{report_day.isoformat()}",
                    "domain": domain,
                    "org_name": "DMARQ Demo TLS Reporter",
                    "contact_info": "mailto:tls-rpt@demo.dmarq.org",
                    "policy_domain": domain,
                    "policy_type": "sts",
                    "begin_date": datetime.combine(
                        report_day, time.min, tzinfo=timezone.utc
                    ).isoformat(),
                    "end_date": datetime.combine(
                        report_day, time.max.replace(microsecond=0), tzinfo=timezone.utc
                    ).isoformat(),
                    "total_successful_sessions": successful_sessions,
                    "total_failure_sessions": failed_sessions,
                    "processed_at": datetime.combine(
                        report_day + timedelta(days=1), time(hour=1), tzinfo=timezone.utc
                    ).isoformat(),
                    "failures": failures,
                }
            )
            report_id += 1
    reports.sort(key=lambda item: (item["begin_date"], item["id"]), reverse=True)
    return reports


def list_demo_tls_reports(
    *,
    domain: Optional[str] = None,
    page: int = 1,
    page_size: int = 50,
    today: Optional[date] = None,
) -> Dict[str, Any]:
    normalized_domain = domain.lower().strip(".") if domain else None
    rows = [
        row
        for row in build_demo_tls_reports(today=today)
        if normalized_domain is None or row["policy_domain"] == normalized_domain
    ]
    total = len(rows)
    start = (page - 1) * page_size
    end = start + page_size
    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": (total + page_size - 1) // page_size if total else 0,
        "reports": rows[start:end],
        "privacy": DEMO_TLS_REPORT_PRIVACY_CONTROLS,
    }


def summarize_demo_tls_reports(
    *,
    domain: Optional[str] = None,
    days: int = 30,
    limit: int = 10,
    today: Optional[date] = None,
) -> Dict[str, Any]:
    anchor = _demo_today(today)
    cutoff = anchor - timedelta(days=max(1, days) - 1)
    normalized_domain = domain.lower().strip(".") if domain else None
    rows = [
        row
        for row in build_demo_tls_reports(today=anchor, days=max(DEMO_DAYS, days))
        if datetime.fromisoformat(row["begin_date"]).date() >= cutoff
        and (normalized_domain is None or row["policy_domain"] == normalized_domain)
    ]

    totals = {
        "reports": len(rows),
        "successful_sessions": sum(row["total_successful_sessions"] for row in rows),
        "failed_sessions": sum(row["total_failure_sessions"] for row in rows),
    }
    session_total = totals["successful_sessions"] + totals["failed_sessions"]
    totals["failure_rate"] = totals["failed_sessions"] / session_total if session_total else 0.0

    trend_map: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {"date": "", "reports": 0, "successful_sessions": 0, "failed_sessions": 0}
    )
    domain_map: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {
            "domain": "",
            "reports": 0,
            "successful_sessions": 0,
            "failed_sessions": 0,
            "top_failure": None,
        }
    )
    failure_map: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {
            "result_type": "",
            "failed_sessions": 0,
            "reports": set(),
            "affected_domains": set(),
            "receiving_mx_hostnames": set(),
            "reason_codes": set(),
        }
    )

    for row in rows:
        day_key = datetime.fromisoformat(row["begin_date"]).date().isoformat()
        trend = trend_map[day_key]
        trend["date"] = day_key
        trend["reports"] += 1
        trend["successful_sessions"] += row["total_successful_sessions"]
        trend["failed_sessions"] += row["total_failure_sessions"]

        domain_summary = domain_map[row["policy_domain"]]
        domain_summary["domain"] = row["policy_domain"]
        domain_summary["reports"] += 1
        domain_summary["successful_sessions"] += row["total_successful_sessions"]
        domain_summary["failed_sessions"] += row["total_failure_sessions"]

        top_failure = None
        for failure in row["failures"]:
            item = failure_map[failure["result_type"]]
            item["result_type"] = failure["result_type"]
            item["failed_sessions"] += failure["failed_session_count"]
            item["reports"].add(row["report_id"])
            item["affected_domains"].add(row["policy_domain"])
            if failure.get("receiving_mx_hostname"):
                item["receiving_mx_hostnames"].add(failure["receiving_mx_hostname"])
            if failure.get("failure_reason_code"):
                item["reason_codes"].add(failure["failure_reason_code"])
            if (
                top_failure is None
                or failure["failed_session_count"] > top_failure["failed_session_count"]
            ):
                top_failure = failure
        if top_failure:
            domain_summary["top_failure"] = top_failure["result_type"]

    affected_domains = []
    for item in domain_map.values():
        domain_sessions = item["successful_sessions"] + item["failed_sessions"]
        item["failure_rate"] = item["failed_sessions"] / domain_sessions if domain_sessions else 0.0
        affected_domains.append(item)
    affected_domains.sort(key=lambda item: item["failed_sessions"], reverse=True)

    top_failures = [
        {
            "result_type": item["result_type"],
            "failed_sessions": item["failed_sessions"],
            "report_count": len(item["reports"]),
            "affected_domains": sorted(item["affected_domains"]),
            "receiving_mx_hostnames": sorted(item["receiving_mx_hostnames"])[:5],
            "reason_codes": sorted(item["reason_codes"])[:5],
        }
        for item in failure_map.values()
    ]
    top_failures.sort(key=lambda item: item["failed_sessions"], reverse=True)

    return {
        "domain": normalized_domain,
        "days": days,
        "totals": totals,
        "trends": [trend_map[key] for key in sorted(trend_map)],
        "top_failures": top_failures[:limit],
        "affected_domains": affected_domains[:limit],
        "privacy": DEMO_TLS_REPORT_PRIVACY_CONTROLS,
    }


def _forensic_scenarios() -> List[Dict[str, Any]]:
    return [
        {
            "domain": "dmarq.org",
            "source_ip": "203.0.113.44",
            "auth_failure": "dkim",
            "delivery_result": "quarantine",
            "selector": "news",
            "mail_from": "bounce.dmarq.org",
            "diagnostic": "newsletter body hash did not verify",
        },
        {
            "domain": "dmarq.org",
            "source_ip": "192.0.2.66",
            "auth_failure": "dmarc",
            "delivery_result": "reject",
            "selector": "legacy",
            "mail_from": "legacy.dmarq.org",
            "diagnostic": "legacy CRM failed SPF and DKIM alignment",
        },
        {
            "domain": "dmarq.com",
            "source_ip": "198.51.100.88",
            "auth_failure": "dkim",
            "delivery_result": "none",
            "selector": "mailchimp",
            "mail_from": "bounce.dmarq.com",
            "diagnostic": "marketing sender intermittently signs with the old selector",
        },
        {
            "domain": "dmarq.com",
            "source_ip": "198.51.100.199",
            "auth_failure": "spf",
            "delivery_result": "none",
            "selector": "unknown",
            "mail_from": "forwarder.example.net",
            "diagnostic": "unknown forwarder is not authorized in SPF",
        },
    ]


def build_demo_forensic_reports(
    today: Optional[date] = None, days: int = DEMO_DAYS
) -> List[Dict[str, Any]]:
    """Return redacted rolling DMARC forensic/failure samples for the demo."""
    anchor = _demo_today(today)
    start = anchor - timedelta(days=max(1, days) - 1)
    reports: List[Dict[str, Any]] = []
    report_id = 1
    for offset in range(max(1, days)):
        report_day = start + timedelta(days=offset)
        day_index = (report_day - date(2026, 1, 1)).days
        for scenario_index, scenario in enumerate(_forensic_scenarios()):
            if (day_index + scenario_index) % (4 + scenario_index) != 0:
                continue
            arrival = datetime.combine(
                report_day, time(hour=8 + scenario_index, minute=15), tzinfo=timezone.utc
            )
            dkim_result = "fail" if scenario["auth_failure"] in {"dkim", "dmarc"} else "pass"
            spf_result = "fail" if scenario["auth_failure"] in {"spf", "dmarc"} else "pass"
            auth_results = (
                f"mx.demo.dmarq.org; dkim={dkim_result} "
                f"header.d={scenario['domain']} header.s={scenario['selector']}; "
                f"spf={spf_result} "
                f"smtp.mailfrom={scenario['mail_from']}; dmarc=fail"
            )
            item = {
                "id": report_id,
                "report_id": (
                    f"demo-ruf-{scenario['domain']}-{report_day.isoformat()}-{scenario_index}"
                ),
                "domain": scenario["domain"],
                "reported_domain": scenario["domain"],
                "source_email": "DMARC Reporter <reports@receiver.example>",
                "feedback_type": "auth-failure",
                "user_agent": "DMARQ Demo Failure Reporter",
                "version": "1.0",
                "source_ip": scenario["source_ip"],
                "auth_failure": scenario["auth_failure"],
                "delivery_result": scenario["delivery_result"],
                "arrival_date": arrival.isoformat(),
                "authentication_results": auth_results,
                "original_mail_from": f"bo***@{scenario['mail_from'].split('.', 1)[-1]}",
                "original_from": f"se***@{scenario['domain']}",
                "original_to": "re***@recipient.example",
                "original_subject": "[redacted-subject]",
                "original_message_id": f"demo-redacted-{report_id}@example.invalid",
                "original_date": arrival.isoformat(),
                "feedback_headers": {
                    "identity_alignment": scenario["auth_failure"],
                    "dkim_selector": scenario["selector"],
                    "dkim_identity": f"se***@{scenario['domain']}",
                    "spf_dns": "v=spf1 include:_spf.example.net -all",
                    "demo_note": scenario["diagnostic"],
                },
                "processed_at": (arrival + timedelta(minutes=3)).isoformat(),
            }
            item["analysis"] = _analyze_demo_forensic_item(item)
            reports.append(item)
            report_id += 1
    reports.sort(key=lambda item: (item["arrival_date"], item["id"]), reverse=True)
    return reports


def _priority_for_forensic(item: Dict[str, Any]) -> str:
    if item.get("delivery_result") in {"reject", "quarantine"}:
        return "high"
    if item.get("auth_failure") == "dmarc":
        return "high"
    return "medium"


def _recommendations_for_forensic(item: Dict[str, Any]) -> List[str]:
    failure = item.get("auth_failure")
    if failure == "dkim":
        return [
            "Check the signing selector and canonicalization for this sender.",
            "Confirm the DKIM public key still matches the sending platform.",
        ]
    if failure == "spf":
        return [
            "Verify whether the source is authorized before extending SPF.",
            "Prefer DKIM alignment for forwarding paths that cannot pass SPF.",
        ]
    return [
        "Treat this as a full DMARC alignment failure and verify source ownership.",
        "Keep enforcement in quarantine until the sending path is identified.",
    ]


def _analyze_demo_forensic_item(item: Dict[str, Any]) -> Dict[str, Any]:
    headers = item.get("feedback_headers") or {}
    failure = item.get("auth_failure") or "unknown"
    priority = _priority_for_forensic(item)
    dkim_domain = item.get("reported_domain")
    mail_from = (
        str(item.get("authentication_results") or "").split("smtp.mailfrom=")[-1].split(";")[0]
    )
    signals = [
        f"Identity alignment: {headers.get('identity_alignment', failure)}",
        f"DKIM selector: {headers.get('dkim_selector', 'unknown')}",
        f"SPF DNS: {headers.get('spf_dns', 'unknown')}",
    ]
    if headers.get("demo_note"):
        signals.append(f"Demo scenario: {headers['demo_note']}")
    return {
        "id": item["id"],
        "report_id": item["report_id"],
        "domain": item.get("reported_domain"),
        "source_ip": item.get("source_ip"),
        "auth_failure": failure,
        "delivery_result": item.get("delivery_result"),
        "priority": priority,
        "diagnosis": (
            f"{failure.upper()} failure sample from {item.get('source_ip')} "
            f"for {item.get('reported_domain')}."
        ),
        "recommendations": _recommendations_for_forensic(item),
        "signals": signals,
        "authentication_results": {
            "dkim": "fail" if failure in {"dkim", "dmarc"} else "pass",
            "spf": "fail" if failure in {"spf", "dmarc"} else "pass",
            "dmarc": "fail",
        },
        "dkim_domain": dkim_domain,
        "mail_from_domain": mail_from,
        "privacy_note": "DMARQ stores redacted headers and metadata only for forensic samples.",
    }


def _filter_demo_forensics(
    rows: Iterable[Dict[str, Any]],
    *,
    domain: Optional[str] = None,
    source_ip: Optional[str] = None,
    auth_failure: Optional[str] = None,
    delivery_result: Optional[str] = None,
) -> List[Dict[str, Any]]:
    normalized_domain = domain.lower().strip(".") if domain else None
    normalized_auth = auth_failure.strip().lower() if auth_failure else None
    normalized_result = delivery_result.strip().lower() if delivery_result else None
    normalized_ip = source_ip.strip() if source_ip else None
    return [
        row
        for row in rows
        if (normalized_domain is None or row["reported_domain"] == normalized_domain)
        and (normalized_ip is None or row["source_ip"] == normalized_ip)
        and (normalized_auth is None or row["auth_failure"] == normalized_auth)
        and (normalized_result is None or row["delivery_result"] == normalized_result)
    ]


def list_demo_forensic_reports(
    *,
    domain: Optional[str] = None,
    source_ip: Optional[str] = None,
    auth_failure: Optional[str] = None,
    delivery_result: Optional[str] = None,
    page: int = 1,
    page_size: int = 50,
    today: Optional[date] = None,
) -> Dict[str, Any]:
    rows = _filter_demo_forensics(
        build_demo_forensic_reports(today=today),
        domain=domain,
        source_ip=source_ip,
        auth_failure=auth_failure,
        delivery_result=delivery_result,
    )
    total = len(rows)
    start = (page - 1) * page_size
    end = start + page_size
    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": (total + page_size - 1) // page_size if total else 0,
        "reports": rows[start:end],
    }


def analyze_demo_forensic_reports(
    *,
    domain: Optional[str] = None,
    source_ip: Optional[str] = None,
    auth_failure: Optional[str] = None,
    delivery_result: Optional[str] = None,
    page_size: int = 200,
    today: Optional[date] = None,
) -> Dict[str, Any]:
    rows = _filter_demo_forensics(
        build_demo_forensic_reports(today=today),
        domain=domain,
        source_ip=source_ip,
        auth_failure=auth_failure,
        delivery_result=delivery_result,
    )[:page_size]
    samples = [row["analysis"] for row in rows]
    priority_counts = Counter(sample["priority"] for sample in samples)
    failure_counts = Counter(sample["auth_failure"] for sample in samples)
    result_counts = Counter(sample.get("delivery_result") or "unknown" for sample in samples)

    grouped: Dict[tuple[str, str, str, str], Dict[str, Any]] = {}
    for row in rows:
        key = (
            row.get("reported_domain") or "",
            row.get("source_ip") or "",
            row.get("auth_failure") or "unknown",
            row.get("delivery_result") or "unknown",
        )
        group = grouped.setdefault(
            key,
            {
                "key": "|".join(key),
                "domain": key[0],
                "source_ip": key[1],
                "auth_failure": key[2],
                "delivery_result": key[3],
                "count": 0,
                "priority": row["analysis"]["priority"],
                "latest_arrival": row.get("arrival_date"),
                "diagnosis": row["analysis"]["diagnosis"],
                "recommendations": row["analysis"]["recommendations"],
            },
        )
        group["count"] += 1
        if row.get("arrival_date") and row["arrival_date"] > (group.get("latest_arrival") or ""):
            group["latest_arrival"] = row["arrival_date"]
    groups = sorted(
        grouped.values(),
        key=lambda item: (item["count"], item["latest_arrival"]),
        reverse=True,
    )
    return {
        "total": len(rows),
        "priority_counts": dict(priority_counts),
        "failure_counts": dict(failure_counts),
        "result_counts": dict(result_counts),
        "groups": groups,
        "samples": samples[:50],
    }


def get_demo_forensic_report(
    report_id: int, today: Optional[date] = None
) -> Optional[Dict[str, Any]]:
    for row in build_demo_forensic_reports(today=today):
        if row["id"] == report_id:
            return row
    return None


def seed_demo_report_store(store: Optional[ReportStore] = None) -> int:
    """Replace the report store contents with rolling demo reports."""
    target = store or ReportStore.get_instance()
    target.clear()
    reports = build_demo_reports()
    for report in reports:
        target.add_report(report)
    return len(reports)
