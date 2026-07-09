"""Complete synthetic provider-console data for the dedicated multi-user demo."""

from copy import deepcopy
from datetime import date, timedelta
from typing import Any, Dict, List, Optional

_PLAN_CATALOG = [
    {
        "code": "monitor",
        "label": "DMARQ Monitor",
        "monthly_charge_cents": 1900,
        "domains": 5,
        "users": 10,
        "messages": 500_000,
        "retention_days": 90,
    },
    {
        "code": "protect",
        "label": "DMARQ Protect",
        "monthly_charge_cents": 3900,
        "domains": 15,
        "users": 25,
        "messages": 2_000_000,
        "retention_days": 180,
    },
    {
        "code": "protect_plus",
        "label": "DMARQ Protect Plus",
        "monthly_charge_cents": 7900,
        "domains": 50,
        "users": 100,
        "messages": 10_000_000,
        "retention_days": 400,
    },
]


def _recent_report(
    anchor: date,
    *,
    account_slug: str,
    domain: str,
    provider: str,
    days_ago: int,
    messages: int,
    pass_rate: float,
) -> Dict[str, Any]:
    report_day = anchor - timedelta(days=days_ago)
    return {
        "id": f"{account_slug}-{provider.lower()}-{report_day.isoformat()}",
        "provider": provider,
        "domain": domain,
        "period_start": (report_day - timedelta(days=1)).isoformat(),
        "period_end": report_day.isoformat(),
        "received_at": f"{report_day.isoformat()}T08:45:00Z",
        "messages": messages,
        "pass_rate": pass_rate,
        "status": "processed",
    }


def _activity(
    anchor: date,
    *,
    event_id: str,
    days_ago: int,
    actor: str,
    action: str,
    summary: str,
) -> Dict[str, Any]:
    activity_day = anchor - timedelta(days=days_ago)
    return {
        "id": event_id,
        "occurred_at": f"{activity_day.isoformat()}T10:20:00Z",
        "actor": actor,
        "action": action,
        "summary": summary,
    }


def _account_profiles(anchor: date) -> List[Dict[str, Any]]:
    profiles: List[Dict[str, Any]] = [
        {
            "id": "acct-bakery",
            "slug": "bakery-example",
            "customer_number": "NS-10042",
            "name": "Bäckerei Morgenrot GmbH",
            "short_name": "Bäckerei Morgenrot",
            "status": "active",
            "health": "healthy",
            "plan_code": "monitor",
            "created_at": f"{(anchor - timedelta(days=310)).isoformat()}T09:15:00Z",
            "last_activity_at": f"{anchor.isoformat()}T07:40:00Z",
            "primary_contact": {
                "name": "Taylor Brooks",
                "email": "taylor@bakery.example",
                "phone": "+49 30 555 0101",
            },
            "billing": {
                "status": "current",
                "invoice_owner": "Northstar ISP",
                "billing_contact": "rechnung@bakery.example",
                "collection_model": "provider_pass_through",
                "payment_rail": "isp_monthly_invoice",
                "invoice_reference": "NS-10042",
                "monthly_charge_cents": 1900,
                "next_invoice_at": (anchor + timedelta(days=12)).isoformat(),
            },
            "usage": {
                "messages_30d": 64_300,
                "reports_30d": 92,
                "compliance_rate": 98.7,
                "change_percent": 8.4,
            },
            "entitlements": {
                "domains": {"used": 1, "included": 5},
                "users": {"used": 3, "included": 10},
                "messages": {"used": 64_300, "included": 500_000},
                "retention_days": {"used": 90, "included": 90},
            },
            "onboarding": {
                "completed_steps": 5,
                "total_steps": 5,
                "next_step": "Reject-Rollout für die nächste Wartungswoche freigeben.",
            },
            "recommended_action": "DMARC von quarantine auf reject anheben und sieben Tage überwachen.",
            "domains": [
                {
                    "name": "bakery.example",
                    "health": "healthy",
                    "policy": "quarantine",
                    "compliance_rate": 98.7,
                    "messages_30d": 64_300,
                    "reports_30d": 92,
                    "source_count": 7,
                    "spf_alignment": 99.2,
                    "dkim_alignment": 98.9,
                    "last_report_at": f"{anchor.isoformat()}T07:40:00Z",
                    "open_findings": ["Policy ist bereit für reject."],
                }
            ],
            "users": [
                {
                    "id": "usr-bakery-taylor",
                    "name": "Taylor Brooks",
                    "email": "taylor@bakery.example",
                    "role": "workspace_admin",
                    "status": "active",
                    "last_active_at": f"{anchor.isoformat()}T07:32:00Z",
                    "mfa_enabled": True,
                    "can_impersonate": True,
                },
                {
                    "id": "usr-bakery-anna",
                    "name": "Anna Morgenrot",
                    "email": "anna@bakery.example",
                    "role": "organization_owner",
                    "status": "active",
                    "last_active_at": f"{(anchor - timedelta(days=1)).isoformat()}T15:20:00Z",
                    "mfa_enabled": True,
                    "can_impersonate": True,
                },
                {
                    "id": "usr-bakery-audit",
                    "name": "Mara Audit",
                    "email": "audit@bakery.example",
                    "role": "auditor",
                    "status": "active",
                    "last_active_at": f"{(anchor - timedelta(days=5)).isoformat()}T09:10:00Z",
                    "mfa_enabled": False,
                    "can_impersonate": False,
                },
            ],
            "settings": {
                "report_mailbox": "dmarc@bakery.example",
                "timezone": "Europe/Berlin",
                "weekly_digest": True,
                "ai_redaction": "strict",
            },
        },
        {
            "id": "acct-lawfirm",
            "slug": "lawfirm-example",
            "customer_number": "NS-10087",
            "name": "Kanzlei Hansen & Partner",
            "short_name": "Hansen & Partner",
            "status": "active",
            "health": "critical",
            "plan_code": "protect_plus",
            "created_at": f"{(anchor - timedelta(days=185)).isoformat()}T11:30:00Z",
            "last_activity_at": f"{anchor.isoformat()}T06:55:00Z",
            "primary_contact": {
                "name": "Dr. Lena Hansen",
                "email": "admin@lawfirm.example",
                "phone": "+49 40 555 0187",
            },
            "billing": {
                "status": "current",
                "invoice_owner": "Northstar ISP",
                "billing_contact": "finance@lawfirm.example",
                "collection_model": "provider_pass_through",
                "payment_rail": "isp_monthly_invoice",
                "invoice_reference": "NS-10087",
                "monthly_charge_cents": 7900,
                "next_invoice_at": (anchor + timedelta(days=12)).isoformat(),
            },
            "usage": {
                "messages_30d": 142_700,
                "reports_30d": 176,
                "compliance_rate": 71.4,
                "change_percent": -11.8,
            },
            "entitlements": {
                "domains": {"used": 2, "included": 50},
                "users": {"used": 4, "included": 100},
                "messages": {"used": 142_700, "included": 10_000_000},
                "retention_days": {"used": 180, "included": 400},
            },
            "onboarding": {
                "completed_steps": 4,
                "total_steps": 5,
                "next_step": "Microsoft-365-DKIM aktivieren und SPF-Lookups reduzieren.",
            },
            "recommended_action": "DKIM-Ausfall beheben, bevor die aktuelle quarantine-Policy verschärft wird.",
            "domains": [
                {
                    "name": "lawfirm.example",
                    "health": "critical",
                    "policy": "quarantine",
                    "compliance_rate": 68.2,
                    "messages_30d": 129_800,
                    "reports_30d": 121,
                    "source_count": 14,
                    "spf_alignment": 74.1,
                    "dkim_alignment": 63.8,
                    "last_report_at": f"{anchor.isoformat()}T06:55:00Z",
                    "open_findings": [
                        "Neue Microsoft-365-Quelle sendet ohne DKIM.",
                        "SPF überschreitet das Lookup-Limit.",
                    ],
                },
                {
                    "name": "secure.lawfirm.example",
                    "health": "monitoring",
                    "policy": "none",
                    "compliance_rate": 92.8,
                    "messages_30d": 12_900,
                    "reports_30d": 55,
                    "source_count": 4,
                    "spf_alignment": 95.2,
                    "dkim_alignment": 91.7,
                    "last_report_at": f"{(anchor - timedelta(days=1)).isoformat()}T20:10:00Z",
                    "open_findings": ["Subdomain-Policy ist noch nicht gesetzt."],
                },
            ],
            "users": [
                {
                    "id": "usr-lawfirm-lena",
                    "name": "Dr. Lena Hansen",
                    "email": "admin@lawfirm.example",
                    "role": "organization_owner",
                    "status": "active",
                    "last_active_at": f"{anchor.isoformat()}T06:40:00Z",
                    "mfa_enabled": True,
                    "can_impersonate": True,
                },
                {
                    "id": "usr-lawfirm-it",
                    "name": "Jan Voss",
                    "email": "it@lawfirm.example",
                    "role": "workspace_admin",
                    "status": "active",
                    "last_active_at": f"{(anchor - timedelta(days=1)).isoformat()}T16:05:00Z",
                    "mfa_enabled": True,
                    "can_impersonate": True,
                },
                {
                    "id": "usr-lawfirm-sec",
                    "name": "Sophie Kern",
                    "email": "security@lawfirm.example",
                    "role": "security_analyst",
                    "status": "active",
                    "last_active_at": f"{anchor.isoformat()}T06:51:00Z",
                    "mfa_enabled": True,
                    "can_impersonate": True,
                },
                {
                    "id": "usr-lawfirm-audit",
                    "name": "Externe Revision",
                    "email": "audit@lawfirm.example",
                    "role": "auditor",
                    "status": "invited",
                    "last_active_at": None,
                    "mfa_enabled": False,
                    "can_impersonate": False,
                },
            ],
            "settings": {
                "report_mailbox": "dmarc@lawfirm.example",
                "timezone": "Europe/Berlin",
                "weekly_digest": True,
                "ai_redaction": "strict",
            },
        },
        {
            "id": "acct-retail",
            "slug": "retail-example",
            "customer_number": "NS-10112",
            "name": "Nordmarkt Retail GmbH",
            "short_name": "Nordmarkt Retail",
            "status": "active",
            "health": "warning",
            "plan_code": "protect",
            "created_at": f"{(anchor - timedelta(days=121)).isoformat()}T10:00:00Z",
            "last_activity_at": f"{(anchor - timedelta(days=1)).isoformat()}T22:15:00Z",
            "primary_contact": {
                "name": "Mina Keller",
                "email": "ops@retail.example",
                "phone": "+49 211 555 0112",
            },
            "billing": {
                "status": "grace_period",
                "invoice_owner": "Northstar ISP",
                "billing_contact": "billing@retail.example",
                "collection_model": "provider_pass_through",
                "payment_rail": "isp_monthly_invoice",
                "invoice_reference": "NS-10112",
                "monthly_charge_cents": 3900,
                "next_invoice_at": (anchor + timedelta(days=4)).isoformat(),
            },
            "usage": {
                "messages_30d": 228_600,
                "reports_30d": 248,
                "compliance_rate": 88.3,
                "change_percent": 23.7,
            },
            "entitlements": {
                "domains": {"used": 2, "included": 15},
                "users": {"used": 3, "included": 25},
                "messages": {"used": 228_600, "included": 2_000_000},
                "retention_days": {"used": 90, "included": 180},
            },
            "onboarding": {
                "completed_steps": 5,
                "total_steps": 5,
                "next_step": "Legacy-Sender klassifizieren und Grace Period beenden.",
            },
            "recommended_action": "Unbekannte Kassenquelle bestätigen und auslaufende Grace Period entscheiden.",
            "domains": [
                {
                    "name": "retail.example",
                    "health": "warning",
                    "policy": "quarantine",
                    "compliance_rate": 86.1,
                    "messages_30d": 201_400,
                    "reports_30d": 181,
                    "source_count": 19,
                    "spf_alignment": 90.4,
                    "dkim_alignment": 84.6,
                    "last_report_at": f"{(anchor - timedelta(days=1)).isoformat()}T22:15:00Z",
                    "open_findings": ["Legacy-Kassenquelle ist nur per SPF ausgerichtet."],
                },
                {
                    "name": "shop.retail.example",
                    "health": "monitoring",
                    "policy": "none",
                    "compliance_rate": 96.5,
                    "messages_30d": 27_200,
                    "reports_30d": 67,
                    "source_count": 6,
                    "spf_alignment": 97.1,
                    "dkim_alignment": 96.2,
                    "last_report_at": f"{anchor.isoformat()}T05:40:00Z",
                    "open_findings": ["Policy-Aufbau läuft noch bis nächste Woche."],
                },
            ],
            "users": [
                {
                    "id": "usr-retail-mina",
                    "name": "Mina Keller",
                    "email": "ops@retail.example",
                    "role": "workspace_admin",
                    "status": "active",
                    "last_active_at": f"{(anchor - timedelta(days=1)).isoformat()}T21:50:00Z",
                    "mfa_enabled": True,
                    "can_impersonate": True,
                },
                {
                    "id": "usr-retail-tobias",
                    "name": "Tobias Nord",
                    "email": "it@retail.example",
                    "role": "security_analyst",
                    "status": "active",
                    "last_active_at": f"{(anchor - timedelta(days=2)).isoformat()}T13:10:00Z",
                    "mfa_enabled": True,
                    "can_impersonate": True,
                },
                {
                    "id": "usr-retail-finance",
                    "name": "Finance Team",
                    "email": "finance@retail.example",
                    "role": "billing_admin",
                    "status": "active",
                    "last_active_at": f"{(anchor - timedelta(days=8)).isoformat()}T08:20:00Z",
                    "mfa_enabled": False,
                    "can_impersonate": False,
                },
            ],
            "settings": {
                "report_mailbox": "dmarc@retail.example",
                "timezone": "Europe/Berlin",
                "weekly_digest": True,
                "ai_redaction": "balanced",
            },
        },
        {
            "id": "acct-studio",
            "slug": "studio-example",
            "customer_number": "NS-10135",
            "name": "Studio Nordlicht GmbH",
            "short_name": "Studio Nordlicht",
            "status": "active",
            "health": "healthy",
            "plan_code": "monitor",
            "created_at": f"{(anchor - timedelta(days=74)).isoformat()}T14:20:00Z",
            "last_activity_at": f"{anchor.isoformat()}T08:12:00Z",
            "primary_contact": {
                "name": "Elena Weiss",
                "email": "elena@studio.example",
                "phone": "+49 89 555 0135",
            },
            "billing": {
                "status": "current",
                "invoice_owner": "Northstar ISP",
                "billing_contact": "office@studio.example",
                "collection_model": "provider_pass_through",
                "payment_rail": "isp_monthly_invoice",
                "invoice_reference": "NS-10135",
                "monthly_charge_cents": 1900,
                "next_invoice_at": (anchor + timedelta(days=12)).isoformat(),
            },
            "usage": {
                "messages_30d": 88_410,
                "reports_30d": 109,
                "compliance_rate": 99.1,
                "change_percent": 3.1,
            },
            "entitlements": {
                "domains": {"used": 2, "included": 5},
                "users": {"used": 3, "included": 10},
                "messages": {"used": 88_410, "included": 500_000},
                "retention_days": {"used": 90, "included": 90},
            },
            "onboarding": {
                "completed_steps": 5,
                "total_steps": 5,
                "next_step": "Monitoring fortsetzen; aktuell keine dringende Aktion.",
            },
            "recommended_action": "Monitoring bestätigen; keine akute Remediation erforderlich.",
            "domains": [
                {
                    "name": "studio.example",
                    "health": "healthy",
                    "policy": "reject",
                    "compliance_rate": 99.4,
                    "messages_30d": 79_100,
                    "reports_30d": 76,
                    "source_count": 5,
                    "spf_alignment": 99.5,
                    "dkim_alignment": 99.2,
                    "last_report_at": f"{anchor.isoformat()}T08:12:00Z",
                    "open_findings": [],
                },
                {
                    "name": "alerts.studio.example",
                    "health": "healthy",
                    "policy": "quarantine",
                    "compliance_rate": 97.2,
                    "messages_30d": 9_310,
                    "reports_30d": 33,
                    "source_count": 3,
                    "spf_alignment": 98.1,
                    "dkim_alignment": 97.7,
                    "last_report_at": f"{(anchor - timedelta(days=1)).isoformat()}T18:40:00Z",
                    "open_findings": ["Reject-Freigabe nach nächster Monitoring-Woche."],
                },
            ],
            "users": [
                {
                    "id": "usr-studio-elena",
                    "name": "Elena Weiss",
                    "email": "elena@studio.example",
                    "role": "organization_owner",
                    "status": "active",
                    "last_active_at": f"{anchor.isoformat()}T08:05:00Z",
                    "mfa_enabled": True,
                    "can_impersonate": True,
                },
                {
                    "id": "usr-studio-mateo",
                    "name": "Mateo Klein",
                    "email": "mateo@studio.example",
                    "role": "security_analyst",
                    "status": "active",
                    "last_active_at": f"{(anchor - timedelta(days=1)).isoformat()}T12:30:00Z",
                    "mfa_enabled": True,
                    "can_impersonate": True,
                },
                {
                    "id": "usr-studio-iris",
                    "name": "Iris Novak",
                    "email": "iris.audit@studio.example",
                    "role": "auditor",
                    "status": "active",
                    "last_active_at": f"{(anchor - timedelta(days=4)).isoformat()}T09:00:00Z",
                    "mfa_enabled": True,
                    "can_impersonate": False,
                },
            ],
            "settings": {
                "report_mailbox": "dmarc@studio.example",
                "timezone": "Europe/Berlin",
                "weekly_digest": False,
                "ai_redaction": "balanced",
            },
        },
        {
            "id": "acct-logistics",
            "slug": "feldwerk-logistics",
            "customer_number": "NS-10158",
            "name": "Feldwerk Logistik AG",
            "short_name": "Feldwerk Logistik",
            "status": "onboarding",
            "health": "monitoring",
            "plan_code": "protect",
            "created_at": f"{(anchor - timedelta(days=18)).isoformat()}T08:00:00Z",
            "last_activity_at": f"{(anchor - timedelta(days=2)).isoformat()}T16:35:00Z",
            "primary_contact": {
                "name": "Jonas Feld",
                "email": "jonas@feldwerk.example",
                "phone": "+49 511 555 0158",
            },
            "billing": {
                "status": "trial",
                "invoice_owner": "Northstar ISP",
                "billing_contact": "finance@feldwerk.example",
                "collection_model": "provider_pass_through",
                "payment_rail": "isp_monthly_invoice",
                "invoice_reference": "NS-10158",
                "monthly_charge_cents": 0,
                "next_invoice_at": (anchor + timedelta(days=19)).isoformat(),
            },
            "usage": {
                "messages_30d": 31_820,
                "reports_30d": 41,
                "compliance_rate": 84.6,
                "change_percent": 0.0,
            },
            "entitlements": {
                "domains": {"used": 1, "included": 15},
                "users": {"used": 2, "included": 25},
                "messages": {"used": 31_820, "included": 2_000_000},
                "retention_days": {"used": 18, "included": 180},
            },
            "onboarding": {
                "completed_steps": 3,
                "total_steps": 5,
                "next_step": "Reporting-Adresse bestätigen und DKIM-Selectoren importieren.",
            },
            "recommended_action": "Onboarding abschließen, bevor eine Policy empfohlen wird.",
            "domains": [
                {
                    "name": "feldwerk.example",
                    "health": "monitoring",
                    "policy": "none",
                    "compliance_rate": 84.6,
                    "messages_30d": 31_820,
                    "reports_30d": 41,
                    "source_count": 9,
                    "spf_alignment": 88.3,
                    "dkim_alignment": 82.4,
                    "last_report_at": f"{(anchor - timedelta(days=2)).isoformat()}T16:35:00Z",
                    "open_findings": ["Zwei DKIM-Selectoren sind noch nicht bestätigt."],
                }
            ],
            "users": [
                {
                    "id": "usr-feldwerk-jonas",
                    "name": "Jonas Feld",
                    "email": "jonas@feldwerk.example",
                    "role": "organization_owner",
                    "status": "active",
                    "last_active_at": f"{(anchor - timedelta(days=2)).isoformat()}T16:20:00Z",
                    "mfa_enabled": True,
                    "can_impersonate": True,
                },
                {
                    "id": "usr-feldwerk-it",
                    "name": "Feldwerk IT",
                    "email": "it@feldwerk.example",
                    "role": "workspace_admin",
                    "status": "invited",
                    "last_active_at": None,
                    "mfa_enabled": False,
                    "can_impersonate": False,
                },
            ],
            "settings": {
                "report_mailbox": "dmarc@feldwerk.example",
                "timezone": "Europe/Berlin",
                "weekly_digest": True,
                "ai_redaction": "strict",
            },
        },
        {
            "id": "acct-praxis",
            "slug": "praxis-stadtpark",
            "customer_number": "NS-10171",
            "name": "Praxis am Stadtpark",
            "short_name": "Praxis Stadtpark",
            "status": "suspended",
            "health": "attention",
            "plan_code": "monitor",
            "created_at": f"{(anchor - timedelta(days=96)).isoformat()}T13:00:00Z",
            "last_activity_at": f"{(anchor - timedelta(days=14)).isoformat()}T11:10:00Z",
            "primary_contact": {
                "name": "Dr. Nele Brandt",
                "email": "nele@praxis.example",
                "phone": "+49 351 555 0171",
            },
            "billing": {
                "status": "past_due",
                "invoice_owner": "Northstar ISP",
                "billing_contact": "office@praxis.example",
                "collection_model": "provider_pass_through",
                "payment_rail": "isp_monthly_invoice",
                "invoice_reference": "NS-10171",
                "monthly_charge_cents": 1900,
                "next_invoice_at": (anchor - timedelta(days=9)).isoformat(),
            },
            "usage": {
                "messages_30d": 17_540,
                "reports_30d": 29,
                "compliance_rate": 91.2,
                "change_percent": -32.0,
            },
            "entitlements": {
                "domains": {"used": 1, "included": 5},
                "users": {"used": 2, "included": 10},
                "messages": {"used": 17_540, "included": 500_000},
                "retention_days": {"used": 90, "included": 90},
            },
            "onboarding": {
                "completed_steps": 5,
                "total_steps": 5,
                "next_step": "Überfällige Rechnung klären und Account reaktivieren.",
            },
            "recommended_action": "Billing-Eskalation klären; technische Konfiguration ist stabil.",
            "domains": [
                {
                    "name": "praxis.example",
                    "health": "attention",
                    "policy": "quarantine",
                    "compliance_rate": 91.2,
                    "messages_30d": 17_540,
                    "reports_30d": 29,
                    "source_count": 4,
                    "spf_alignment": 93.0,
                    "dkim_alignment": 90.1,
                    "last_report_at": f"{(anchor - timedelta(days=4)).isoformat()}T11:10:00Z",
                    "open_findings": ["Account ist wegen Billing pausiert."],
                }
            ],
            "users": [
                {
                    "id": "usr-praxis-nele",
                    "name": "Dr. Nele Brandt",
                    "email": "nele@praxis.example",
                    "role": "organization_owner",
                    "status": "active",
                    "last_active_at": f"{(anchor - timedelta(days=14)).isoformat()}T10:50:00Z",
                    "mfa_enabled": True,
                    "can_impersonate": True,
                },
                {
                    "id": "usr-praxis-office",
                    "name": "Praxis Office",
                    "email": "office@praxis.example",
                    "role": "billing_admin",
                    "status": "active",
                    "last_active_at": f"{(anchor - timedelta(days=16)).isoformat()}T09:30:00Z",
                    "mfa_enabled": False,
                    "can_impersonate": False,
                },
            ],
            "settings": {
                "report_mailbox": "dmarc@praxis.example",
                "timezone": "Europe/Berlin",
                "weekly_digest": True,
                "ai_redaction": "strict",
            },
        },
    ]

    providers = ["Google", "Microsoft", "Yahoo"]
    for profile in profiles:
        reports: List[Dict[str, Any]] = []
        for index, domain in enumerate(profile["domains"]):
            domain_messages = int(domain["messages_30d"])
            for provider_index, provider in enumerate(providers):
                reports.append(
                    _recent_report(
                        anchor,
                        account_slug=profile["slug"],
                        domain=domain["name"],
                        provider=provider,
                        days_ago=provider_index + index,
                        messages=max(1, domain_messages // (4 + provider_index)),
                        pass_rate=float(domain["compliance_rate"]),
                    )
                )
        profile["reports"] = reports
        profile["activity"] = [
            _activity(
                anchor,
                event_id=f"{profile['slug']}-report",
                days_ago=0,
                actor="DMARQ Import",
                action="report.imported",
                summary=f"{len(reports)} aktuelle Aggregate-Reports verarbeitet.",
            ),
            _activity(
                anchor,
                event_id=f"{profile['slug']}-review",
                days_ago=2,
                actor=profile["primary_contact"]["name"],
                action="account.reviewed",
                summary=profile["recommended_action"],
            ),
            _activity(
                anchor,
                event_id=f"{profile['slug']}-billing",
                days_ago=7,
                actor="Northstar Billing",
                action="billing.checked",
                summary=f"Billing-Status: {profile['billing']['status']}.",
            ),
        ]

    return profiles


def build_demo_provider_console(today: Optional[date] = None) -> Dict[str, Any]:
    """Return a provider-owned account model with complete drill-down data."""
    anchor = today or date.today()
    accounts = deepcopy(_account_profiles(anchor))
    plans = {plan["code"]: plan for plan in _PLAN_CATALOG}
    for account in accounts:
        account["plan_label"] = plans[account["plan_code"]]["label"]

    monthly_messages = sum(account["usage"]["messages_30d"] for account in accounts)
    monthly_revenue = sum(
        account["billing"]["monthly_charge_cents"]
        for account in accounts
        if account["billing"]["status"] not in {"trial"}
    )
    at_risk = sum(
        1 for account in accounts if account["health"] in {"warning", "attention", "critical"}
    )
    domains = sum(len(account["domains"]) for account in accounts)
    users = sum(len(account["users"]) for account in accounts)
    weighted_pass = sum(
        account["usage"]["messages_30d"] * account["usage"]["compliance_rate"]
        for account in accounts
    )
    compliance_rate = round(weighted_pass / monthly_messages, 1) if monthly_messages else 0.0

    operator = {
        "id": "provider-user-sofia",
        "name": "Sofia Weber",
        "email": "sofia.ops@northstar.example",
        "role": "site_manager",
    }
    allowed_targets = []
    for account in accounts:
        for user in account["users"]:
            if user.get("can_impersonate"):
                allowed_targets.append(
                    {
                        "account_slug": account["slug"],
                        "workspace_slug": account["slug"],
                        "domain": account["domains"][0]["name"],
                        "target_user": user["email"],
                        "target_user_name": user["name"],
                        "target_role": user["role"],
                        "health": account["health"],
                    }
                )

    return {
        "source": "demo_provider_accounts_v2",
        "generated_for": anchor.isoformat(),
        "provider": {
            "id": "provider-northstar",
            "slug": "northstar-isp",
            "name": "Northstar ISP",
            "operator": operator,
            "support_email": "partner-ops@northstar.example",
            "billing_reference": "NS-ISP-DEMO",
        },
        "summary": {
            "accounts": len(accounts),
            "active_accounts": sum(1 for account in accounts if account["status"] == "active"),
            "at_risk_accounts": at_risk,
            "domains": domains,
            "users": users,
            "messages_30d": monthly_messages,
            "monthly_revenue_cents": monthly_revenue,
            "compliance_rate": compliance_rate,
        },
        "health_segments": {
            "healthy": sum(1 for account in accounts if account["health"] == "healthy"),
            "monitoring": sum(1 for account in accounts if account["health"] == "monitoring"),
            "attention": sum(
                1 for account in accounts if account["health"] in {"warning", "attention"}
            ),
            "critical": sum(1 for account in accounts if account["health"] == "critical"),
        },
        "plans": deepcopy(_PLAN_CATALOG),
        "accounts": accounts,
        "support_access_demo": {
            "mode": "read_only_customer_view",
            "operator": operator,
            "reason": "Kundensupport und Konfigurationsprüfung",
            "allowed_targets": allowed_targets,
            "safeguards": [
                "Zeitlich begrenzte Demo-Sitzung",
                "Operator, Zielbenutzer und Grund werden protokolliert",
                "Kundenansicht ist schreibgeschützt",
                "DNS- und Provider-Schreibzugriffe bleiben deaktiviert",
            ],
            "audit_events": [],
        },
    }


def build_demo_provider_seed_spec(today: Optional[date] = None) -> Dict[str, Any]:
    """Return the deterministic fixture specification used by the DB seeder."""
    anchor = today or date.today()
    return {
        "provider": {
            "slug": "northstar-isp",
            "name": "Northstar ISP",
            "operator": {
                "name": "Sofia Weber",
                "email": "sofia.ops@northstar.example",
                "role": "site_manager",
            },
        },
        "plans": deepcopy(_PLAN_CATALOG),
        "accounts": deepcopy(_account_profiles(anchor)),
    }
