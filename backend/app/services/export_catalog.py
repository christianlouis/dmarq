"""Stable read-only export catalog helpers for public API and MCP clients."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List
from urllib.parse import quote

from sqlalchemy.orm import Session

from app.models.api_token import APIToken
from app.models.domain import Domain
from app.models.workspace import Workspace
from app.services.api_tokens import (
    MCP_READ_SCOPE,
    READ_POSTURE_SCOPE,
    READ_REPORTS_SCOPE,
    READ_TLS_SCOPE,
    parse_scopes,
)

PUBLIC_EXPORT_ENDPOINTS = [
    {
        "key": "domains",
        "method": "GET",
        "path": "/api/v1/public/domains",
        "scope": READ_REPORTS_SCOPE,
        "description": "Domain report and DNS summary list.",
    },
    {
        "key": "domain_reports",
        "method": "GET",
        "path_template": "/api/v1/public/domains/{domain}/reports",
        "scope": READ_REPORTS_SCOPE,
        "description": "Recent DMARC aggregate report summaries.",
    },
    {
        "key": "domain_sources",
        "method": "GET",
        "path_template": "/api/v1/public/domains/{domain}/sources",
        "scope": READ_REPORTS_SCOPE,
        "description": "Enriched DMARC sending sources.",
    },
    {
        "key": "source_intelligence",
        "method": "GET",
        "path_template": "/api/v1/public/domains/{domain}/source-intelligence",
        "scope": READ_REPORTS_SCOPE,
        "description": "Regional source summaries and anomaly hints.",
    },
    {
        "key": "domain_posture",
        "method": "GET",
        "path_template": "/api/v1/public/domains/{domain}/posture",
        "scope": READ_POSTURE_SCOPE,
        "description": "Evidence-first posture dashboard payload.",
    },
    {
        "key": "health_evidence_export",
        "method": "GET",
        "path_template": "/api/v1/public/domains/{domain}/posture/evidence/export",
        "scope": READ_POSTURE_SCOPE,
        "description": "Sanitized health score evidence export.",
    },
    {
        "key": "dns_lint",
        "method": "GET",
        "path_template": "/api/v1/public/domains/{domain}/dns/lint",
        "scope": READ_POSTURE_SCOPE,
        "description": "DNS lint findings, target records, and evidence.",
    },
    {
        "key": "dns_change_plan",
        "method": "GET",
        "path_template": "/api/v1/public/domains/{domain}/dns/change-plan",
        "scope": READ_POSTURE_SCOPE,
        "description": "Read-only DNS change plans without apply links.",
    },
    {
        "key": "action_proposals",
        "method": "GET",
        "path_template": "/api/v1/public/domains/{domain}/action-proposals",
        "scope": READ_POSTURE_SCOPE,
        "description": "Reviewable read-only remediation proposals.",
    },
    {
        "key": "alerts",
        "method": "GET",
        "path": "/api/v1/public/alerts",
        "scope": READ_POSTURE_SCOPE,
        "description": "Sanitized alert history for monitored workspace domains.",
    },
    {
        "key": "tls_report_summary",
        "method": "GET",
        "path": "/api/v1/public/tls-reports/summary",
        "scope": READ_TLS_SCOPE,
        "description": "SMTP TLS report trends and failure groups.",
    },
]

MCP_EXPORT_TOOLS = [
    {
        "name": "list_domains",
        "description": "List monitored domains and aggregate counts.",
        "read_only": True,
    },
    {
        "name": "domain_summary",
        "description": "Return an evidence-first summary for one domain.",
        "read_only": True,
    },
    {
        "name": "domain_posture",
        "description": "Return DNS posture, health score, grade, and action guidance.",
        "read_only": True,
    },
    {
        "name": "domain_sources",
        "description": "Return enriched DMARC sending sources for one domain.",
        "read_only": True,
    },
    {
        "name": "dns_lint",
        "description": "Return DNS lint findings, evidence, and target records for one domain.",
        "read_only": True,
    },
    {
        "name": "dns_change_plan",
        "description": "Return read-only DNS change plans without apply links.",
        "read_only": True,
    },
    {
        "name": "source_intelligence",
        "description": "Return source geography summaries and anomaly hints for one domain.",
        "read_only": True,
    },
    {
        "name": "action_proposals",
        "description": "Return reviewable remediation proposals without applying changes.",
        "read_only": True,
    },
    {
        "name": "health_evidence_export",
        "description": "Return sanitized health score evidence rows for one domain.",
        "read_only": True,
    },
    {
        "name": "alert_history",
        "description": "Return sanitized alert history for monitored workspace domains.",
        "read_only": True,
    },
    {
        "name": "export_catalog",
        "description": "Return available public exports, MCP tools, and token usage metadata.",
        "read_only": True,
    },
]


def _timestamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _token_summary(db: Session, auth_context: Dict[str, Any]) -> Dict[str, Any]:
    token = None
    token_id = auth_context.get("token_id")
    try:
        token_id_int = int(token_id) if token_id is not None else None
    except (TypeError, ValueError):
        token_id_int = None
    if token_id_int is not None:
        token = db.query(APIToken).filter(APIToken.id == token_id_int).first()

    scopes = (
        sorted(parse_scopes(token.scopes)) if token is not None else auth_context.get("scopes", [])
    )
    return {
        "id": token.id if token is not None else token_id,
        "name": token.name if token is not None else auth_context.get("token_name"),
        "workspace_id": (
            token.workspace_id if token is not None else auth_context.get("workspace_id")
        ),
        "scopes": sorted(scopes),
        "usage_count": int(token.usage_count or 0) if token is not None else None,
        "last_used_at": token.last_used_at.isoformat() if token and token.last_used_at else None,
    }


def _scope_available(scope: str, token_scopes: Iterable[str]) -> bool:
    return scope in set(token_scopes)


def _public_endpoint_catalog(token_scopes: Iterable[str]) -> List[Dict[str, Any]]:
    scopes = set(token_scopes)
    return [
        {
            **endpoint,
            "available": _scope_available(endpoint["scope"], scopes),
        }
        for endpoint in PUBLIC_EXPORT_ENDPOINTS
    ]


def _domain_export_links(domain_name: str, token_scopes: Iterable[str]) -> Dict[str, Any]:
    encoded_domain = quote(domain_name, safe="")
    links: Dict[str, Any] = {}
    scopes = set(token_scopes)
    for endpoint in PUBLIC_EXPORT_ENDPOINTS:
        path_template = endpoint.get("path_template")
        if not path_template:
            continue
        links[endpoint["key"]] = {
            "href": path_template.format(domain=encoded_domain),
            "method": endpoint["method"],
            "scope": endpoint["scope"],
            "available": _scope_available(endpoint["scope"], scopes),
        }
    return links


def build_export_catalog(
    db: Session,
    *,
    workspace: Workspace,
    auth_context: Dict[str, Any],
) -> Dict[str, Any]:
    """Return a stable catalog of public and MCP export surfaces for a workspace."""
    token = _token_summary(db, auth_context)
    token_scopes = set(token.get("scopes") or [])
    can_list_domains = not token_scopes.isdisjoint(
        {READ_REPORTS_SCOPE, READ_POSTURE_SCOPE, MCP_READ_SCOPE}
    )
    domains = []
    if can_list_domains:
        domains = (
            db.query(Domain)
            .filter(Domain.workspace_id == workspace.id)
            .order_by(Domain.name.asc())
            .all()
        )
    return {
        "generated_at": _timestamp(),
        "workspace": {
            "id": workspace.id,
            "slug": workspace.slug,
            "name": workspace.name,
            "domain_count": len(domains),
        },
        "token": token,
        "public_endpoints": _public_endpoint_catalog(token_scopes),
        "mcp": {
            "endpoint": "/api/v1/mcp",
            "scope": MCP_READ_SCOPE,
            "available": MCP_READ_SCOPE in token_scopes,
            "tools": MCP_EXPORT_TOOLS,
        },
        "domains": [
            {
                "domain": domain.name,
                "active": bool(domain.active),
                "verified": bool(domain.verified),
                "exports": _domain_export_links(domain.name, token_scopes),
            }
            for domain in domains
        ],
    }
