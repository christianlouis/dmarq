"""Read-only MCP-style JSON-RPC endpoint for agent integrations."""

from __future__ import annotations

from datetime import date
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.api_v1.endpoints import domains
from app.core.database import get_db
from app.core.security import require_api_token_scope
from app.services.ai_assistance import (
    build_action_proposals,
    build_evidence_summary,
    get_assistance_config,
)
from app.services.alert_history import alert_history_summary, list_workspace_alert_history
from app.services.api_tokens import MCP_READ_SCOPE
from app.services.export_catalog import build_export_catalog
from app.services.organizations import require_organization_feature
from app.services.report_persistence import hydrate_report_store_from_db
from app.services.report_store import ReportStore
from app.services.workspace_access import PERMISSION_REPORTS_READ, resolve_authorized_workspace
from app.services.workspace_audit import record_workspace_audit_log
from app.services.workspace_usage import build_workspace_usage_summary

router = APIRouter()


class MCPRequest(BaseModel):
    """Minimal JSON-RPC request for MCP HTTP integrations."""

    jsonrpc: str = "2.0"
    id: Optional[Any] = None
    method: str
    params: Dict[str, Any] = {}


READ_ONLY_TOOLS = [
    {
        "name": "list_domains",
        "description": "List monitored domains and aggregate counts.",
        "inputSchema": {"type": "object", "properties": {}},
        "readOnlyHint": True,
    },
    {
        "name": "domain_summary",
        "description": "Return an evidence-first summary for one domain.",
        "inputSchema": {
            "type": "object",
            "properties": {"domain": {"type": "string"}},
            "required": ["domain"],
        },
        "readOnlyHint": True,
    },
    {
        "name": "domain_posture",
        "description": "Return DNS posture, health score, grade, and action guidance.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string"},
                "refresh": {"type": "boolean", "default": False},
            },
            "required": ["domain"],
        },
        "readOnlyHint": True,
    },
    {
        "name": "domain_sources",
        "description": "Return enriched DMARC sending sources for one domain.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string"},
                "days": {"type": "integer", "minimum": 1, "maximum": 365, "default": 30},
            },
            "required": ["domain"],
        },
        "readOnlyHint": True,
    },
    {
        "name": "dns_lint",
        "description": "Return DNS lint findings, evidence, and target records for one domain.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string"},
                "refresh": {"type": "boolean", "default": False},
            },
            "required": ["domain"],
        },
        "readOnlyHint": True,
    },
    {
        "name": "dns_change_plan",
        "description": "Return read-only DNS change plans without apply links.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string"},
                "refresh": {"type": "boolean", "default": False},
            },
            "required": ["domain"],
        },
        "readOnlyHint": True,
    },
    {
        "name": "remediation_queue",
        "description": "Return prioritized remediation work items without apply links.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string"},
                "refresh": {"type": "boolean", "default": False},
            },
            "required": ["domain"],
        },
        "readOnlyHint": True,
    },
    {
        "name": "source_intelligence",
        "description": "Return source geography summaries and anomaly hints for one domain.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string"},
                "days": {"type": "integer", "minimum": 1, "maximum": 365, "default": 30},
            },
            "required": ["domain"],
        },
        "readOnlyHint": True,
    },
    {
        "name": "action_proposals",
        "description": "Return reviewable remediation proposals without applying changes.",
        "inputSchema": {
            "type": "object",
            "properties": {"domain": {"type": "string"}},
            "required": ["domain"],
        },
        "readOnlyHint": True,
    },
    {
        "name": "health_evidence_export",
        "description": "Return sanitized health score evidence rows for one domain.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string"},
                "start_date": {"type": "string", "format": "date"},
                "end_date": {"type": "string", "format": "date"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 400},
            },
            "required": ["domain"],
        },
        "readOnlyHint": True,
    },
    {
        "name": "alert_history",
        "description": "Return sanitized alert history for monitored workspace domains.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string"},
                "active": {"type": "boolean"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 200, "default": 50},
            },
        },
        "readOnlyHint": True,
    },
    {
        "name": "export_catalog",
        "description": "Return available public exports, MCP tools, and token usage metadata.",
        "inputSchema": {"type": "object", "properties": {}},
        "readOnlyHint": True,
    },
    {
        "name": "workspace_usage",
        "description": "Return workspace-level DMARC usage, source, alert, and import counts.",
        "inputSchema": {"type": "object", "properties": {}},
        "readOnlyHint": True,
    },
]


def _jsonrpc_response(request_id: Any, result: Any = None, error: Optional[Dict[str, Any]] = None):
    payload = {"jsonrpc": "2.0", "id": request_id}
    if error is not None:
        payload["error"] = error
    else:
        payload["result"] = result
    return payload


def _require_mcp_enabled(db: Session) -> None:
    if not get_assistance_config(db).mcp_enabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="MCP access is disabled. Enable mcp.enabled before using this endpoint.",
        )


def _require_advanced_integrations(db: Session, workspace) -> None:
    if workspace.organization is None:
        return
    try:
        require_organization_feature(db, workspace.organization, "advanced_integrations")
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail={
                "code": "feature_not_included",
                "feature": "advanced_integrations",
                "message": str(exc),
                "can_export": True,
            },
        ) from exc


def _list_domains(db: Session, *, workspace_id: Optional[int] = None) -> Dict[str, Any]:
    store = ReportStore.get_instance()
    hydrate_report_store_from_db(db, store, workspace_id=workspace_id)
    summaries = store.get_all_domain_summaries()
    return {
        "domains": [
            {
                "domain": domain,
                "total_messages": int(summary.get("total_count", 0) or 0),
                "failed_messages": int(summary.get("failed_count", 0) or 0),
                "compliance_rate": float(summary.get("compliance_rate", 0.0) or 0.0),
                "reports_processed": int(summary.get("reports_processed", 0) or 0),
            }
            for domain, summary in sorted(summaries.items())
        ]
    }


def _tool_domain(arguments: Dict[str, Any]) -> str:
    domain = str(arguments.get("domain", "")).strip()
    if not domain:
        raise ValueError("domain is required")
    return domain


def _tool_days(arguments: Dict[str, Any]) -> int:
    raw_days = arguments.get("days", 30)
    try:
        days = int(raw_days)
    except (TypeError, ValueError) as exc:
        raise ValueError("days must be an integer from 1 to 365") from exc
    if days < 1 or days > 365:
        raise ValueError("days must be an integer from 1 to 365")
    return days


def _tool_optional_date(arguments: Dict[str, Any], key: str) -> Optional[date]:
    raw_value = arguments.get(key)
    if raw_value in (None, ""):
        return None
    try:
        return date.fromisoformat(str(raw_value))
    except ValueError as exc:
        raise ValueError(f"{key} must be an ISO date in YYYY-MM-DD format") from exc


def _tool_limit(arguments: Dict[str, Any], *, default: int = 400, maximum: int = 1000) -> int:
    raw_limit = arguments.get("limit", default)
    try:
        limit = int(raw_limit)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"limit must be an integer from 1 to {maximum}") from exc
    if limit < 1 or limit > maximum:
        raise ValueError(f"limit must be an integer from 1 to {maximum}")
    return limit


def _tool_optional_bool(arguments: Dict[str, Any], key: str) -> Optional[bool]:
    raw_value = arguments.get(key)
    if raw_value in (None, ""):
        return None
    if isinstance(raw_value, bool):
        return raw_value
    normalized = str(raw_value).strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{key} must be a boolean")


def _tool_optional_domain(arguments: Dict[str, Any]) -> Optional[str]:
    domain = str(arguments.get("domain", "")).strip()
    return domain or None


def _call_action_proposals_tool(
    arguments: Dict[str, Any],
    *,
    db: Session,
    auth_context: Dict[str, Any],
    workspace_id: Optional[int],
) -> Any:
    del auth_context
    return build_action_proposals(db, _tool_domain(arguments), workspace_id=workspace_id)


def _call_alert_history_tool(
    arguments: Dict[str, Any],
    *,
    db: Session,
    auth_context: Dict[str, Any],
    workspace_id: Optional[int],
) -> Dict[str, Any]:
    del auth_context
    active_filter = _tool_optional_bool(arguments, "active")
    domain_filter = _tool_optional_domain(arguments)
    limit = _tool_limit(arguments, default=50, maximum=200)
    alerts = list_workspace_alert_history(
        db,
        workspace_id=workspace_id or 0,
        active=active_filter,
        domain=domain_filter,
        limit=limit,
    )
    return {
        "alerts": alerts,
        "summary": alert_history_summary(alerts),
        "filters": {
            "active": active_filter,
            "domain": domain_filter,
            "limit": limit,
        },
    }


def _call_export_catalog_tool(
    arguments: Dict[str, Any],
    *,
    db: Session,
    auth_context: Dict[str, Any],
    workspace_id: Optional[int],
) -> Dict[str, Any]:
    del arguments
    workspace = resolve_authorized_workspace(
        db,
        auth_context,
        PERMISSION_REPORTS_READ,
        selected_workspace_id=workspace_id,
    )
    return build_export_catalog(db, workspace=workspace, auth_context=auth_context)


def _call_workspace_usage_tool(
    arguments: Dict[str, Any],
    *,
    db: Session,
    auth_context: Dict[str, Any],
    workspace_id: Optional[int],
) -> Dict[str, Any]:
    del arguments
    workspace = resolve_authorized_workspace(
        db,
        auth_context,
        PERMISSION_REPORTS_READ,
        selected_workspace_id=workspace_id,
    )
    return build_workspace_usage_summary(db, workspace)


READ_ONLY_SYNC_HANDLERS = {
    "action_proposals": _call_action_proposals_tool,
    "alert_history": _call_alert_history_tool,
    "export_catalog": _call_export_catalog_tool,
    "workspace_usage": _call_workspace_usage_tool,
}


async def _call_remediation_queue_tool(
    arguments: Dict[str, Any],
    *,
    db: Session,
    auth_context: Dict[str, Any],
    workspace_id: Optional[int],
) -> Any:
    workspace = resolve_authorized_workspace(
        db,
        auth_context,
        PERMISSION_REPORTS_READ,
        selected_workspace_id=workspace_id,
    )
    queue = await domains._build_domain_remediation_queue_for_workspace(
        db,
        workspace=workspace,
        domain_id=_tool_domain(arguments),
        refresh=bool(arguments.get("refresh", False)),
    )
    queue = domains.attach_remediation_dispatch_previews(db, workspace=workspace, queue=queue)
    return domains.read_only_remediation_queue_response(queue)


async def _call_health_evidence_export_tool(
    arguments: Dict[str, Any],
    *,
    db: Session,
    auth_context: Dict[str, Any],
    workspace_id: Optional[int],
) -> Dict[str, Any]:
    domain = _tool_domain(arguments)
    rows = await domains.build_domain_health_evidence_export_rows(
        domain_id=domain,
        start_date=_tool_optional_date(arguments, "start_date"),
        end_date=_tool_optional_date(arguments, "end_date"),
        limit=_tool_limit(arguments),
        capture_current=False,
        db=db,
        auth_context=auth_context,
        selected_workspace_id=workspace_id,
    )
    return {"scope": "domain", "domain": domain, "rows": rows}


READ_ONLY_ASYNC_HANDLERS = {
    "health_evidence_export": _call_health_evidence_export_tool,
    "remediation_queue": _call_remediation_queue_tool,
}


async def _call_read_only_tool(
    name: str,
    arguments: Dict[str, Any],
    *,
    db: Session,
    auth_context: Dict[str, Any],
    workspace_id: Optional[int],
) -> Any:
    if name == "list_domains":
        return _list_domains(db, workspace_id=workspace_id)
    if name == "domain_summary":
        return build_evidence_summary(db, _tool_domain(arguments), workspace_id=workspace_id)
    if name == "domain_posture":
        return await domains.get_domain_posture_dashboard(
            domain_id=_tool_domain(arguments),
            refresh=bool(arguments.get("refresh", False)),
            db=db,
            _auth=auth_context,
        )
    if name == "domain_sources":
        return await domains.get_domain_sources(
            domain_id=_tool_domain(arguments),
            days=_tool_days(arguments),
            db=db,
            _auth=auth_context,
        )
    if name == "dns_lint":
        return await domains.get_domain_dns_lint(
            domain_id=_tool_domain(arguments),
            refresh=bool(arguments.get("refresh", False)),
            db=db,
            _auth=auth_context,
        )
    if name == "dns_change_plan":
        response = await domains.get_domain_dns_change_plan(
            domain_id=_tool_domain(arguments),
            refresh=bool(arguments.get("refresh", False)),
            db=db,
            _auth=auth_context,
        )
        return domains.read_only_dns_change_plan_response(response)
    if name == "source_intelligence":
        return await domains.get_domain_source_intelligence(
            domain_id=_tool_domain(arguments),
            days=_tool_days(arguments),
            db=db,
            _auth=auth_context,
        )
    sync_handler = READ_ONLY_SYNC_HANDLERS.get(name)
    if sync_handler is not None:
        return sync_handler(
            arguments,
            db=db,
            auth_context=auth_context,
            workspace_id=workspace_id,
        )
    async_handler = READ_ONLY_ASYNC_HANDLERS.get(name)
    if async_handler is not None:
        return await async_handler(
            arguments,
            db=db,
            auth_context=auth_context,
            workspace_id=workspace_id,
        )
    raise KeyError(name)


@router.post("")
async def mcp_jsonrpc(
    payload: MCPRequest,
    request: Request,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_api_token_scope(MCP_READ_SCOPE)),
) -> Dict[str, Any]:
    """Handle a small read-only MCP tool surface over JSON-RPC."""
    _require_mcp_enabled(db)
    workspace = resolve_authorized_workspace(
        db,
        _auth,
        PERMISSION_REPORTS_READ,
    )
    _require_advanced_integrations(db, workspace)
    if payload.method == "initialize":
        return _jsonrpc_response(
            payload.id,
            {
                "protocolVersion": "2024-11-05",
                "serverInfo": {"name": "dmarq", "version": "1"},
                "capabilities": {"tools": {}},
            },
        )
    if payload.method == "tools/list":
        return _jsonrpc_response(payload.id, {"tools": READ_ONLY_TOOLS})
    if payload.method != "tools/call":
        return _jsonrpc_response(
            payload.id,
            error={"code": -32601, "message": f"Unsupported method: {payload.method}"},
        )

    name = payload.params.get("name")
    arguments = payload.params.get("arguments") or {}
    try:
        result = await _call_read_only_tool(
            str(name),
            arguments,
            db=db,
            auth_context=_auth,
            workspace_id=workspace.id,
        )
    except KeyError:
        return _jsonrpc_response(
            payload.id,
            error={"code": -32602, "message": f"Unsupported tool: {name}"},
        )
    except ValueError as exc:
        return _jsonrpc_response(payload.id, error={"code": -32004, "message": str(exc)})

    record_workspace_audit_log(
        db,
        workspace=workspace,
        action="mcp.tool_called",
        entity_type="mcp_tool",
        entity_id=name,
        entity_name=name,
        details={"tool": name, "read_only": True},
        auth_context=_auth,
        request=request,
    )
    db.commit()
    return _jsonrpc_response(
        payload.id,
        {
            "content": [{"type": "json", "json": jsonable_encoder(result)}],
            "isError": False,
        },
    )
