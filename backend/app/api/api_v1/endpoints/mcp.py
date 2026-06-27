"""Read-only MCP-style JSON-RPC endpoint for agent integrations."""

from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import require_api_token_scope
from app.services.ai_assistance import (
    build_action_proposals,
    build_evidence_summary,
    get_assistance_config,
)
from app.services.api_tokens import MCP_READ_SCOPE
from app.services.report_persistence import hydrate_report_store_from_db
from app.services.report_store import ReportStore
from app.services.workspace_access import PERMISSION_REPORTS_READ, resolve_authorized_workspace
from app.services.workspace_audit import record_workspace_audit_log

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
        "name": "action_proposals",
        "description": "Return reviewable remediation proposals without applying changes.",
        "inputSchema": {
            "type": "object",
            "properties": {"domain": {"type": "string"}},
            "required": ["domain"],
        },
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


@router.post("")
async def mcp_jsonrpc(
    payload: MCPRequest,
    request: Request,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_api_token_scope(MCP_READ_SCOPE)),
) -> Dict[str, Any]:
    """Handle a small read-only MCP tool surface over JSON-RPC."""
    _require_mcp_enabled(db)
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
    workspace = resolve_authorized_workspace(
        db,
        _auth,
        PERMISSION_REPORTS_READ,
    )
    try:
        if name == "list_domains":
            result = _list_domains(db, workspace_id=workspace.id)
        elif name == "domain_summary":
            result = build_evidence_summary(db, str(arguments.get("domain", "")))
        elif name == "action_proposals":
            result = build_action_proposals(db, str(arguments.get("domain", "")))
        else:
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
            "content": [{"type": "json", "json": result}],
            "isError": False,
        },
    )
