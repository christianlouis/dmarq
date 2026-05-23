"""Admin endpoints for outbound webhook event delivery."""

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import require_admin_auth
from app.models.webhook import WebhookDelivery, WebhookEndpoint
from app.services.webhook_events import (
    SUPPORTED_EVENT_TYPES,
    create_webhook_endpoint,
    deliver_due_webhooks,
    delivery_to_dict,
    endpoint_to_dict,
    queue_test_webhook,
    update_webhook_endpoint,
)
from app.services.workspace_audit import changed_fields, record_workspace_audit_log
from app.services.workspaces import assign_default_workspace_to_unscoped_rows

router = APIRouter()


class WebhookEndpointCreate(BaseModel):
    """Create payload for outbound webhook endpoints."""

    name: str
    url: str
    secret: Optional[str] = None
    event_types: List[str] = ["*"]
    enabled: bool = True
    max_attempts: int = 5
    timeout_seconds: int = 10


class WebhookEndpointUpdate(BaseModel):
    """Update payload for outbound webhook endpoints."""

    name: Optional[str] = None
    url: Optional[str] = None
    secret: Optional[str] = None
    event_types: Optional[List[str]] = None
    enabled: Optional[bool] = None
    max_attempts: Optional[int] = None
    timeout_seconds: Optional[int] = None


class WebhookEndpointResponse(BaseModel):
    """API-safe webhook endpoint metadata."""

    id: int
    name: str
    url: str
    event_types: List[str]
    enabled: bool
    max_attempts: int
    timeout_seconds: int
    created_at: Optional[str]
    updated_at: Optional[str]
    last_success_at: Optional[str]
    last_failure_at: Optional[str]
    failure_count: int
    secret_configured: bool
    url_encrypted: bool
    secret: Optional[str] = None


class WebhookEndpointListResponse(BaseModel):
    """List response for outbound webhook endpoints."""

    endpoints: List[WebhookEndpointResponse]
    supported_event_types: List[str]


class WebhookDeliveryResponse(BaseModel):
    """API-safe webhook delivery metadata."""

    id: int
    endpoint_id: int
    event_type: str
    idempotency_key: str
    status: str
    attempt_count: int
    max_attempts: int
    next_attempt_at: Optional[str]
    last_attempt_at: Optional[str]
    delivered_at: Optional[str]
    last_status_code: Optional[int]
    last_error: Optional[str]
    response_excerpt: Optional[str]
    created_at: Optional[str]
    updated_at: Optional[str]


class WebhookDeliveryListResponse(BaseModel):
    """List response for outbound webhook deliveries."""

    deliveries: List[WebhookDeliveryResponse]


class WebhookTestResponse(BaseModel):
    """Response for a webhook test delivery."""

    delivery: WebhookDeliveryResponse


@router.get("", response_model=WebhookEndpointListResponse)
async def list_webhook_endpoints(
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
) -> Dict[str, Any]:
    """Return configured outbound webhook endpoints."""
    endpoints = db.query(WebhookEndpoint).order_by(WebhookEndpoint.created_at.desc()).all()
    return {
        "endpoints": [endpoint_to_dict(endpoint) for endpoint in endpoints],
        "supported_event_types": SUPPORTED_EVENT_TYPES,
    }


@router.post("", response_model=WebhookEndpointResponse)
async def create_webhook(
    payload: WebhookEndpointCreate,
    request: Request,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
) -> Dict[str, Any]:
    """Create an outbound webhook endpoint."""
    workspace = assign_default_workspace_to_unscoped_rows(db)
    try:
        endpoint, raw_secret = create_webhook_endpoint(db, **payload.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    record_workspace_audit_log(
        db,
        workspace=workspace,
        action="webhook.created",
        entity_type="webhook_endpoint",
        entity_id=endpoint.id,
        entity_name=endpoint.name,
        details={"event_types": payload.event_types, "enabled": endpoint.enabled},
        auth_context=_auth,
        request=request,
        commit=True,
    )
    body = endpoint_to_dict(endpoint)
    body["secret"] = raw_secret
    return body


@router.put("/{endpoint_id}", response_model=WebhookEndpointResponse)
async def update_webhook(
    endpoint_id: int,
    payload: WebhookEndpointUpdate,
    request: Request,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
) -> Dict[str, Any]:
    """Update an outbound webhook endpoint."""
    workspace = assign_default_workspace_to_unscoped_rows(db)
    endpoint = db.query(WebhookEndpoint).filter(WebhookEndpoint.id == endpoint_id).first()
    if endpoint is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Webhook endpoint not found"
        )
    try:
        endpoint, raw_secret = update_webhook_endpoint(
            db,
            endpoint,
            **payload.model_dump(exclude_unset=True),
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    record_workspace_audit_log(
        db,
        workspace=workspace,
        action="webhook.updated",
        entity_type="webhook_endpoint",
        entity_id=endpoint.id,
        entity_name=endpoint.name,
        details={"changed_fields": changed_fields(payload.model_dump(exclude_unset=True))},
        auth_context=_auth,
        request=request,
        commit=True,
    )
    body = endpoint_to_dict(endpoint)
    body["secret"] = raw_secret
    return body


@router.delete("/{endpoint_id}", response_model=WebhookEndpointResponse)
async def disable_webhook(
    endpoint_id: int,
    request: Request,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
) -> Dict[str, Any]:
    """Disable a webhook endpoint without deleting delivery history."""
    workspace = assign_default_workspace_to_unscoped_rows(db)
    endpoint = db.query(WebhookEndpoint).filter(WebhookEndpoint.id == endpoint_id).first()
    if endpoint is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Webhook endpoint not found"
        )
    endpoint.enabled = False
    db.commit()
    db.refresh(endpoint)
    record_workspace_audit_log(
        db,
        workspace=workspace,
        action="webhook.disabled",
        entity_type="webhook_endpoint",
        entity_id=endpoint.id,
        entity_name=endpoint.name,
        auth_context=_auth,
        request=request,
        commit=True,
    )
    body = endpoint_to_dict(endpoint)
    body["secret"] = None
    return body


@router.get("/deliveries", response_model=WebhookDeliveryListResponse)
async def list_webhook_deliveries(
    endpoint_id: Optional[int] = None,
    delivery_status: Optional[str] = Query(None, alias="status"),
    limit: int = 50,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
) -> Dict[str, Any]:
    """Return recent outbound webhook deliveries."""
    query = db.query(WebhookDelivery)
    if endpoint_id is not None:
        query = query.filter(WebhookDelivery.endpoint_id == endpoint_id)
    if delivery_status:
        query = query.filter(WebhookDelivery.status == delivery_status)
    deliveries = (
        query.order_by(WebhookDelivery.created_at.desc(), WebhookDelivery.id.desc())
        .limit(max(1, min(limit, 200)))
        .all()
    )
    return {"deliveries": [delivery_to_dict(delivery) for delivery in deliveries]}


@router.post("/{endpoint_id}/test", response_model=WebhookTestResponse)
async def test_webhook(
    endpoint_id: int,
    request: Request,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
) -> Dict[str, Any]:
    """Queue and immediately attempt a test delivery for an endpoint."""
    workspace = assign_default_workspace_to_unscoped_rows(db)
    try:
        delivery = queue_test_webhook(db, endpoint_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    delivered = deliver_due_webhooks(db, endpoint_id=endpoint_id, limit=1)
    record_workspace_audit_log(
        db,
        workspace=workspace,
        action="webhook.tested",
        entity_type="webhook_endpoint",
        entity_id=endpoint_id,
        details={"delivery_id": delivery.id},
        auth_context=_auth,
        request=request,
        commit=True,
    )
    return {"delivery": delivery_to_dict(delivered[0] if delivered else delivery)}


@router.post("/deliveries/process", response_model=WebhookDeliveryListResponse)
async def process_due_webhooks(
    limit: int = 25,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
) -> Dict[str, Any]:
    """Attempt due pending webhook deliveries."""
    deliveries = deliver_due_webhooks(db, limit=max(1, min(limit, 100)))
    return {"deliveries": [delivery_to_dict(delivery) for delivery in deliveries]}
