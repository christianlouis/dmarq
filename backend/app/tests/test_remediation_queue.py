from app.services.remediation_queue import build_remediation_queue


def test_remediation_queue_prioritizes_provider_ready_dns_plan():
    health = {
        "actions": [
            {
                "type": "missing_dmarc",
                "severity": "high",
                "title": "Publish DMARC",
                "detail": "No DMARC policy was found.",
                "next_step": "Publish a DMARC TXT record.",
                "score_impact": 30,
                "evidence": [{"label": "record", "value": "_dmarc.example.com"}],
            },
            {
                "type": "low_compliance",
                "severity": "medium",
                "title": "Review failing senders",
                "detail": "Some senders fail DMARC.",
                "next_step": "Investigate the top failing source.",
                "score_impact": 12,
            },
        ]
    }
    dns_guidance = {
        "findings": [
            {
                "code": "dmarc_missing",
                "severity": "error",
                "title": "Publish DMARC",
                "detail": "No DMARC TXT record was found.",
                "evidence": ["_dmarc.example.com"],
            }
        ],
        "change_plans": [
            {
                "plan_id": "dmarc-missing",
                "finding_code": "dmarc_missing",
                "severity": "error",
                "operation": "create",
                "record_type": "TXT",
                "name": "_dmarc.example.com",
                "proposed_value": "v=DMARC1; p=none; rua=mailto:dmarc@example.com",
                "current_values": [],
                "rationale": "Publish a monitoring DMARC record.",
                "expected_health_impact": "High",
                "manual_steps": ["Create the TXT record."],
            }
        ],
    }

    queue = build_remediation_queue(
        domain="example.com",
        health=health,
        dns_guidance=dns_guidance,
        available_write_providers=["cloudflare"],
        recommended_provider="cloudflare",
    )

    assert queue["status"] == "needs_approval"
    assert queue["summary"] == {
        "total": 2,
        "approval_ready": 1,
        "manual_action": 0,
        "investigate": 1,
        "informational": 0,
        "notify_approval_required": 1,
        "notify_action_required": 0,
        "notify_investigation_required": 1,
        "notify_summary_only": 0,
    }
    assert queue["items"][0]["id"] == "dns:dmarc-missing"
    assert queue["items"][0]["state"] == "approval_ready"
    assert queue["items"][0]["automation"]["eligible"] is True
    assert queue["items"][0]["automation"]["apply_endpoint"] == (
        "/api/v1/domains/example.com/dns/change-plan/apply"
    )
    notification = queue["items"][0]["notification"]
    assert notification == {
        "state": "approval_required",
        "event": "dmarq.remediation.approval_required",
        "channel": "email_security",
        "dedupe_key": "dmarq:remediation:example.com:dns:dmarc-missing",
        "reason": "Notify an operator that a safe DNS repair is ready for preview.",
        "next_transition": "verified_after_apply",
        "payload_preview": notification["payload_preview"],
    }
    assert notification["payload_preview"] == {
        "schema_version": "dmarq.remediation.notification.v1",
        "domain": "example.com",
        "item_id": "dns:dmarc-missing",
        "source": "dns_lint",
        "state": "approval_ready",
        "severity": "critical",
        "confidence": "high",
        "title": "Publish DMARC",
        "detail": "No DMARC TXT record was found.",
        "notification_state": "approval_required",
        "event_type": "dmarq.remediation.approval_required",
        "channel": "email_security",
        "dedupe_key": "dmarq:remediation:example.com:dns:dmarc-missing",
        "reason": "Notify an operator that a safe DNS repair is ready for preview.",
        "next_transition": "verified_after_apply",
        "automation": {
            "eligible": True,
            "requires_approval": True,
            "provider": "cloudflare",
            "plan_id": "dmarc-missing",
            "apply_endpoint": "/api/v1/domains/example.com/dns/change-plan/apply",
        },
        "evidence": [{"label": "finding", "value": "_dmarc.example.com"}],
    }
    assert queue["items"][1]["notification"]["state"] == "investigation_required"
    assert queue["items"][1]["notification"]["event"] == (
        "dmarq.remediation.investigation_required"
    )
    assert queue["items"][1]["notification"]["payload_preview"]["event_type"] == (
        "dmarq.remediation.investigation_required"
    )
    assert [item["id"] for item in queue["items"]] == [
        "dns:dmarc-missing",
        "health:low_compliance",
    ]


def test_remediation_queue_keeps_placeholder_plan_manual():
    queue = build_remediation_queue(
        domain="example.com",
        health={"actions": []},
        dns_guidance={
            "findings": [
                {
                    "code": "dkim_selector_missing",
                    "severity": "warning",
                    "title": "Publish DKIM",
                    "detail": "The selector target is not configured.",
                }
            ],
            "change_plans": [
                {
                    "plan_id": "dkim-selector",
                    "finding_code": "dkim_selector_missing",
                    "severity": "warning",
                    "operation": "create",
                    "record_type": "CNAME",
                    "name": "pm._domainkey.example.com",
                    "proposed_value": "<selector target from mail provider>",
                    "provider_value_required": True,
                    "rationale": "Provider-specific DKIM target is required.",
                    "expected_health_impact": "Medium",
                }
            ],
        },
        available_write_providers=["cloudflare"],
        recommended_provider="cloudflare",
    )

    assert queue["status"] == "needs_manual_action"
    assert queue["summary"]["manual_action"] == 1
    assert queue["summary"]["notify_summary_only"] == 1
    assert queue["items"][0]["state"] == "manual_action"
    assert queue["items"][0]["automation"]["eligible"] is False
    assert queue["items"][0]["automation"]["apply_endpoint"] is None
    assert queue["items"][0]["notification"]["state"] == "summary_only"
    assert queue["items"][0]["notification"]["event"] == "dmarq.remediation.summary"
    assert queue["items"][0]["notification"]["payload_preview"]["event_type"] == (
        "dmarq.remediation.summary"
    )


def test_remediation_queue_requires_recommended_provider_for_automation():
    queue = build_remediation_queue(
        domain="example.com",
        health={"actions": []},
        dns_guidance={
            "findings": [
                {
                    "code": "dmarc_missing",
                    "severity": "error",
                    "title": "Publish DMARC",
                    "detail": "No DMARC TXT record was found.",
                }
            ],
            "change_plans": [
                {
                    "plan_id": "dmarc-missing",
                    "finding_code": "dmarc_missing",
                    "severity": "error",
                    "operation": "create",
                    "record_type": "TXT",
                    "name": "_dmarc.example.com",
                    "proposed_value": "v=DMARC1; p=none; rua=mailto:dmarc@example.com",
                    "rationale": "Publish a monitoring DMARC record.",
                }
            ],
        },
        available_write_providers=["cloudflare"],
        recommended_provider=None,
    )

    assert queue["status"] == "needs_manual_action"
    assert queue["summary"]["approval_ready"] == 0
    assert queue["summary"]["manual_action"] == 1
    assert queue["items"][0]["state"] == "manual_action"
    assert queue["items"][0]["automation"]["eligible"] is False
    assert queue["items"][0]["automation"]["provider"] is None
    assert queue["items"][0]["automation"]["apply_endpoint"] is None
    assert queue["items"][0]["notification"]["state"] == "action_required"
    assert queue["items"][0]["notification"]["event"] == (
        "dmarq.remediation.manual_action_required"
    )
