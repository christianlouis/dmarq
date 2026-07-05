from app.services.remediation_queue import (
    TRACKS,
    _remediation_notification_payload,
    _summary,
    build_remediation_queue,
)


def test_remediation_summary_emits_track_counters_in_stable_order():
    summary = _summary([])

    track_keys = [key for key in summary if key.startswith("track_")]

    assert isinstance(TRACKS, tuple)
    assert track_keys == [f"track_{track}" for track in TRACKS]


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
        "provider_fix_available": 1,
        "self_hosted_guidance": 1,
        "manual_only": 0,
        "blocked_by_prerequisite": 0,
        "repair_preview_ready": 1,
        "repair_approval_pending": 0,
        "repair_blocked": 0,
        "repair_needs_evidence": 2,
        "repair_ready_for_preview": 1,
        "repair_waiting_on_operator": 1,
        "repair_readiness_blocked": 0,
        "repair_readiness_score": 80,
        "provider_preview_available": 1,
        "provider_apply_after_approval": 1,
        "provider_apply_blocked": 0,
        "provider_value_missing": 0,
        "provider_manual_fallback": 1,
        "requires_fresh_evidence": 2,
        "rollback_guidance": 2,
        "closure_gate_required": 2,
        "stale_evidence_warning": 2,
        "evidence_refresh_required": 2,
        "evidence_refresh_dns": 1,
        "evidence_refresh_reports": 1,
        "evidence_refresh_reputation": 0,
        "evidence_refresh_prerequisite": 0,
        "notify_approval_required": 1,
        "notify_action_required": 0,
        "notify_investigation_required": 1,
        "notify_summary_only": 0,
        "track_blocked_by_prerequisite": 0,
        "track_manual_dns": 0,
        "track_manual_only": 0,
        "track_provider_preview": 1,
        "track_reputation_review": 0,
        "track_self_hosted_or_provider": 0,
        "track_sender_investigation": 1,
    }
    assert queue["loop"] == {
        "domain": "example.com",
        "status": "approval_required",
        "next_action": "Preview and approve the highest-priority provider-backed repair.",
        "what_dmarq_can_fix": 1,
        "what_needs_approval": 1,
        "what_needs_manual_action": 0,
        "what_needs_investigation": 1,
        "manual_only": 0,
        "blocked_by_prerequisite": 0,
        "track_provider_preview": 1,
        "track_manual_dns": 0,
        "track_sender_investigation": 1,
        "track_reputation_review": 0,
        "track_self_hosted_or_provider": 0,
        "repair_preview_ready": 1,
        "repair_approval_pending": 0,
        "repair_blocked": 0,
        "repair_needs_evidence": 2,
        "repair_ready_for_preview": 1,
        "repair_waiting_on_operator": 1,
        "repair_readiness_blocked": 0,
        "repair_readiness_score": 80,
        "provider_preview_available": 1,
        "provider_apply_after_approval": 1,
        "provider_apply_blocked": 0,
        "provider_value_missing": 0,
        "provider_manual_fallback": 1,
        "requires_fresh_evidence": 2,
        "rollback_guidance": 2,
        "closure_gate_required": 2,
        "stale_evidence_warning": 2,
        "evidence_refresh_required": 2,
        "evidence_refresh_dns": 1,
        "evidence_refresh_reports": 1,
        "evidence_refresh_reputation": 0,
        "evidence_refresh_prerequisite": 0,
        "top_item_id": "dns:dmarc-missing",
        "top_incident_type": "dmarc_policy_missing_or_weak",
        "top_loop_state": "proposal_ready_for_approval",
        "top_remediation_track": "provider_preview",
        "top_priority_band": "urgent",
        "top_priority_score": 455,
    }
    assert queue["items"][0]["id"] == "dns:dmarc-missing"
    assert queue["items"][0]["incident_type"] == "dmarc_policy_missing_or_weak"
    assert queue["items"][0]["loop_state"] == "proposal_ready_for_approval"
    assert queue["items"][0]["remediation_track"] == "provider_preview"
    assert queue["items"][0]["priority_score"] == 455
    assert queue["items"][0]["priority_band"] == "urgent"
    assert queue["items"][0]["operator_decisions"][:2] == [
        "preview_change",
        "approve_after_preview",
    ]
    assert queue["items"][0]["repair_progression"] == {
        "stage": "preview_ready",
        "label": "Preview ready",
        "summary": "A connected DNS provider can prepare the exact mutation for review.",
        "next_gate": "Human approval before apply",
        "next_step": (
            "Open the provider preview, compare old and new DNS values, then approve or reject."
        ),
        "can_preview": True,
        "can_apply_after_approval": True,
        "manual_fallback": True,
        "verification_required": True,
        "verification_status": "pending_operator_approval",
        "readiness_level": "ready_for_preview",
        "readiness_label": "Ready for provider preview",
        "readiness_score": 80,
        "readiness_reasons": [
            "A connected DNS provider can produce an exact change preview.",
            "A human approval gate is still required before apply.",
            "Fresh evidence is required before DMARQ can call this fixed.",
        ],
        "blocked_by": [
            "fresh_evidence_before_closure",
            "pending_operator_approval",
        ],
        "next_safe_action": (
            "Open the provider preview, compare old and new DNS values, then approve or reject."
        ),
    }
    assert queue["items"][0]["provider_repair_plan"] == {
        "kind": "dns_provider_repair",
        "provider": "cloudflare",
        "provider_label": "cloudflare",
        "plan_id": "dmarc-missing",
        "stage": "preview_ready",
        "safe_preview_available": True,
        "can_apply_after_approval": True,
        "apply_requires_approval": True,
        "apply_blocked": False,
        "blocked_reasons": [],
        "manual_fallback": True,
        "preview_endpoint": "/api/v1/domains/example.com/dns/change-plan/apply",
        "apply_endpoint": "/api/v1/domains/example.com/dns/change-plan/apply",
        "operation": "create",
        "record_name": "_dmarc.example.com",
        "record_type": "TXT",
        "capability": "provider_preview",
        "next_step": (
            "Open the provider preview, compare old and new DNS values, then approve or reject."
        ),
        "completion_gate": "Close only after approved provider apply and fresh DNS evidence agree.",
    }
    assert queue["items"][0]["state"] == "approval_ready"
    assert queue["items"][0]["automation"]["eligible"] is True
    assert queue["items"][0]["automation"]["apply_endpoint"] == (
        "/api/v1/domains/example.com/dns/change-plan/apply"
    )
    assert queue["items"][0]["action_plan"]["owner"] == "Domain DNS operator"
    assert queue["items"][0]["action_plan"]["automation_path"] == "provider_preview"
    assert queue["items"][0]["action_plan"]["safe_to_automate"] is True
    assert queue["items"][0]["action_plan"]["risk_level"] == "medium"
    assert (
        "Preview the exact DNS diff"
        in queue["items"][0]["action_plan"]["operator_decision_summary"]
    )
    assert queue["items"][0]["action_plan"]["guidance_paths"][0]["key"] == "provider"
    assert "cloudflare" in queue["items"][0]["action_plan"]["guidance_paths"][0]["label"].lower()
    assert queue["items"][0]["action_plan"]["guidance_paths"][1]["key"] == "manual"
    assert (
        "preview the provider mutation"
        in " ".join(queue["items"][0]["action_plan"]["steps"]).lower()
    )
    assert queue["items"][0]["action_plan"]["completion_criteria"]
    assert queue["items"][0]["action_plan"]["requires_fresh_evidence"] is True
    assert any(
        "authoritative zone" in checkpoint
        for checkpoint in queue["items"][0]["action_plan"]["decision_checkpoints"]
    )
    assert "restore the previous DNS value" in queue["items"][0]["action_plan"]["rollback_plan"]
    assert queue["items"][0]["verification_plan"]["status"] == "pending_operator_approval"
    assert queue["items"][0]["verification_plan"]["verification_method"] == (
        "provider_write_then_dns_refresh"
    )
    assert "Fresh DNS evidence" in queue["items"][0]["verification_plan"]["freshness_requirement"]
    assert "Keep the item open" in queue["items"][0]["verification_plan"]["failure_mode"]
    assert "fresh DNS evidence agree" in queue["items"][0]["verification_plan"]["closure_gate"]
    assert "preview alone" in queue["items"][0]["verification_plan"]["stale_evidence_warning"]
    assert "fresh DNS evidence" in queue["items"][0]["verification_plan"]["summary"]
    assert any(
        "provider preview was approved" in evidence
        for evidence in queue["items"][0]["verification_plan"]["evidence_needed"]
    )
    assert queue["items"][0]["evidence_refresh"] == {
        "required": True,
        "source": "dns",
        "refresh_key": "dns",
        "label": "Refresh DNS evidence",
        "safe_to_run": True,
        "recommended_action": (
            "Refresh DNS records, DNS lint, posture, and the remediation queue after the DNS TTL."
        ),
        "completion_signal": "The original DNS finding is absent from the refreshed queue.",
        "stale_warning": (
            "Do not mark this fixed from the preview alone; DNS propagation evidence is required."
        ),
        "next_check": "Refresh DNS posture after provider propagation, then rebuild the queue.",
        "ui_anchor": "#dns-records",
        "endpoint_hint": "/api/v1/domains/example.com/dns?refresh=true",
    }
    assert queue["items"][1]["verification_plan"]["status"] == "pending_sender_review"
    assert "next receiver report window" in queue["items"][1]["verification_plan"]["next_check"]
    assert queue["items"][1]["evidence_refresh"]["refresh_key"] == "reports_and_sources"
    assert queue["items"][1]["evidence_refresh"]["ui_anchor"] == "#sending-sources"
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
        "incident_type": "dmarc_policy_missing_or_weak",
        "loop_state": "proposal_ready_for_approval",
        "remediation_track": "provider_preview",
        "priority_score": 455,
        "priority_band": "urgent",
        "operator_decisions": [
            "preview_change",
            "approve_after_preview",
            "previewed",
            "acknowledged",
            "snoozed",
            "resolved",
            "rejected",
        ],
        "repair_progression": {
            "stage": "preview_ready",
            "label": "Preview ready",
            "summary": "A connected DNS provider can prepare the exact mutation for review.",
            "next_gate": "Human approval before apply",
            "next_step": (
                "Open the provider preview, compare old and new DNS values, then approve or reject."
            ),
            "can_preview": True,
            "can_apply_after_approval": True,
            "manual_fallback": True,
            "verification_required": True,
            "verification_status": "pending_operator_approval",
            "readiness_level": "ready_for_preview",
            "readiness_label": "Ready for provider preview",
            "readiness_score": 80,
            "readiness_reasons": [
                "A connected DNS provider can produce an exact change preview.",
                "A human approval gate is still required before apply.",
                "Fresh evidence is required before DMARQ can call this fixed.",
            ],
            "blocked_by": [
                "fresh_evidence_before_closure",
                "pending_operator_approval",
            ],
            "next_safe_action": (
                "Open the provider preview, compare old and new DNS values, then approve or reject."
            ),
        },
        "evidence_refresh": {
            "required": True,
            "source": "dns",
            "refresh_key": "dns",
            "label": "Refresh DNS evidence",
            "safe_to_run": True,
            "recommended_action": (
                "Refresh DNS records, DNS lint, posture, and the remediation queue after the DNS TTL."
            ),
            "completion_signal": "The original DNS finding is absent from the refreshed queue.",
            "stale_warning": (
                "Do not mark this fixed from the preview alone; DNS propagation evidence is required."
            ),
            "next_check": "Refresh DNS posture after provider propagation, then rebuild the queue.",
            "ui_anchor": "#dns-records",
            "endpoint_hint": "/api/v1/domains/example.com/dns?refresh=true",
        },
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
            "operation": "create",
            "record_name": "_dmarc.example.com",
            "record_type": "TXT",
        },
        "provider_repair_plan": {
            "kind": "dns_provider_repair",
            "provider": "cloudflare",
            "provider_label": "cloudflare",
            "plan_id": "dmarc-missing",
            "stage": "preview_ready",
            "safe_preview_available": True,
            "can_apply_after_approval": True,
            "apply_requires_approval": True,
            "apply_blocked": False,
            "blocked_reasons": [],
            "manual_fallback": True,
            "preview_endpoint": "/api/v1/domains/example.com/dns/change-plan/apply",
            "apply_endpoint": "/api/v1/domains/example.com/dns/change-plan/apply",
            "operation": "create",
            "record_name": "_dmarc.example.com",
            "record_type": "TXT",
            "capability": "provider_preview",
            "next_step": (
                "Open the provider preview, compare old and new DNS values, then approve or reject."
            ),
            "completion_gate": "Close only after approved provider apply and fresh DNS evidence agree.",
        },
        "action_plan": {
            "owner": "Domain DNS operator",
            "automation_path": "provider_preview",
            "risk_level": "medium",
            "safe_to_automate": True,
            "operator_decision_summary": (
                "Preview the exact DNS diff, then explicitly approve or reject the proposed repair."
            ),
            "completion_criteria": "Provider preview is approved, applied, and verified by DMARQ.",
            "decision_checkpoints": [
                "Confirm the authoritative zone and record owner before approving the preview.",
                "Compare old and proposed DNS values, including TTL and record type.",
                "Wait for fresh DNS evidence before treating the item as fixed.",
            ],
            "rollback_plan": (
                "If verification fails, restore the previous DNS value from the provider preview "
                "or keep the manual remediation item open."
            ),
            "requires_fresh_evidence": True,
            "steps": [
                "Open the DNS change plan and preview the provider mutation.",
                "Confirm the zone, record name, old value, new value, and TTL.",
                "Approve the change, then refresh DNS posture after propagation.",
            ],
            "guidance_paths": [
                {
                    "key": "provider",
                    "label": "cloudflare guided repair",
                    "owner": "Domain DNS operator",
                },
                {"key": "manual", "label": "Manual DNS fallback", "owner": "Domain DNS operator"},
            ],
        },
        "verification": {
            "label": "Verify after approved provider repair",
            "status": "pending_operator_approval",
            "method": "provider_write_then_dns_refresh",
            "freshness_requirement": "Fresh DNS evidence after provider propagation.",
            "failure_mode": "Keep the item open if the expected record is not visible.",
            "closure_gate": "Close only after approved provider apply and fresh DNS evidence agree.",
            "stale_evidence_warning": (
                "Do not mark this fixed from the preview alone; DNS propagation evidence is required."
            ),
            "summary": (
                "DMARQ should only mark this fixed after the approved cloudflare write is "
                "visible in fresh DNS evidence."
            ),
            "next_check": (
                "Refresh DNS posture after provider propagation, then rebuild the queue."
            ),
            "evidence_needed": [
                "The provider preview was approved and applied by a human operator.",
                "A fresh DNS lookup returns the expected record value from authoritative evidence.",
                "The remediation item disappears from the current queue after DNS refresh.",
            ],
        },
        "evidence": [{"label": "finding", "value": "_dmarc.example.com"}],
    }
    assert queue["items"][1]["notification"]["state"] == "investigation_required"
    assert queue["items"][1]["incident_type"] == "legitimate_sender_failing_alignment"
    assert queue["items"][1]["loop_state"] == "evidence_review_required"
    assert queue["items"][1]["remediation_track"] == "sender_investigation"
    assert "mark_legitimate" in queue["items"][1]["operator_decisions"]
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
    assert queue["summary"]["blocked_by_prerequisite"] == 1
    assert queue["summary"]["repair_blocked"] == 1
    assert queue["summary"]["repair_needs_evidence"] == 1
    assert queue["summary"]["repair_ready_for_preview"] == 0
    assert queue["summary"]["repair_waiting_on_operator"] == 0
    assert queue["summary"]["repair_readiness_blocked"] == 1
    assert queue["summary"]["repair_readiness_score"] == 20
    assert queue["summary"]["provider_preview_available"] == 0
    assert queue["summary"]["provider_apply_after_approval"] == 0
    assert queue["summary"]["provider_apply_blocked"] == 1
    assert queue["summary"]["provider_value_missing"] == 1
    assert queue["summary"]["provider_manual_fallback"] == 1
    assert queue["summary"]["closure_gate_required"] == 1
    assert queue["summary"]["rollback_guidance"] == 1
    assert queue["summary"]["notify_summary_only"] == 1
    assert queue["loop"]["status"] == "manual_action_required"
    assert queue["loop"]["blocked_by_prerequisite"] == 1
    assert queue["items"][0]["state"] == "manual_action"
    assert queue["items"][0]["remediation_track"] == "blocked_by_prerequisite"
    assert queue["items"][0]["loop_state"] == "operator_action_required"
    assert queue["items"][0]["automation"]["eligible"] is False
    assert queue["items"][0]["automation"]["apply_endpoint"] is None
    assert queue["items"][0]["action_plan"]["automation_path"] == "manual"
    assert {path["key"] for path in queue["items"][0]["action_plan"]["guidance_paths"]} == {
        "provider",
        "self_hosted",
    }
    assert queue["items"][0]["action_plan"]["completion_criteria"]
    assert queue["items"][0]["action_plan"]["requires_fresh_evidence"] is True
    assert any(
        "dns ttl" in checkpoint.lower()
        for checkpoint in queue["items"][0]["action_plan"]["decision_checkpoints"]
    )
    assert "keep the item open" in queue["items"][0]["action_plan"]["rollback_plan"]
    assert queue["items"][0]["repair_progression"]["stage"] == "blocked"
    assert queue["items"][0]["repair_progression"]["can_preview"] is False
    assert queue["items"][0]["repair_progression"]["manual_fallback"] is True
    assert queue["items"][0]["repair_progression"]["readiness_level"] == "blocked"
    assert queue["items"][0]["repair_progression"]["readiness_score"] == 20
    assert "provider_specific_value" in queue["items"][0]["repair_progression"]["blocked_by"]
    assert queue["items"][0]["provider_repair_plan"]["kind"] == "dns_provider_repair"
    assert queue["items"][0]["provider_repair_plan"]["safe_preview_available"] is False
    assert queue["items"][0]["provider_repair_plan"]["apply_blocked"] is True
    assert "provider_specific_value" in queue["items"][0]["provider_repair_plan"]["blocked_reasons"]
    assert queue["items"][0]["provider_repair_plan"]["record_name"] == (
        "pm._domainkey.example.com"
    )
    assert queue["items"][0]["notification"]["state"] == "summary_only"
    assert queue["items"][0]["notification"]["event"] == "dmarq.remediation.summary"
    assert queue["items"][0]["notification"]["payload_preview"]["event_type"] == (
        "dmarq.remediation.summary"
    )


def test_remediation_notification_payload_uses_first_non_empty_evidence_rows():
    """Payload previews keep the first five evidence rows after removing blanks."""
    payload = _remediation_notification_payload(
        "example.com",
        {
            "id": "health:review",
            "source": "health_score",
            "state": "manual_action",
            "severity": "medium",
            "title": "Review evidence",
            "notification": {"event": "dmarq.remediation.summary"},
            "automation": {},
            "evidence": [
                {"label": "empty", "value": ""},
                {"label": "first", "value": "one"},
                {"label": "empty_again", "value": None},
                {"label": "second", "value": "two"},
                {"label": "third", "value": "three"},
                {"label": "fourth", "value": "four"},
                {"label": "fifth", "value": "five"},
                {"label": "sixth", "value": "six"},
            ],
        },
    )

    assert payload["evidence"] == [
        {"label": "first", "value": "one"},
        {"label": "second", "value": "two"},
        {"label": "third", "value": "three"},
        {"label": "fourth", "value": "four"},
        {"label": "fifth", "value": "five"},
    ]


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
    assert queue["items"][0]["repair_progression"]["stage"] == "manual_repair"
    assert queue["items"][0]["repair_progression"]["next_gate"] == ("Operator applies DNS manually")
    assert queue["items"][0]["action_plan"]["owner"] == "Domain DNS operator"
    assert queue["items"][0]["action_plan"]["steps"]
    assert queue["items"][0]["notification"]["state"] == "action_required"
    assert queue["items"][0]["notification"]["event"] == (
        "dmarq.remediation.manual_action_required"
    )


def test_remediation_summary_uses_stored_tracks_after_metadata_application():
    """Summary counters should match each item's published remediation track."""
    summary = _summary(
        [
            {
                "state": "manual_action",
                "source": "dns_lint",
                "remediation_track": "manual_only",
                "notification": {"state": "summary_only"},
            },
            {
                "state": "manual_action",
                "source": "health_score",
                "remediation_track": "blocked_by_prerequisite",
                "notification": {"state": "summary_only"},
            },
        ]
    )

    assert summary["manual_only"] == 1
    assert summary["blocked_by_prerequisite"] == 1


def test_remediation_queue_adds_generic_operator_guidance_for_health_actions():
    queue = build_remediation_queue(
        domain="example.com",
        health={
            "actions": [
                {
                    "type": "review_forwarding",
                    "severity": "high",
                    "title": "Review forwarding alignment",
                    "detail": "Some forwarded messages are failing DMARC.",
                    "next_step": "Confirm whether the forwarding path is expected.",
                }
            ]
        },
        dns_guidance={"findings": [], "change_plans": []},
    )

    assert queue["status"] == "needs_manual_action"
    assert queue["items"][0]["action_plan"]["automation_path"] == "manual"
    assert queue["items"][0]["action_plan"]["guidance_paths"] == [
        {
            "key": "provider",
            "label": "Provider-guided remediation",
            "summary": (
                "Use the provider dashboard to confirm required DNS or sender settings "
                "before applying changes."
            ),
            "owner": "Mail operations owner",
        },
        {
            "key": "self_hosted",
            "label": "Self-hosted remediation",
            "summary": (
                "Apply the equivalent mail or DNS configuration directly in the "
                "local infrastructure."
            ),
            "owner": "Mail operations owner",
        },
    ]


def test_remediation_queue_adds_specific_low_compliance_playbook():
    queue = build_remediation_queue(
        domain="cklnet.com",
        health={
            "actions": [
                {
                    "type": "low_compliance",
                    "severity": "high",
                    "title": "Investigate failing senders",
                    "detail": "DMARC pass rate is 65.0%, below the 90% enforcement target.",
                    "next_step": "Open the domain detail page.",
                    "score_impact": 18,
                    "evidence": [
                        {"label": "pass_rate", "value": "65.0%"},
                        {"label": "failed", "value": "42"},
                    ],
                }
            ]
        },
        dns_guidance={"findings": [], "change_plans": []},
    )

    item = queue["items"][0]

    assert queue["status"] == "needs_investigation"
    assert item["state"] == "investigate"
    assert "last sent date" in item["action_plan"]["steps"][0]
    assert any("receiver, mailbox, or forwarding IPs" in step for step in item["next_steps"])
    assert "active failing sources" in item["action_plan"]["completion_criteria"]
    assert item["action_plan"]["automation_path"] == "investigate"


def test_remediation_queue_adds_specific_reputation_playbook():
    queue = build_remediation_queue(
        domain="example.com",
        health={
            "actions": [
                {
                    "type": "source_reputation_listed",
                    "severity": "critical",
                    "title": "Review listed sending IPs",
                    "detail": "1 observed sending source is listed.",
                    "score_impact": 18,
                    "evidence": [{"label": "listed_sources", "value": "1"}],
                }
            ]
        },
        dns_guidance={"findings": [], "change_plans": []},
    )

    item = queue["items"][0]

    assert queue["status"] == "needs_manual_action"
    assert item["state"] == "manual_action"
    assert any("delisting process" in step for step in item["action_plan"]["steps"])
    assert "delisted by the provider" in item["action_plan"]["completion_criteria"]
    assert item["notification"]["state"] == "action_required"


def test_remediation_queue_adds_specific_reputation_review_playbook():
    queue = build_remediation_queue(
        domain="example.com",
        health={
            "actions": [
                {
                    "type": "source_reputation_review",
                    "severity": "high",
                    "title": "Review suspicious sending source",
                    "detail": "A sender needs source intelligence review.",
                    "score_impact": 10,
                }
            ]
        },
        dns_guidance={"findings": [], "change_plans": []},
    )

    item = queue["items"][0]

    assert any("PTR, ASN, country" in step for step in item["next_steps"])
    assert any("human owner" in step for step in item["action_plan"]["prerequisites"])
    assert "unauthorized traffic" in item["action_plan"]["completion_criteria"]


def test_remediation_queue_adds_specific_policy_none_playbook():
    queue = build_remediation_queue(
        domain="example.com",
        health={
            "actions": [
                {
                    "type": "policy_none",
                    "severity": "high",
                    "title": "Move domain toward enforcement",
                    "detail": "The DMARC policy is still monitoring-only.",
                    "score_impact": 8,
                }
            ]
        },
        dns_guidance={"findings": [], "change_plans": []},
    )

    item = queue["items"][0]

    assert any("p=quarantine" in step for step in item["next_steps"])
    assert any("rua reporting remains configured" in step for step in item["prerequisites"])
    assert item["action_plan"]["completion_criteria"] == (
        "The domain enforces quarantine or reject without new failures."
    )


def test_remediation_queue_adds_specific_missing_dkim_playbook():
    queue = build_remediation_queue(
        domain="example.com",
        health={
            "actions": [
                {
                    "type": "missing_dkim",
                    "severity": "high",
                    "title": "Fix DKIM selector coverage",
                    "detail": "DKIM selectors from report data are not fully healthy.",
                    "score_impact": 12,
                }
            ]
        },
        dns_guidance={"findings": [], "change_plans": []},
    )

    item = queue["items"][0]

    assert any("exact DKIM TXT or CNAME value" in step for step in item["next_steps"])
    assert "Do not publish placeholder DKIM values." in item["action_plan"]["prerequisites"]
    assert item["action_plan"]["completion_criteria"] == (
        "Observed legitimate senders have healthy DKIM selectors."
    )
