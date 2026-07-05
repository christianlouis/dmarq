from app.services.remediation_queue import (
    _remediation_notification_payload,
    build_remediation_queue,
)


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
    assert queue["items"][0]["action_plan"]["owner"] == "Domain DNS operator"
    assert queue["items"][0]["action_plan"]["automation_path"] == "provider_preview"
    assert queue["items"][0]["action_plan"]["guidance_paths"][0]["key"] == "provider"
    assert "cloudflare" in queue["items"][0]["action_plan"]["guidance_paths"][0]["label"].lower()
    assert queue["items"][0]["action_plan"]["guidance_paths"][1]["key"] == "manual"
    assert (
        "preview the provider mutation"
        in " ".join(queue["items"][0]["action_plan"]["steps"]).lower()
    )
    assert queue["items"][0]["action_plan"]["completion_criteria"]
    assert queue["items"][0]["verification_plan"]["status"] == "pending_operator_approval"
    assert "fresh DNS evidence" in queue["items"][0]["verification_plan"]["summary"]
    assert any(
        "provider preview was approved" in evidence
        for evidence in queue["items"][0]["verification_plan"]["evidence_needed"]
    )
    assert queue["items"][1]["verification_plan"]["status"] == "pending_sender_review"
    assert "next receiver report window" in queue["items"][1]["verification_plan"]["next_check"]
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
    assert queue["items"][0]["action_plan"]["automation_path"] == "manual"
    assert {path["key"] for path in queue["items"][0]["action_plan"]["guidance_paths"]} == {
        "provider",
        "self_hosted",
    }
    assert queue["items"][0]["action_plan"]["completion_criteria"]
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
    assert queue["items"][0]["action_plan"]["owner"] == "Domain DNS operator"
    assert queue["items"][0]["action_plan"]["steps"]
    assert queue["items"][0]["notification"]["state"] == "action_required"
    assert queue["items"][0]["notification"]["event"] == (
        "dmarq.remediation.manual_action_required"
    )


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
