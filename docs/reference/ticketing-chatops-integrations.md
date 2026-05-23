# Ticketing and Chatops Templates

DMARQ publishes workflow templates for turning webhook events into tickets and
channel notifications. Use these templates with a relay, automation platform, or
SIEM rule that receives signed DMARQ webhook events.

## Template Endpoint

Administrators can fetch the template bundle from:

```http
GET /api/v1/integrations/ticketing-chatops/templates
```

The response contains:

- `schema_version`: stable workflow template identifier, currently `dmarq.workflow.template.v1`.
- `event_workflow_mappings`: event-to-owner, severity, action, and dedupe rules.
- `sample_context`: example values for rendering templates.
- `payload_templates`: Jira, GitHub Issues, Slack, and Microsoft Teams shapes.
- `operating_model`: ownership, dedupe, threading, and noise-control guidance.

## Event Routing

Use these default workflow mappings as the starting point:

| Event | Owner | Ticket Action | Chat Action |
| --- | --- | --- | --- |
| `dmarq.sender.new` | email-security | create or update | notify channel |
| `dmarq.compliance.drop` | email-security | create or update | notify channel and thread |
| `dmarq.reports.missing` | mail-operations | create or update | notify channel |
| `dmarq.alert.created` | email-security | create or update | notify channel |
| `dmarq.alert.resolved` | email-security | resolve or comment | notify thread |

Use the DMARQ webhook `X-DMARQ-Idempotency-Key` header when available. If the
receiver is building a workflow from API output, use the documented
`dedupe_key_template` from the template endpoint.

## Jira

Create or update one issue per active signal. Look up open issues by project,
label, and dedupe key before creating a new one.

```json
{
  "operation": "create_or_update_issue",
  "lookup": {
    "jql": "project = EMAILSEC AND labels = \"dmarq\" AND \"Dedupe Key\" ~ \"{dedupe_key}\" AND statusCategory != Done"
  },
  "create": {
    "fields": {
      "project": {"key": "EMAILSEC"},
      "issuetype": {"name": "Task"},
      "summary": "[DMARQ][{severity}] {title}",
      "labels": ["dmarq", "email-security", "{alert_rule}"],
      "priority": {"name": "High"},
      "customfield_dedupe_key": "{dedupe_key}"
    }
  },
  "update": {
    "comment": "{event_time}: {detail}"
  },
  "resolve": {
    "transition": "Done",
    "comment": "DMARQ reports this alert is resolved. Event: {event_id}"
  }
}
```

Store Jira credentials in the relay, CI/CD variable store, or ticketing
automation platform.

## GitHub Issues

For teams tracking operations work in GitHub, create or update one issue in the
operations repository:

```json
{
  "operation": "create_or_update_issue",
  "repository": "security-operations/email-auth",
  "lookup": {
    "state": "open",
    "labels": ["dmarq", "{alert_rule}", "dedupe:{dedupe_key}"]
  },
  "create": {
    "title": "[DMARQ][{severity}] {title}",
    "labels": ["dmarq", "email-security", "{alert_rule}", "dedupe:{dedupe_key}"]
  },
  "update": {
    "comment": "{event_time}: {detail}\n\nDedupe key: `{dedupe_key}`"
  },
  "resolve": {
    "state": "closed",
    "comment": "Resolved by DMARQ event `{event_id}`."
  }
}
```

Use labels for routing and dedupe. Keep human assignment rules in GitHub or the
relay instead of hard-coding personal owners in DMARQ payloads.

## Slack

Send a concise summary to a stable channel, then keep updates in a thread keyed
by the dedupe key:

```json
{
  "channel": "#email-security",
  "thread_key": "{dedupe_key}",
  "text": "[DMARQ][{severity}] {title}",
  "blocks": [
    {
      "type": "header",
      "text": {"type": "plain_text", "text": "DMARQ: {title}"}
    },
    {
      "type": "section",
      "text": {"type": "mrkdwn", "text": "{detail}"}
    },
    {
      "type": "section",
      "fields": [
        {"type": "mrkdwn", "text": "*Domain*\n{domain}"},
        {"type": "mrkdwn", "text": "*Severity*\n{severity}"},
        {"type": "mrkdwn", "text": "*Compliance*\n{compliance_rate}%"},
        {"type": "mrkdwn", "text": "*Drop*\n{drop_points} points"}
      ]
    }
  ]
}
```

Use channel mentions sparingly. Reserve paging or urgent mentions for
high-severity compliance drops or repeated missing-report windows.

## Microsoft Teams

Teams destinations can use an Adaptive Card:

```json
{
  "type": "message",
  "attachments": [
    {
      "contentType": "application/vnd.microsoft.card.adaptive",
      "content": {
        "type": "AdaptiveCard",
        "version": "1.5",
        "body": [
          {
            "type": "TextBlock",
            "size": "Medium",
            "weight": "Bolder",
            "text": "DMARQ: {title}"
          },
          {"type": "TextBlock", "wrap": true, "text": "{detail}"}
        ]
      }
    }
  ]
}
```

Use the relay or workflow platform to map dedupe keys to Teams threads when the
destination supports it.

## Operating Model

- Use one ticket per active signal and dedupe by DMARQ idempotency key or the documented dedupe key.
- Route sender, compliance, and alert signals to email security; route missing-report signals to mail operations.
- Close or comment on existing tickets when `dmarq.alert.resolved` arrives.
- Send chat updates into the same thread while a signal remains active.
- Keep repeats quiet: daily reminders are usually enough for missing reports, and compliance drops should follow configured thresholds.
- Keep Jira, GitHub, Slack, and Teams credentials in the receiving platform or secret manager, not in DMARQ payloads.
