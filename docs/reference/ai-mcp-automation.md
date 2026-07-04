# AI and MCP Automation

Milestone 16 adds optional automation surfaces that are safe by default:

- AI assistance is disabled until `ai.enabled=true`.
- MCP access is disabled until `mcp.enabled=true`.
- MCP requires scoped API tokens with `mcp:read`.
- Provider secrets are not stored in DMARQ settings.
- Safe context redacts secret-like key/value fragments, bearer tokens, long
  opaque values, and email local-parts in strict mode.
- Action tools produce reviewable proposals first. Confirmation is audited, and
  the current implementation does not apply DNS or other external changes.
- Remediation plans are deterministic by default and can optionally be enhanced
  through LiteLLM/OpenAI-compatible providers after explicit opt-in.

## Settings

| Key | Default | Purpose |
| --- | --- | --- |
| `ai.enabled` | `false` | Enables AI assistance endpoints |
| `ai.provider` | `template` | `template`, `local`, `remote`, or `litellm` provider mode |
| `ai.model` | empty | Optional model name |
| `ai.remote_base_url` | empty | Optional remote provider URL |
| `ai.redaction_mode` | `strict` | `strict` or `balanced` safe-context redaction |
| `ai.action_tools_enabled` | `false` | Allows proposal confirmation records |
| `ai.remediation_cache_seconds` | `86400` | Cache TTL for AI remediation plans; demo mode uses a longer fixed cache |
| `mcp.enabled` | `false` | Enables the read-only MCP endpoint |

Use 1Password or another deployment secret injector for provider credentials.
Do not put provider API keys into DMARQ settings.

## Safe Context

`GET /api/v1/ai/domains/{domain}/context` builds the payload that model or
agent surfaces are allowed to inspect. It includes:

- domain summary counts
- recent report metadata
- top sending sources
- evidence links to the UI
- redaction metadata

The payload deliberately excludes raw report XML, mailbox credentials, OAuth
tokens, notification target URLs, and original forensic message content.

## Remediation Plans

`GET /api/v1/ai/domains/{domain}/remediation-plan` builds a step-by-step plan
from the current DNS lint findings, observed DKIM selectors, configured mail
sources, DNS provider type, target records, and redacted report summary. Use
`finding_code=...` to focus the plan on one problem.

Template mode returns deterministic steps and is available without a remote
model. When `ai.enabled=true` and `ai.provider` is `local`, `remote`, or
`litellm`, DMARQ uses LiteLLM to request a JSON remediation plan from the
configured model. `ai.remote_base_url` can point at an OpenAI-compatible local
or hosted endpoint. Provider credentials must be injected into the process
environment, for example through 1Password or Kubernetes secrets; DMARQ settings
do not store API keys.

Remote remediation plans are cached by a hash of the redacted context,
provider, model, and base-URL state. Demo mode always uses the template plan
and a long cache window so the public demo does not generate repeated model
requests.

## MCP

`POST /api/v1/mcp` accepts minimal JSON-RPC requests for:

- `initialize`
- `tools/list`
- `tools/call`

The current tools are read-only:

- `list_domains`
- `export_catalog`
- `workspace_usage`
- `domain_summary`
- `domain_posture`
- `health_evidence_export`
- `alert_history`
- `domain_sources`
- `dns_lint`
- `dns_change_plan`
- `remediation_queue`
- `source_intelligence`
- `action_proposals`

Create a token with the `mcp:read` scope and send it through `X-API-Key`.

## Audit

DMARQ records sanitized workspace audit events for:

- `ai.summary_generated`
- `ai.action_proposals_generated`
- `ai.action_proposal_confirmed`
- `mcp.tool_called`

Audit details are sanitized with the same secret-field redaction used for other
workspace audit logs.
