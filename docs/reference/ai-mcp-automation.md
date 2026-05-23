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

## Settings

| Key | Default | Purpose |
| --- | --- | --- |
| `ai.enabled` | `false` | Enables AI assistance endpoints |
| `ai.provider` | `template` | `template`, `local`, or `remote` provider mode |
| `ai.model` | empty | Optional model name |
| `ai.remote_base_url` | empty | Optional remote provider URL |
| `ai.redaction_mode` | `strict` | `strict` or `balanced` safe-context redaction |
| `ai.action_tools_enabled` | `false` | Allows proposal confirmation records |
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

## MCP

`POST /api/v1/mcp` accepts minimal JSON-RPC requests for:

- `initialize`
- `tools/list`
- `tools/call`

The current tools are read-only:

- `list_domains`
- `domain_summary`
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
