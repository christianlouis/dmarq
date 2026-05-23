# Mail Connector Framework

DMARQ mailbox integrations should share one ingestion contract so new providers do not fork import behavior.

## Connector Contract

New mail-source connectors should implement the `MailSourceConnector` protocol in `backend/app/services/mail_connector.py`:

- `import_context(days=None)` returns safe provider context such as source type, target mailbox, target folder, and search window. Do not include access tokens, refresh tokens, passwords, client secrets, authorization headers, raw provider payloads, or full message bodies.
- `search_messages(days)` returns provider messages within the bounded search window.
- `iter_attachments(message)` yields attachments for one provider message.
- `fetch_reports(days=7)` runs the full ingestion path and returns the shared import-result shape.

Use `ConnectorMessage` and `ConnectorAttachment` when provider data can be normalized cleanly. A connector may keep raw provider objects internally, but API responses and import history must use sanitized context and details only.

## Import Result Shape

Use `initial_import_stats()` to start an import result. The common keys are:

- `success`
- `processed`
- `reports_found`
- `forensic_reports_found`
- `duplicate_reports`
- `duplicate_forensic_reports`
- `new_domains`
- `errors`
- `new_ingested_ids`
- `details`

Use `append_import_detail()` for message and attachment outcomes. Details should make retries understandable with reasons such as `already_ingested_message`, `unsupported_attachment`, `empty_attachment`, `parse_failed`, `duplicate`, or `imported`.

Use `load_ingested_ids()` and `dump_ingested_ids()` for provider message IDs. A connector should mark a message as ingested only after the message was processed or determined to be safely skippable. Retryable message or attachment failures should not add the message ID to the ingested list.

## Error Handling

Provider failures must be mapped to sanitized, operator-readable diagnostics:

- Use `sanitize_connector_error()` before storing or returning provider exception text.
- Use `connector_failure_stats()` for failed list/search/setup paths.
- Keep raw provider responses out of logs, import history, API responses, and frontend attributes.
- Prefer bounded retries with provider backoff hints for throttling or temporary service failures.

## Secret Handling

Connectors may receive secrets from encrypted database fields or environment variables injected by the deployment runtime. They must not print or return those values.

For local, preprod, and production deployments, prefer 1Password Environments or another runner-level secret injection mechanism. The connector code should only read the values it needs at runtime and should keep generated diagnostics safe for GitHub issues, import history, screenshots, and support requests.

When adding a connector, add tests proving that:

- duplicated provider message IDs do not inflate import totals,
- parse failures and duplicates appear in `details`,
- provider errors are redacted,
- search/backfill windows are bounded,
- secret-bearing strings are redacted before storage or API return.
