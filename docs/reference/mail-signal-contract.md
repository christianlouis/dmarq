# Mail Signal Contract

DMARQ keeps protocol observations separate from product interpretation. This
prevents an aggregate DMARC report from being presented as proof that an
individual message was delivered, bounced, read, or placed in an inbox.

The versioned `dmarq.mail_signal.v1` envelope is returned with guided
mail-health assessments, domain mailflow diagnoses, and sending-source rows.
It is additive: existing API fields remain available while integrations move
to the explicit signal contract.

## Common envelope

Every signal includes:

- a stable `signal_id` and `schema_version`;
- `family`, `signal_type`, and protocol-specific `outcome`;
- `claim_level`: `observed`, `derived`, `inferred`, `operator_reported`, or
  `unknown`;
- `delivery_certainty`, which limits what DMARQ may say about delivery;
- source system, workspace/domain correlation, evidence window, and freshness;
- aggregate-safe evidence references and payload;
- a stable `guidance_key` for localized explanation.

Raw message bodies, mailbox credentials, tokens, and recipient addresses do
not belong in this envelope. Current DMARC signals use the `aggregate` privacy
classification.

## Signal families

| Family | What it means |
| --- | --- |
| `dmarc_authentication` | A receiver's aggregate SPF/DKIM alignment evaluation |
| `dmarc_reported_disposition` | The DMARC policy action recorded by the reporting receiver |
| `dmarc_failure_detail` | Failure-report evidence, when explicitly available |
| `smtp_tls_report` | TLS-RPT transport-path evidence |
| `dsn_delivery_status` | A delivery status notification from a sending system |
| `provider_delivery_event` | An event with the provider's documented semantics |
| `dns_posture` | Stored DNS posture evidence |
| `intake_health` | Persisted report-intake availability or failure |
| `operator_reported_symptom` | A symptom entered by an operator, not independently verified |

The DSN family is produced by IMAP, Gmail, Microsoft 365, raw-email webhook,
and manual DSN intake. The provider family is produced by the authenticated
provider-neutral event endpoint. DNS posture, intake health, and
operator-reported symptoms remain separate operational families; a family
being defined does not imply that every connector produces it.

## Delivery certainty

`delivery_certainty` is deliberately more precise than a generic status:

- `authentication_only`: DMARC authentication evidence, no delivery claim;
- `receiver_disposition_reported`: a receiver recorded `none`, `quarantine`,
  or `reject`, but this is not a per-message bounce claim;
- `transport_failure_reported`: a TLS transport failure was reported;
- `non_delivery_reported`: a DSN or equivalent explicitly reported
  non-delivery;
- `delivery_reported`: a provider explicitly reported delivery according to
  its own event definition, not inbox placement or reading;
- `inferred_only`: DMARQ formed an interpretation from supporting facts;
- `not_applicable`: the signal is operational evidence rather than a delivery
  observation.

## DMARC example

One aggregate sender row produces two signals rather than one ambiguous
"delivery" value:

```json
[
  {
    "family": "dmarc_authentication",
    "outcome": "mixed",
    "claim_level": "observed",
    "delivery_certainty": "authentication_only",
    "payload": {"passed": 40, "failed": 2}
  },
  {
    "family": "dmarc_reported_disposition",
    "outcome": "reject",
    "claim_level": "observed",
    "delivery_certainty": "receiver_disposition_reported",
    "payload": {"dispositions": {"reject": 2}}
  }
]
```

A guided conclusion built from these observations is separately marked
`inferred`. It must state what is known, what is inferred, what remains
unknown, and what evidence would verify the next action.

## Delivery event privacy

RFC DSNs are parsed with bounded message size, MIME-part, header, and recipient
limits. DMARQ retains normalized action, enhanced SMTP status, sanitized
diagnostic text, recipient domain, reporting/remote MTA, event time, and keyed
hashes for recipient and message/envelope identifiers. Original message bodies
and full recipient addresses are discarded. Provider events accept the same
minimal semantics and reject timestamps outside the bounded replay window.
Workspace retention defaults to 30 days and is enforced by scheduled cleanup.

## Compatibility

The sending-source API retains `delivery_status`, `delivery_label`, and
`delivery_detail` for compatibility. They describe historical aggregate
authentication categories and are deprecated. New clients should use
`authentication_*`, `receiver_disposition*`, `claim_level`,
`delivery_certainty`, and `signals`.

## Standards boundary

DMARQ continues to parse legacy RFC 7489 aggregate reports while using the
separated terminology of RFC 9989 (DMARC), RFC 9990 (aggregate reporting), and
RFC 9991 (failure reporting). Legacy `pct` and `ri` values may be retained as
historic report metadata, but they are not treated as controls for DMARQ's
notification volume or as proof that a report should have arrived. A missing
report is evaluated from persisted intake and coverage evidence instead.
