# External membership provenance

External role synchronization marks only memberships created or updated by a
verified IdP claim. Authoritative snapshots deactivate those external rows when
a role is removed or when all role claims are omitted. Manual administrator
grants remain active through both cases; the membership API resets provenance to
manual on every explicit create or update.

The provenance migration deactivates ambiguous legacy memberships only for
`oidc:` and `authentik:` user identities, classifying those rows as inactive
external-managed records. Logto and SCIM identities are left untouched. A later
verified role claim reactivates and updates a legacy row, while an omitted role
claim keeps it inactive. Administrators can regrant access through the normal
membership API, which converts the row to manual provenance.

DNS posture refreshes cap attacker-controlled DKIM selector fanout at 100
selectors per domain; persisted report and extension data have independent
bounds before hydration.
