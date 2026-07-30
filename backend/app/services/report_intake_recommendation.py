"""Deterministic, secret-free report-intake recommendations for guided setup."""

# The localized catalog intentionally keeps complete operator-facing sentences
# beside their stable option IDs. Splitting those strings harms translation
# review more than it improves source readability.
# pylint: disable=line-too-long,too-many-instance-attributes,too-many-locals

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, Optional
from urllib.parse import urlparse

OPTION_ORDER = (
    "manual_upload",
    "local_imap",
    "proton_bridge",
    "gmail",
    "m365",
    "cloudflare_worker",
    "aws_gateway",
    "webhook",
)

METHOD_OPTIONS = {
    "IMAP": "local_imap",
    "GMAIL_API": "gmail",
    "M365_GRAPH": "m365",
}


@dataclass(frozen=True)
class ReportIntakeEvidence:
    """Bounded persisted state used to rank intake options."""

    source_methods: tuple[str, ...] = ()
    source_labels: tuple[str, ...] = ()
    enabled_source_count: int = 0
    checked_source_count: int = 0
    total_report_count: int = 0
    latest_report_id: Optional[int] = None
    domain_name: Optional[str] = None
    report_destination_configured: bool = False
    dmarc_reporting_configured: bool = False
    latest_import_status: Optional[str] = None
    latest_import_reports_found: int = 0
    latest_import_duplicates: int = 0
    latest_import_errors: int = 0
    public_base_url: Optional[str] = None
    webhook_configured: bool = False

    @property
    def public_https(self) -> bool:
        parsed = urlparse(str(self.public_base_url or ""))
        return parsed.scheme == "https" and bool(parsed.netloc)


def _copy(locale: str) -> Dict[str, Any]:
    """Return localized option copy without mixing presentation into ranking."""
    if locale == "de":
        return {
            "manual_upload": {
                "title": "Vorhandenen Report hochladen",
                "summary": "Der schnellste Weg zu einer ersten Auswertung ohne dauerhafte Verbindung.",
                "flow": ["Report-Datei", "DMARQ Upload", "Lokale Auswertung"],
                "processors": ["Du", "Deine DMARQ-Instanz"],
                "public_exposure": "Keine öffentliche DMARQ-URL erforderlich.",
                "credentials": "Keine Zugangsdaten erforderlich.",
                "complexity": "low",
                "dependencies": ["Du musst eine XML-, ZIP- oder GZIP-Reportdatei beschaffen."],
                "failure_modes": [
                    "Keine automatische Überwachung; neue Reports müssen erneut hochgeladen werden."
                ],
                "test_method": "Eine Reportdatei hochladen und die bestätigte Importmeldung öffnen.",
                "next_step": "Lade einen vorhandenen DMARC-Aggregatreport hoch.",
                "action_label": "Report hochladen",
                "href": "/upload",
                "tradeoff": "Sehr einfach, aber nicht für dauerhafte unbeaufsichtigte Überwachung geeignet.",
            },
            "local_imap": {
                "title": "Eigene Report-Mailbox per IMAP",
                "summary": "DMARQ liest eine abgegrenzte Mailbox in deiner kontrollierten Umgebung.",
                "flow": ["Report-Absender", "Deine Mailbox", "IMAP", "DMARQ"],
                "processors": ["Dein Mailanbieter oder Mailserver", "Deine DMARQ-Instanz"],
                "public_exposure": "Keine öffentliche DMARQ-URL erforderlich.",
                "credentials": "Mailbox-Benutzer und Passwort; nur die Report-Mailbox freigeben.",
                "complexity": "medium",
                "dependencies": ["Erreichbarer IMAP-Server", "Dauerhaft verfügbare Report-Mailbox"],
                "failure_modes": ["Anmeldung, TLS-Modus oder Mailbox-Pfad können ausfallen."],
                "test_method": "Verbindung testen, einen Poll auslösen und den Importstatus prüfen.",
                "next_step": "Verbinde eine dedizierte IMAP-Report-Mailbox.",
                "action_label": "IMAP verbinden",
                "href": "/mail-sources?method=IMAP",
                "tradeoff": "Mehr Kontrolle, dafür betreibst du Mailbox, Zugang und Erreichbarkeit selbst.",
            },
            "proton_bridge": {
                "title": "Proton Mail über lokale Bridge",
                "summary": "Eine Proton-Mailbox wird über Proton Mail Bridge lokal für DMARQ erreichbar.",
                "flow": ["Report-Absender", "Proton Mail", "Lokale Bridge", "DMARQ"],
                "processors": ["Proton", "Proton Mail Bridge", "Deine DMARQ-Instanz"],
                "public_exposure": "Keine öffentliche DMARQ-URL erforderlich.",
                "credentials": "Von Bridge erzeugte lokale IMAP-Zugangsdaten; nicht das Proton-Passwort.",
                "complexity": "medium",
                "dependencies": ["Proton Mail Bridge muss nahe DMARQ dauerhaft laufen."],
                "failure_modes": [
                    "Eine gestoppte oder neu gekoppelte Bridge unterbricht den Intake."
                ],
                "test_method": "Bridge-IMAP testen und danach einen DMARQ-Poll auslösen.",
                "next_step": "Starte Bridge und verbinde deren lokalen IMAP-Endpunkt.",
                "action_label": "Bridge-IMAP verbinden",
                "href": "/mail-sources?method=IMAP&bridge=proton",
                "tradeoff": "Privacy-orientiert, aber Bridge ist eine zusätzliche Betriebsabhängigkeit.",
            },
            "gmail": {
                "title": "Gmail per OAuth verbinden",
                "summary": "Gmail liefert Report-Anhänge mit widerrufbarem, delegiertem Mailbox-Zugriff.",
                "flow": ["Report-Absender", "Gmail", "OAuth", "DMARQ"],
                "processors": ["Google", "Deine DMARQ-Instanz"],
                "public_exposure": "Für OAuth ist eine korrekte Callback-URL nötig; produktiv HTTPS verwenden.",
                "credentials": "OAuth-Client und delegierte Gmail-Berechtigung; keine Passwörter im Formular.",
                "complexity": "low",
                "dependencies": ["Google OAuth-Client", "Autorisierter Gmail-Account"],
                "failure_modes": [
                    "Widerrufene Tokens oder geänderte OAuth-Callbacks erfordern Neuverbindung."
                ],
                "test_method": "OAuth abschließen, Verbindung testen und einen Backfill starten.",
                "next_step": "Lege eine Gmail-Quelle an und autorisiere die Report-Mailbox.",
                "action_label": "Gmail verbinden",
                "href": "/mail-sources?method=GMAIL_API",
                "tradeoff": "Wenig Betriebsaufwand, Reportdaten werden jedoch von Google verarbeitet.",
            },
            "m365": {
                "title": "Microsoft 365 Graph verbinden",
                "summary": "Delegierter oder anwendungsbasierter Graph-Zugriff liest eine festgelegte Report-Mailbox.",
                "flow": ["Report-Absender", "Exchange Online", "Microsoft Graph", "DMARQ"],
                "processors": ["Microsoft", "Deine DMARQ-Instanz"],
                "public_exposure": "Delegiertes OAuth benötigt einen HTTPS-Callback; Application Access läuft unbeaufsichtigt.",
                "credentials": "Tenant-ID, Application-ID und je nach Modus Consent, Token oder Client Secret.",
                "complexity": "medium",
                "dependencies": [
                    "Entra-Anwendung",
                    "Exchange-Online-Mailbox und begrenzte Mail.Read-Rechte",
                ],
                "failure_modes": [
                    "Abgelaufene Secrets, fehlender Consent oder zu breite/falsche Mailbox-Scope."
                ],
                "test_method": "Zielmailbox prüfen, Graph-Verbindung testen und einen Backfill starten.",
                "next_step": "Lege eine Microsoft-365-Quelle mit klarer Zielmailbox an.",
                "action_label": "Microsoft 365 verbinden",
                "href": "/mail-sources?method=M365_GRAPH",
                "tradeoff": "Guter unbeaufsichtigter Betrieb, aber Entra- und Exchange-Berechtigungen brauchen Sorgfalt.",
            },
            "cloudflare_worker": {
                "title": "Cloudflare Email Routing und Worker",
                "summary": "Cloudflare nimmt Report-Mail an und leitet die rohe E-Mail authentifiziert an DMARQ weiter.",
                "flow": [
                    "Report-Absender",
                    "Cloudflare Email Routing",
                    "Email Worker",
                    "DMARQ HTTPS-Webhook",
                ],
                "processors": ["Cloudflare", "Deine DMARQ-Instanz"],
                "public_exposure": "Eine öffentliche HTTPS-DMARQ-URL ist erforderlich.",
                "credentials": "Separates Inbound-Webhook-Secret; keine DNS-Schreibrechte für den Worker.",
                "complexity": "medium",
                "dependencies": [
                    "Cloudflare Email Routing",
                    "Worker",
                    "Erreichbarer authentifizierter DMARQ-Webhook",
                ],
                "failure_modes": [
                    "Routing-, Worker-, Secret- oder Payload-Limits können die Weiterleitung stoppen."
                ],
                "test_method": "Test-E-Mail durch Routing und Worker senden und Webhook-Antwort prüfen.",
                "next_step": "Prüfe HTTPS und Webhook-Secret, dann folge dem Worker-How-to.",
                "action_label": "Worker-How-to öffnen",
                "href": "https://github.com/christianlouis/dmarq/blob/main/docs/cloudflare-email-worker-inbound-webhook.md",
                "tradeoff": "Kein Mailbox-Polling, aber öffentliche HTTPS-Erreichbarkeit und Cloudflare-Betrieb sind nötig.",
            },
            "aws_gateway": {
                "title": "AWS SES Receipt und Lambda",
                "summary": "SES nimmt Report-Mail an und eine Lambda-Funktion sendet RFC-822-Daten an DMARQ.",
                "flow": ["Report-Absender", "Amazon SES", "Lambda", "DMARQ HTTPS-Webhook"],
                "processors": ["AWS", "Deine DMARQ-Instanz"],
                "public_exposure": "Eine öffentliche HTTPS-DMARQ-URL ist erforderlich.",
                "credentials": "AWS-Rollen für Receipt/Lambda und ein separates DMARQ-Webhook-Secret.",
                "complexity": "high",
                "dependencies": [
                    "Verifizierte SES-Region/Domain",
                    "Receipt Rule",
                    "Lambda",
                    "Öffentlicher Webhook",
                ],
                "failure_modes": [
                    "Region, IAM, Lambda-Retry, Payload-Größe oder Webhook-Erreichbarkeit."
                ],
                "test_method": "Eine SES-Testnachricht zustellen und Lambda- sowie DMARQ-Ergebnis prüfen.",
                "next_step": "Prüfe den öffentlichen Webhook und plane die SES Receipt Rule.",
                "action_label": "Gateway-Option prüfen",
                "href": "https://github.com/christianlouis/dmarq/blob/main/docs/reference/report-intake-options.md#aws-ses-receipt-and-lambda",
                "tradeoff": "Skalierbar und automatisierbar, aber deutlich komplexer als Mailbox-Intake.",
            },
            "webhook": {
                "title": "Generischer authentifizierter E-Mail-Webhook",
                "summary": "Ein vorhandenes Gateway sendet die vollständige RFC-822-Nachricht an DMARQ.",
                "flow": [
                    "Report-Absender",
                    "Dein Mail-Gateway",
                    "Authentifizierter HTTPS-Webhook",
                    "DMARQ",
                ],
                "processors": ["Dein gewähltes Gateway", "Deine DMARQ-Instanz"],
                "public_exposure": "Eine vom Gateway erreichbare HTTPS-DMARQ-URL ist erforderlich.",
                "credentials": "Separates X-Webhook-Secret nur für den Inbound-Endpunkt.",
                "complexity": "high",
                "dependencies": [
                    "Gateway mit RFC-822-Weiterleitung",
                    "Retry-Handling",
                    "Öffentlicher Webhook",
                ],
                "failure_modes": [
                    "Falsches Format, Secret, Payload-Limit oder fehlende Gateway-Retries."
                ],
                "test_method": "Eine gespeicherte RFC-822-Nachricht senden und Importantwort prüfen.",
                "next_step": "Verbinde dein Gateway mit dem Raw-E-Mail-Endpunkt.",
                "action_label": "Webhook-Vertrag öffnen",
                "href": "https://github.com/christianlouis/dmarq/blob/main/docs/reference/report-intake-options.md#generic-authenticated-raw-email-webhook",
                "tradeoff": "Flexibel, aber Transformation, Retry und Zustellnachweis liegen bei dir.",
            },
        }
    return {
        "manual_upload": {
            "title": "Upload an existing report",
            "summary": "The quickest route to a first interpretation without a persistent connection.",
            "flow": ["Report file", "DMARQ upload", "Local interpretation"],
            "processors": ["You", "Your DMARQ instance"],
            "public_exposure": "No public DMARQ URL is required.",
            "credentials": "No credentials required.",
            "complexity": "low",
            "dependencies": ["You need an XML, ZIP, or GZIP aggregate report file."],
            "failure_modes": ["No continuous monitoring; later reports must be uploaded again."],
            "test_method": "Upload one report file and open the confirmed import result.",
            "next_step": "Upload an existing DMARC aggregate report.",
            "action_label": "Upload report",
            "href": "/upload",
            "tradeoff": "Very simple, but unsuitable for durable unattended monitoring.",
        },
        "local_imap": {
            "title": "Your own report mailbox over IMAP",
            "summary": "DMARQ reads a dedicated mailbox in an environment you control.",
            "flow": ["Report sender", "Your mailbox", "IMAP", "DMARQ"],
            "processors": ["Your mail provider or server", "Your DMARQ instance"],
            "public_exposure": "No public DMARQ URL is required.",
            "credentials": "Mailbox user and password; scope access to the report mailbox.",
            "complexity": "medium",
            "dependencies": ["Reachable IMAP server", "Continuously available report mailbox"],
            "failure_modes": ["Authentication, TLS mode, or mailbox path can break intake."],
            "test_method": "Test the connection, trigger one poll, and inspect import status.",
            "next_step": "Connect a dedicated IMAP report mailbox.",
            "action_label": "Connect IMAP",
            "href": "/mail-sources?method=IMAP",
            "tradeoff": "More control, with responsibility for mailbox, credentials, and reachability.",
        },
        "proton_bridge": {
            "title": "Proton Mail through a local Bridge",
            "summary": "A Proton mailbox becomes locally available to DMARQ through Proton Mail Bridge.",
            "flow": ["Report sender", "Proton Mail", "Local Bridge", "DMARQ"],
            "processors": ["Proton", "Proton Mail Bridge", "Your DMARQ instance"],
            "public_exposure": "No public DMARQ URL is required.",
            "credentials": "Bridge-generated local IMAP credentials, not the Proton password.",
            "complexity": "medium",
            "dependencies": ["Proton Mail Bridge must run continuously near DMARQ."],
            "failure_modes": ["A stopped or re-paired Bridge interrupts intake."],
            "test_method": "Test Bridge IMAP, then trigger a DMARQ poll.",
            "next_step": "Start Bridge and connect its local IMAP endpoint.",
            "action_label": "Connect Bridge IMAP",
            "href": "/mail-sources?method=IMAP&bridge=proton",
            "tradeoff": "Privacy-oriented, with Bridge as an additional operational dependency.",
        },
        "gmail": {
            "title": "Connect Gmail with OAuth",
            "summary": "Gmail supplies report attachments through revocable delegated mailbox access.",
            "flow": ["Report sender", "Gmail", "OAuth", "DMARQ"],
            "processors": ["Google", "Your DMARQ instance"],
            "public_exposure": "OAuth needs a correct callback URL; use HTTPS in production.",
            "credentials": "OAuth client and delegated Gmail scope; no mailbox password in DMARQ.",
            "complexity": "low",
            "dependencies": ["Google OAuth client", "Authorized Gmail account"],
            "failure_modes": ["Revoked tokens or callback changes require reconnection."],
            "test_method": "Complete OAuth, test the connection, and start a backfill.",
            "next_step": "Create a Gmail source and authorize the report mailbox.",
            "action_label": "Connect Gmail",
            "href": "/mail-sources?method=GMAIL_API",
            "tradeoff": "Low operational effort, but Google processes the report data path.",
        },
        "m365": {
            "title": "Connect Microsoft 365 Graph",
            "summary": "Delegated or application Graph access reads one explicit report mailbox.",
            "flow": ["Report sender", "Exchange Online", "Microsoft Graph", "DMARQ"],
            "processors": ["Microsoft", "Your DMARQ instance"],
            "public_exposure": "Delegated OAuth needs an HTTPS callback; application access is unattended.",
            "credentials": "Tenant ID, application ID, and consent, tokens, or client secret for the selected mode.",
            "complexity": "medium",
            "dependencies": [
                "Entra application",
                "Exchange Online mailbox and bounded Mail.Read access",
            ],
            "failure_modes": ["Expired secrets, missing consent, or an incorrect mailbox scope."],
            "test_method": "Verify the target mailbox, test Graph, and start a backfill.",
            "next_step": "Create a Microsoft 365 source with an explicit target mailbox.",
            "action_label": "Connect Microsoft 365",
            "href": "/mail-sources?method=M365_GRAPH",
            "tradeoff": "Good unattended operation, with careful Entra and Exchange permission setup.",
        },
        "cloudflare_worker": {
            "title": "Cloudflare Email Routing and Worker",
            "summary": "Cloudflare receives report mail and forwards the raw email to authenticated DMARQ intake.",
            "flow": [
                "Report sender",
                "Cloudflare Email Routing",
                "Email Worker",
                "DMARQ HTTPS webhook",
            ],
            "processors": ["Cloudflare", "Your DMARQ instance"],
            "public_exposure": "A public HTTPS DMARQ URL is required.",
            "credentials": "A separate inbound webhook secret; the Worker receives no DNS write access.",
            "complexity": "medium",
            "dependencies": [
                "Cloudflare Email Routing",
                "Worker",
                "Reachable authenticated DMARQ webhook",
            ],
            "failure_modes": ["Routing, Worker, secret, or payload limits can stop forwarding."],
            "test_method": "Send a test email through Routing and Worker, then inspect the webhook response.",
            "next_step": "Verify HTTPS and the webhook secret, then follow the Worker guide.",
            "action_label": "Open Worker guide",
            "href": "https://github.com/christianlouis/dmarq/blob/main/docs/cloudflare-email-worker-inbound-webhook.md",
            "tradeoff": "No mailbox polling, but public HTTPS and Cloudflare operations are required.",
        },
        "aws_gateway": {
            "title": "AWS SES receipt and Lambda",
            "summary": "SES receives report mail and Lambda forwards RFC 822 data to DMARQ.",
            "flow": ["Report sender", "Amazon SES", "Lambda", "DMARQ HTTPS webhook"],
            "processors": ["AWS", "Your DMARQ instance"],
            "public_exposure": "A public HTTPS DMARQ URL is required.",
            "credentials": "AWS roles for receipt/Lambda and a separate DMARQ webhook secret.",
            "complexity": "high",
            "dependencies": [
                "Verified SES region/domain",
                "Receipt rule",
                "Lambda",
                "Public webhook",
            ],
            "failure_modes": ["Region, IAM, Lambda retry, payload size, or webhook reachability."],
            "test_method": "Deliver an SES test message and inspect both Lambda and DMARQ outcomes.",
            "next_step": "Verify public webhook readiness, then plan the SES receipt rule.",
            "action_label": "Review gateway option",
            "href": "https://github.com/christianlouis/dmarq/blob/main/docs/reference/report-intake-options.md#aws-ses-receipt-and-lambda",
            "tradeoff": "Scalable and automatable, but much more complex than mailbox intake.",
        },
        "webhook": {
            "title": "Generic authenticated raw-email webhook",
            "summary": "An existing gateway sends the complete RFC 822 message to DMARQ.",
            "flow": ["Report sender", "Your mail gateway", "Authenticated HTTPS webhook", "DMARQ"],
            "processors": ["Your chosen gateway", "Your DMARQ instance"],
            "public_exposure": "A DMARQ HTTPS URL reachable by the gateway is required.",
            "credentials": "A separate X-Webhook-Secret for inbound email only.",
            "complexity": "high",
            "dependencies": ["RFC 822-capable gateway", "Retry handling", "Public webhook"],
            "failure_modes": ["Wrong format, secret, payload limit, or missing gateway retries."],
            "test_method": "Send a stored RFC 822 message and inspect the import response.",
            "next_step": "Connect your gateway to the raw-email endpoint.",
            "action_label": "Open webhook contract",
            "href": "https://github.com/christianlouis/dmarq/blob/main/docs/reference/report-intake-options.md#generic-authenticated-raw-email-webhook",
            "tradeoff": "Flexible, with transformation, retries, and delivery evidence owned by you.",
        },
    }


def _option_modes(option_id: str, locale: str) -> list[Dict[str, str]]:
    """Keep security-relevant variants structured rather than buried in copy."""
    modes = {
        "en": {
            "local_imap": [
                {
                    "id": "implicit_tls",
                    "label": "Implicit TLS",
                    "boundary": "TLS from connection start, normally port 993.",
                },
                {
                    "id": "starttls",
                    "label": "STARTTLS",
                    "boundary": "Upgrade an IMAP connection to TLS, normally port 143.",
                },
                {
                    "id": "trusted_plain",
                    "label": "Trusted local plain IMAP",
                    "boundary": "Only for an isolated local Bridge path; never across an untrusted network.",
                },
            ],
            "proton_bridge": [
                {
                    "id": "bridge_imap",
                    "label": "Bridge IMAP",
                    "boundary": "Bridge-generated local credentials on a trusted path near DMARQ.",
                },
            ],
            "m365": [
                {
                    "id": "delegated",
                    "label": "Delegated access",
                    "boundary": "Interactive user consent and an HTTPS OAuth callback.",
                },
                {
                    "id": "application",
                    "label": "Application access",
                    "boundary": "Unattended Entra credential with Mail.Read restricted to the report mailbox.",
                },
            ],
        },
        "de": {
            "local_imap": [
                {
                    "id": "implicit_tls",
                    "label": "Implizites TLS",
                    "boundary": "TLS ab Verbindungsbeginn, üblicherweise Port 993.",
                },
                {
                    "id": "starttls",
                    "label": "STARTTLS",
                    "boundary": "Eine IMAP-Verbindung auf TLS anheben, üblicherweise Port 143.",
                },
                {
                    "id": "trusted_plain",
                    "label": "Vertrauenswürdiges lokales Klartext-IMAP",
                    "boundary": "Nur für einen isolierten lokalen Bridge-Pfad; nie über ein nicht vertrauenswürdiges Netz.",
                },
            ],
            "proton_bridge": [
                {
                    "id": "bridge_imap",
                    "label": "Bridge-IMAP",
                    "boundary": "Lokale Bridge-Zugangsdaten auf einem vertrauenswürdigen Pfad nahe DMARQ.",
                },
            ],
            "m365": [
                {
                    "id": "delegated",
                    "label": "Delegierter Zugriff",
                    "boundary": "Interaktive Zustimmung und ein HTTPS-OAuth-Callback.",
                },
                {
                    "id": "application",
                    "label": "Anwendungszugriff",
                    "boundary": "Unbeaufsichtigtes Entra-Credential mit Mail.Read nur für die Report-Mailbox.",
                },
            ],
        },
    }
    return modes[locale].get(option_id, [])


def _existing_options(evidence: ReportIntakeEvidence) -> set[str]:
    options = {
        METHOD_OPTIONS[method] for method in evidence.source_methods if method in METHOD_OPTIONS
    }
    labels = " ".join(evidence.source_labels).lower()
    if "proton" in labels and "local_imap" in options:
        options.discard("local_imap")
        options.add("proton_bridge")
    return options


def _known_provider_bonus(option_id: str, providers: Iterable[object]) -> int:
    text = " ".join(str(value or "").lower() for value in providers)
    matches = {
        "gmail": ("gmail", "google"),
        "m365": ("microsoft", "m365", "office 365", "exchange online", "outlook"),
        "proton_bridge": ("proton",),
        "cloudflare_worker": ("cloudflare",),
        "aws_gateway": ("amazon ses", "aws ses"),
    }
    return 140 if any(term in text for term in matches.get(option_id, ())) else 0


def _availability(
    option_id: str,
    evidence: ReportIntakeEvidence,
    profile: Dict[str, Any],
    locale: str,
) -> tuple[bool, str]:
    if option_id == "proton_bridge":
        bridge_available = bool((profile.get("mail_context") or {}).get("local_bridge_available"))
        message = (
            "Confirm that Proton Mail Bridge can run continuously near DMARQ."
            if locale == "en"
            else "Bestätige, dass Proton Mail Bridge dauerhaft nahe DMARQ laufen kann."
        )
        return bridge_available, "" if bridge_available else message
    if option_id in {"cloudflare_worker", "aws_gateway", "webhook"}:
        if not evidence.public_https:
            message = (
                "Configure a public HTTPS base URL before choosing this path."
                if locale == "en"
                else "Richte zuerst eine öffentliche HTTPS-Basis-URL ein."
            )
            return False, message
        if not evidence.webhook_configured:
            message = (
                "HTTPS is ready; configure a separate inbound webhook secret next."
                if locale == "en"
                else "HTTPS ist bereit; als Nächstes fehlt ein separates Inbound-Webhook-Secret."
            )
            return True, message
    return True, ""


def _score_option(
    option_id: str,
    *,
    profile: Dict[str, Any],
    evidence: ReportIntakeEvidence,
    existing: set[str],
) -> int:
    context = profile.get("mail_context") or {}
    preference = context.get("report_intake_preference")
    sovereignty = profile.get("sovereignty_preference") or "not_sure"
    effort = context.get("setup_effort") or "balanced"
    continuous = bool(context.get("continuous_monitoring")) or "continuous_monitoring" in (
        profile.get("installation_goals") or []
    )
    score = 50
    if option_id == preference:
        score += 500
    if option_id in existing:
        score += 400
    score += _known_provider_bonus(option_id, context.get("known_mail_providers") or [])
    if (
        str(context.get("dns_provider") or "").lower() == "cloudflare"
        and option_id == "cloudflare_worker"
    ):
        score += 70
    if continuous:
        score += 35 if option_id != "manual_upload" else -140
    elif option_id == "manual_upload":
        score += 80
    if effort == "simplest":
        score += {"manual_upload": 100, "gmail": 85, "m365": 70, "cloudflare_worker": 45}.get(
            option_id, -20
        )
    elif effort == "maximum_control":
        score += {"local_imap": 130, "proton_bridge": 100, "webhook": 55, "manual_upload": 25}.get(
            option_id, -25
        )
    else:
        score += {"local_imap": 45, "gmail": 55, "m365": 45, "cloudflare_worker": 35}.get(
            option_id, 0
        )
    sovereignty_scores = {
        "keep_data_local": {
            "local_imap": 150,
            "proton_bridge": 105,
            "manual_upload": 55,
            "webhook": 35,
            "gmail": -80,
            "m365": -80,
            "cloudflare_worker": -40,
            "aws_gateway": -50,
        },
        "privacy_first": {
            "local_imap": 125,
            "proton_bridge": 165,
            "manual_upload": 50,
            "webhook": 30,
            "gmail": -30,
            "m365": -30,
        },
        "balanced": {"local_imap": 35, "gmail": 40, "m365": 35, "cloudflare_worker": 30},
        "convenience_first": {
            "gmail": 115,
            "m365": 100,
            "cloudflare_worker": 75,
            "manual_upload": 65,
            "local_imap": -20,
            "proton_bridge": -35,
        },
    }
    score += sovereignty_scores.get(sovereignty, {}).get(option_id, 0)
    if (
        evidence.public_https
        and evidence.webhook_configured
        and option_id in {"cloudflare_worker", "aws_gateway", "webhook"}
    ):
        score += 50
    return score


def _intake_status(evidence: ReportIntakeEvidence, locale: str) -> Dict[str, Any]:
    if evidence.total_report_count > 0:
        state = "working"
        headline = (
            "Report intake is working" if locale == "en" else "Der Report-Eingang funktioniert"
        )
        detail = (
            f"DMARQ has stored {evidence.total_report_count} aggregate report(s)."
            if locale == "en"
            else f"DMARQ hat {evidence.total_report_count} Aggregatreport(s) gespeichert."
        )
    elif evidence.latest_import_duplicates > 0 and evidence.latest_import_reports_found == 0:
        state = "duplicate"
        headline = (
            "Intake works; the report was already known"
            if locale == "en"
            else "Intake funktioniert; der Report war bereits bekannt"
        )
        detail = (
            f"The latest run confirmed {evidence.latest_import_duplicates} duplicate report(s) without inflating totals."
            if locale == "en"
            else f"Der letzte Lauf bestätigte {evidence.latest_import_duplicates} Duplikat(e), ohne Summen zu erhöhen."
        )
    elif evidence.latest_import_errors > 0 and evidence.latest_import_reports_found == 0:
        state = "rejected"
        headline = (
            "Intake reached DMARQ, but content was rejected"
            if locale == "en"
            else "Der Intake erreicht DMARQ, aber Inhalte wurden abgelehnt"
        )
        detail = (
            f"The latest run recorded {evidence.latest_import_errors} parse or attachment error(s). Review import history."
            if locale == "en"
            else f"Der letzte Lauf enthält {evidence.latest_import_errors} Parsing- oder Anhangfehler. Prüfe den Importverlauf."
        )
    elif evidence.enabled_source_count > 0:
        state = "waiting"
        headline = (
            "Waiting for the first aggregate report"
            if locale == "en"
            else "Warten auf den ersten Aggregatreport"
        )
        detail = (
            "The intake path is configured. Low-volume domains may legitimately wait until a participating receiver observes mail."
            if locale == "en"
            else "Der Intake-Weg ist eingerichtet. Bei wenig Versand kann es dauern, bis ein teilnehmender Empfänger Mail beobachtet."
        )
    else:
        state = "setup_required"
        headline = (
            "Choose a report-intake path"
            if locale == "en"
            else "Wähle einen Weg für den Report-Eingang"
        )
        detail = (
            "No continuous report source is enabled yet."
            if locale == "en"
            else "Noch ist keine dauerhafte Report-Quelle aktiviert."
        )
    return {
        "state": state,
        "headline": headline,
        "description": detail,
        "report_count": evidence.total_report_count,
        "latest_import": {
            "status": evidence.latest_import_status,
            "accepted": evidence.latest_import_reports_found,
            "duplicates": evidence.latest_import_duplicates,
            "rejected": evidence.latest_import_errors,
        },
    }


def _journey_link(evidence: ReportIntakeEvidence, fragment: str = "") -> str:
    if not evidence.domain_name:
        return "/domains"
    suffix = f"#{fragment}" if fragment else ""
    return f"/domains/{evidence.domain_name}{suffix}"


def _first_report_journey(
    evidence: ReportIntakeEvidence,
    *,
    locale: str,
) -> list[Dict[str, Any]]:
    """Expose the complete, resumable path without running setup work."""
    has_intake_result = bool(
        evidence.total_report_count
        or evidence.latest_import_duplicates
        or evidence.latest_import_errors
    )
    source_ready = bool(evidence.enabled_source_count or evidence.total_report_count)
    component_checked = bool(evidence.checked_source_count or evidence.total_report_count)
    report_href = (
        f"/reports/{evidence.latest_report_id}" if evidence.latest_report_id else "/reports"
    )
    if locale == "de":
        copy = (
            (
                "Report-Ziel festlegen",
                "Lege eine abgegrenzte Zieladresse für DMARC-Aggregatreports fest.",
                evidence.report_destination_configured,
                _journey_link(evidence, "dns-records"),
            ),
            (
                "Reporting-DNS vorbereiten",
                "Erzeuge den exakten DMARC-Plan mit rua=mailto: für diese Zieladresse.",
                evidence.dmarc_reporting_configured,
                _journey_link(evidence, "dns-records"),
            ),
            (
                "DNS-Änderung prüfen",
                "Vergleiche vorher und nachher; kopiere oder genehmige genau diese Änderung.",
                evidence.dmarc_reporting_configured,
                _journey_link(evidence, "dns-records"),
            ),
            (
                "Externe Autorisierung bestätigen",
                "Falls Reports an eine andere Domain gehen, prüfe deren DMARC-Autorisierung.",
                bool(evidence.dmarc_reporting_configured and has_intake_result),
                _journey_link(evidence, "dns-records"),
            ),
            (
                "Intake-Verbindung testen",
                "Teste Mailbox, OAuth, Bridge oder Webhook unabhängig vom Reportversand.",
                component_checked,
                "/mail-sources",
            ),
            (
                "Auf Empfänger-Reports warten",
                "Echte Reports entstehen erst, wenn teilnehmende Empfänger Mail der Domain beobachten.",
                source_ready,
                "/mail-sources",
            ),
            (
                "Import-Ergebnis erkennen",
                "DMARQ unterscheidet akzeptierte, sichere Duplikate und abgelehnte Inhalte.",
                has_intake_result,
                "/mail-sources",
            ),
            (
                "Erste Interpretation öffnen",
                "Beende die Einrichtung mit der Erklärung, nicht mit einer rohen Importzeile.",
                bool(evidence.total_report_count),
                report_href,
            ),
        )
    else:
        copy = (
            (
                "Choose a report destination",
                "Choose a dedicated destination address for DMARC aggregate reports.",
                evidence.report_destination_configured,
                _journey_link(evidence, "dns-records"),
            ),
            (
                "Prepare reporting DNS",
                "Generate the exact DMARC plan with rua=mailto: for that destination.",
                evidence.dmarc_reporting_configured,
                _journey_link(evidence, "dns-records"),
            ),
            (
                "Review the DNS change",
                "Compare before and after, then copy or approve only that change.",
                evidence.dmarc_reporting_configured,
                _journey_link(evidence, "dns-records"),
            ),
            (
                "Confirm external authorization",
                "When reports cross domains, verify the destination's DMARC authorization.",
                bool(evidence.dmarc_reporting_configured and has_intake_result),
                _journey_link(evidence, "dns-records"),
            ),
            (
                "Test the intake connection",
                "Test the mailbox, OAuth, Bridge, or webhook independently of report delivery.",
                component_checked,
                "/mail-sources",
            ),
            (
                "Wait for receiver reports",
                "Real reports appear after participating receivers observe mail from the domain.",
                source_ready,
                "/mail-sources",
            ),
            (
                "Recognize the import outcome",
                "DMARQ distinguishes accepted reports, safe duplicates, and rejected content.",
                has_intake_result,
                "/mail-sources",
            ),
            (
                "Open the first interpretation",
                "Finish setup in the explanation, not on a raw import row.",
                bool(evidence.total_report_count),
                report_href,
            ),
        )
    return [
        {
            "id": f"journey_{index}",
            "position": index,
            "title": title,
            "description": description,
            "complete": bool(complete),
            "href": href,
        }
        for index, (title, description, complete, href) in enumerate(copy, start=1)
    ]


def _primary_action(
    recommended: Dict[str, Any],
    evidence: ReportIntakeEvidence,
    *,
    locale: str,
) -> Dict[str, str]:
    """Keep the visible CTA aligned with the next incomplete setup state."""
    if evidence.total_report_count:
        return {
            "label": (
                "Open latest interpretation" if locale == "en" else "Neueste Interpretation öffnen"
            ),
            "href": (
                f"/reports/{evidence.latest_report_id}" if evidence.latest_report_id else "/reports"
            ),
        }
    if evidence.latest_import_errors:
        return {
            "label": "Review rejected import" if locale == "en" else "Abgelehnten Import prüfen",
            "href": "/mail-sources",
        }
    if evidence.latest_import_duplicates:
        return {
            "label": "Open existing reports" if locale == "en" else "Vorhandene Reports öffnen",
            "href": "/reports",
        }
    if (
        evidence.enabled_source_count
        and evidence.domain_name
        and not evidence.dmarc_reporting_configured
    ):
        return {
            "label": "Prepare reporting DNS" if locale == "en" else "Reporting-DNS vorbereiten",
            "href": _journey_link(evidence, "dns-records"),
        }
    if evidence.enabled_source_count:
        return {
            "label": "Check intake status" if locale == "en" else "Intake-Status prüfen",
            "href": "/mail-sources",
        }
    return {"label": recommended["action_label"], "href": recommended["href"]}


def build_report_intake_recommendation(
    profile: Dict[str, Any],
    evidence: ReportIntakeEvidence,
    *,
    locale: str = "en",
) -> Dict[str, Any]:
    """Rank supported intake paths and return one transparent recommendation."""
    selected_locale = "de" if str(locale).lower().startswith("de") else "en"
    copy = _copy(selected_locale)
    existing = _existing_options(evidence)
    ranked = []
    for index, option_id in enumerate(OPTION_ORDER):
        available, availability_reason = _availability(
            option_id, evidence, profile, selected_locale
        )
        score = _score_option(option_id, profile=profile, evidence=evidence, existing=existing)
        if not available:
            score -= 1000
        option = {
            "id": option_id,
            **copy[option_id],
            "modes": _option_modes(option_id, selected_locale),
            "available": available,
            "availability_reason": availability_reason,
            "already_configured": option_id in existing,
        }
        ranked.append((score, -index, option))
    ranked.sort(key=lambda item: (item[0], item[1]), reverse=True)
    recommended = ranked[0][2]
    context = profile.get("mail_context") or {}
    explicit = context.get("report_intake_preference") == recommended["id"]
    confidence = "high" if explicit or recommended["already_configured"] else "medium"
    reason = (
        "This is the path you selected; DMARQ still shows its boundaries and alternatives."
        if selected_locale == "en" and explicit
        else (
            "Du hast diesen Weg gewählt; DMARQ zeigt weiterhin Grenzen und Alternativen."
            if explicit
            else (
                "It best matches your data-path preference, setup effort, provider context, and detected state."
                if selected_locale == "en"
                else "Dieser Weg passt am besten zu Datenpfad, Einrichtungsaufwand, Provider-Kontext und erkanntem Zustand."
            )
        )
    )
    recommended = {**recommended, "confidence": confidence, "reason": reason}
    primary_action = _primary_action(recommended, evidence, locale=selected_locale)
    verification = [
        {
            "id": "component_test",
            "label": recommended["test_method"],
            "complete": bool(evidence.checked_source_count or evidence.total_report_count),
        },
        {
            "id": "first_report",
            "label": (
                "DMARQ accepts or safely deduplicates the first aggregate report."
                if selected_locale == "en"
                else "DMARQ akzeptiert oder dedupliziert den ersten Aggregatreport sicher."
            ),
            "complete": bool(evidence.total_report_count or evidence.latest_import_duplicates),
        },
        {
            "id": "interpretation",
            "label": (
                "Open the first interpretation instead of stopping at raw import data."
                if selected_locale == "en"
                else "Öffne die erste Interpretation statt bei rohen Importdaten stehenzubleiben."
            ),
            "complete": bool(evidence.total_report_count),
        },
    ]
    return {
        "schema": "dmarq.report_intake_recommendation.v1",
        "generated_from": "persisted_state_and_operator_preferences",
        "recommended": recommended,
        "primary_action": primary_action,
        "alternatives": [item[2] for item in ranked[1:]],
        "first_report": _intake_status(evidence, selected_locale),
        "verification": verification,
        "journey": _first_report_journey(evidence, locale=selected_locale),
        "preferences": {
            "selected_option": context.get("report_intake_preference") or "not_sure",
            "setup_effort": context.get("setup_effort") or "balanced",
            "continuous_monitoring": bool(context.get("continuous_monitoring"))
            or "continuous_monitoring" in (profile.get("installation_goals") or []),
            "local_bridge_available": bool(context.get("local_bridge_available")),
        },
        "public_endpoint": {
            "https_ready": evidence.public_https,
            "webhook_configured": evidence.webhook_configured,
        },
    }
