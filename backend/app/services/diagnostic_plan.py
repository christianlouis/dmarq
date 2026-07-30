"""Deterministic, read-only next-step plans for problem-first onboarding."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, Optional, Sequence
from urllib.parse import quote

PLAN_VERSION = 1
PLAN_SCHEMA = "dmarq.diagnostic_plan.v1"


@dataclass(frozen=True)
class DiagnosticEvidence:
    """Small persisted read model used by the diagnostic planner."""

    domain_names: Sequence[str] = ()
    selected_domain: Optional[str] = None
    has_dmarc: bool = False
    has_spf: bool = False
    has_dkim: bool = False
    dkim_selector_count: int = 0
    dmarc_rua_count: int = 0
    dmarc_ruf_count: int = 0
    dmarc_policy: Optional[str] = None
    dns_evidence_available: bool = False
    report_count: int = 0
    forensic_report_count: int = 0
    tls_report_count: int = 0
    message_count: int = 0
    failed_message_count: int = 0
    enabled_source_count: int = 0
    checked_source_count: int = 0
    dns_provider_connected: bool = False
    latest_report_id: Optional[int] = None


_COPY = {
    "en": {
        "add_domain_title": "Add the domain you want DMARQ to help with",
        "add_domain_summary": "DMARQ needs a domain before it can inspect stored DNS, report, and sender evidence.",
        "add_domain_action": "Add a domain",
        "add_domain_why": "This creates the monitoring boundary only. It does not change DNS.",
        "add_domain_verify": "The domain appears in DMARQ and its persisted DNS check can run.",
        "handoff_title": "Prepare the DNS change for the domain owner",
        "handoff_summary": "You said you cannot change DNS for {domain}. DMARQ can still prepare the exact record and verification steps.",
        "handoff_action": "Open DNS checklist",
        "handoff_why": "The person or provider controlling DNS must publish the record.",
        "handoff_verify": "DMARQ's stored DNS evidence shows a valid DMARC record after the owner publishes it.",
        "publish_title": "Publish a monitoring-only DMARC record",
        "publish_summary": "No valid DMARC record is present in the stored evidence for {domain}. Start with monitoring before tightening policy.",
        "publish_action": "Review the exact DNS record",
        "publish_why": "A monitoring record asks receivers for aggregate evidence without rejecting mail.",
        "publish_verify": "A later stored DNS snapshot shows a valid DMARC record for {domain}.",
        "check_dns_title": "Confirm who controls DNS",
        "check_dns_summary": "DMARQ has not yet recorded whether you can publish the DMARC record for {domain}.",
        "check_dns_action": "Review domain DNS",
        "check_dns_why": "The next safe step depends on whether you or another operator controls the zone.",
        "check_dns_verify": "DNS control is recorded and the exact DMARC setup path is known.",
        "connect_title": "Connect the mailbox that receives DMARC reports",
        "connect_summary": "DMARC is present for {domain}, but DMARQ has no enabled report source and no aggregate reports yet.",
        "connect_action": "Choose report intake",
        "connect_why": "Reports are needed before DMARQ can distinguish intended senders from unrelated sources.",
        "connect_verify": "The source completes a check and DMARQ imports the first aggregate report.",
        "wait_title": "Verify that report intake is working",
        "wait_summary": "A report source is enabled, but no aggregate report for {domain} has been stored yet.",
        "wait_action": "Check report intake",
        "wait_why": "A quiet or low-volume domain may legitimately receive reports slowly; the source health separates waiting from a broken connection.",
        "wait_verify": "The source check succeeds and the first report appears, or DMARQ confirms that no report was available.",
        "bounce_title": "Check the bounce or sending-provider event",
        "bounce_summary": "DMARC aggregate data cannot prove why an individual message was rejected. Use the SMTP response or provider delivery event first.",
        "bounce_action": "Review observed senders",
        "bounce_why": "The exact SMTP status identifies the rejecting system and failure reason; DMARC only adds authentication context.",
        "bounce_verify": "The affected sender, recipient provider, timestamp, and SMTP status are identified.",
        "reports_title": "Open the newest report explanation",
        "reports_summary": "DMARQ has stored aggregate evidence for {domain}. Start with one report and its interpreted source records.",
        "reports_action": "Explain the newest report",
        "reports_why": "One bounded report is easier to understand than changing DNS from an aggregate score.",
        "reports_verify": "You can identify which sources are intended, which failed authentication, and whether any action is justified.",
        "failures_title": "Investigate intended senders that fail authentication",
        "failures_summary": "Stored reports contain {failed} messages that did not pass DMARC for {domain}.",
        "failures_action": "Review failing senders",
        "failures_why": "Fix a known legitimate sender before tightening policy; blocked unknown sources may need no action.",
        "failures_verify": "The intended sender passes aligned DKIM or SPF in a later report.",
        "spoofing_title": "Likely unauthorized use is being observed",
        "spoofing_summary": "This domain is marked as non-sending, while reports show unauthenticated traffic. No immediate sending fix is indicated.",
        "spoofing_action": "Review the evidence",
        "spoofing_why": "Confirm that no legitimate service owns the source before treating it as protected spoofing.",
        "spoofing_verify": "Known senders remain empty and receivers continue applying the intended DMARC policy.",
        "ready_title": "Monitoring is ready",
        "ready_summary": "DMARQ has a domain, DMARC evidence, and report intake for {domain}. No more setup action is currently required.",
        "ready_action": "Open domain overview",
        "ready_why": "The next useful work now comes from changes in stored sender or authentication evidence.",
        "ready_verify": "New reports continue arriving and no intended sender develops an authentication failure.",
        "known_domains": "{count} monitored domain(s) are stored.",
        "known_dmarc": "Stored DNS evidence contains a DMARC record for {domain}.",
        "known_no_dmarc": "Stored DNS evidence does not contain a DMARC record for {domain}.",
        "known_reports": "{count} aggregate report(s) with {messages} observed message(s) are stored for {domain}.",
        "known_dkim": "Stored DNS evidence contains {count} working DKIM selector(s).",
        "known_report_destinations": "The stored DMARC record contains {rua} aggregate and {ruf} failure-report destination(s).",
        "known_other_reports": "DMARQ has also stored {forensic} failure report(s) and {tls} TLS report(s).",
        "known_sources": "{count} enabled report source(s) are configured.",
        "unknown_dns": "No persisted DNS posture snapshot is available yet.",
        "unknown_sender": "DMARQ does not yet know whether this domain intentionally sends mail.",
        "unknown_control": "DMARQ does not yet know who controls DNS.",
        "inference_low_volume": "Few or no reports may be normal for a low-volume domain; this is not evidence of a broken mailbox by itself.",
        "later_first_report": "Confirm the first aggregate report",
        "later_classify": "Classify intended sending services",
        "later_notifications": "Choose when DMARQ should notify you",
        "later_evidence": "Keep full technical evidence available",
    },
    "de": {
        "add_domain_title": "Domain hinzufügen, bei der DMARQ helfen soll",
        "add_domain_summary": "DMARQ braucht eine Domain, bevor gespeicherte DNS-, Report- und Absenderdaten ausgewertet werden können.",
        "add_domain_action": "Domain hinzufügen",
        "add_domain_why": "Damit wird nur die Überwachung angelegt. DNS wird nicht verändert.",
        "add_domain_verify": "Die Domain erscheint in DMARQ und die persistierte DNS-Prüfung kann laufen.",
        "handoff_title": "DNS-Änderung für den Domain-Inhaber vorbereiten",
        "handoff_summary": "Du kannst DNS für {domain} nicht selbst ändern. DMARQ kann trotzdem den genauen Record und die Prüfschritte vorbereiten.",
        "handoff_action": "DNS-Checkliste öffnen",
        "handoff_why": "Der Inhaber oder Provider der DNS-Zone muss den Record veröffentlichen.",
        "handoff_verify": "Die gespeicherten DNS-Daten zeigen nach der Änderung einen gültigen DMARC-Record.",
        "publish_title": "DMARC zunächst nur zur Beobachtung einrichten",
        "publish_summary": "Für {domain} liegt in den gespeicherten Daten kein gültiger DMARC-Record vor. Beginne mit Monitoring, bevor eine Policy verschärft wird.",
        "publish_action": "Genauen DNS-Record prüfen",
        "publish_why": "Ein Monitoring-Record fordert aggregierte Berichte an, ohne E-Mails abzulehnen.",
        "publish_verify": "Ein späterer DNS-Snapshot zeigt einen gültigen DMARC-Record für {domain}.",
        "check_dns_title": "Klären, wer DNS verwaltet",
        "check_dns_summary": "DMARQ weiß noch nicht, ob du den DMARC-Record für {domain} selbst veröffentlichen kannst.",
        "check_dns_action": "Domain-DNS prüfen",
        "check_dns_why": "Der nächste sichere Schritt hängt davon ab, wer die DNS-Zone verwaltet.",
        "check_dns_verify": "Die DNS-Verantwortung ist erfasst und der konkrete Einrichtungsweg ist klar.",
        "connect_title": "Postfach für DMARC-Reports verbinden",
        "connect_summary": "DMARC ist für {domain} vorhanden, aber DMARQ hat noch keine aktive Report-Quelle und keine aggregierten Reports.",
        "connect_action": "Report-Eingang wählen",
        "connect_why": "Erst Reports unterscheiden beabsichtigte Absender von fremden Quellen.",
        "connect_verify": "Die Quelle wird erfolgreich geprüft und DMARQ importiert den ersten aggregierten Report.",
        "wait_title": "Prüfen, ob der Report-Eingang funktioniert",
        "wait_summary": "Eine Report-Quelle ist aktiv, aber für {domain} wurde noch kein aggregierter Report gespeichert.",
        "wait_action": "Report-Eingang prüfen",
        "wait_why": "Bei wenig Mailvolumen können Reports spät eintreffen. Der Quellenstatus trennt normales Warten von einer defekten Verbindung.",
        "wait_verify": "Die Quellenprüfung gelingt und der erste Report erscheint, oder DMARQ bestätigt, dass keiner vorlag.",
        "bounce_title": "Bounce oder Provider-Ereignis prüfen",
        "bounce_summary": "DMARC-Aggregatdaten beweisen nicht, warum eine einzelne Nachricht abgelehnt wurde. Prüfe zuerst SMTP-Antwort oder Provider-Ereignis.",
        "bounce_action": "Beobachtete Absender prüfen",
        "bounce_why": "Der SMTP-Status nennt ablehnendes System und Ursache; DMARC liefert nur Authentifizierungskontext.",
        "bounce_verify": "Absender, Empfänger-Provider, Zeitpunkt und SMTP-Status sind bekannt.",
        "reports_title": "Erklärung des neuesten Reports öffnen",
        "reports_summary": "DMARQ hat aggregierte Daten für {domain} gespeichert. Beginne mit einem Report und seinen interpretierten Quellen.",
        "reports_action": "Neuesten Report erklären",
        "reports_why": "Ein begrenzter Report ist leichter zu verstehen als DNS-Änderungen aus einem Gesamtscore abzuleiten.",
        "reports_verify": "Beabsichtigte Quellen, Authentifizierungsfehler und berechtigte Aktionen sind unterscheidbar.",
        "failures_title": "Beabsichtigte Absender mit Authentifizierungsfehlern prüfen",
        "failures_summary": "Gespeicherte Reports enthalten {failed} Nachrichten für {domain}, die DMARC nicht bestanden haben.",
        "failures_action": "Fehlgeschlagene Absender prüfen",
        "failures_why": "Ein legitimer Absender sollte vor einer Policy-Verschärfung repariert werden; blockierte fremde Quellen brauchen eventuell keine Aktion.",
        "failures_verify": "Der beabsichtigte Absender besteht in einem späteren Report aligned DKIM oder SPF.",
        "spoofing_title": "Wahrscheinlich unautorisierte Nutzung beobachtet",
        "spoofing_summary": "Die Domain ist als nicht sendend markiert, während Reports nicht authentifizierten Verkehr zeigen. Eine unmittelbare Sender-Reparatur ist nicht erkennbar.",
        "spoofing_action": "Belege prüfen",
        "spoofing_why": "Bestätige zuerst, dass keine legitime Quelle zu dem Absender gehört.",
        "spoofing_verify": "Es bleiben keine bekannten Absender und Empfänger wenden weiter die gewollte DMARC-Policy an.",
        "ready_title": "Monitoring ist bereit",
        "ready_summary": "DMARQ hat für {domain} eine Domain, DMARC-Daten und Report-Eingang. Aktuell ist kein weiterer Einrichtungsschritt nötig.",
        "ready_action": "Domain-Übersicht öffnen",
        "ready_why": "Die nächste sinnvolle Arbeit entsteht erst durch Änderungen in gespeicherten Absender- oder Authentifizierungsdaten.",
        "ready_verify": "Neue Reports treffen weiter ein und kein beabsichtigter Absender entwickelt Authentifizierungsfehler.",
        "known_domains": "{count} überwachte Domain(s) sind gespeichert.",
        "known_dmarc": "Gespeicherte DNS-Daten enthalten einen DMARC-Record für {domain}.",
        "known_no_dmarc": "Gespeicherte DNS-Daten enthalten keinen DMARC-Record für {domain}.",
        "known_reports": "{count} aggregierte Report(s) mit {messages} beobachteten Nachricht(en) sind für {domain} gespeichert.",
        "known_dkim": "Die gespeicherten DNS-Daten enthalten {count} funktionierende DKIM-Selector(en).",
        "known_report_destinations": "Der gespeicherte DMARC-Record enthält {rua} Ziel(e) für aggregierte und {ruf} Ziel(e) für Fehler-Reports.",
        "known_other_reports": "DMARQ hat außerdem {forensic} Fehler-Report(s) und {tls} TLS-Report(s) gespeichert.",
        "known_sources": "{count} aktive Report-Quelle(n) sind eingerichtet.",
        "unknown_dns": "Noch ist kein persistierter DNS-Posture-Snapshot vorhanden.",
        "unknown_sender": "DMARQ weiß noch nicht, ob diese Domain bewusst E-Mails versendet.",
        "unknown_control": "DMARQ weiß noch nicht, wer DNS verwaltet.",
        "inference_low_volume": "Wenige oder keine Reports können bei einer Domain mit wenig Volumen normal sein und beweisen keinen defekten Eingang.",
        "later_first_report": "Ersten aggregierten Report bestätigen",
        "later_classify": "Beabsichtigte Versanddienste klassifizieren",
        "later_notifications": "Festlegen, wann DMARQ benachrichtigen soll",
        "later_evidence": "Vollständige technische Belege verfügbar halten",
    },
}


def _text(locale: str, key: str, **values: object) -> str:
    catalog = _COPY.get(locale, _COPY["en"])
    return catalog[key].format(**values)


def _action(
    locale: str,
    prefix: str,
    *,
    action_id: str,
    href: str,
    **values: object,
) -> Dict[str, Any]:
    return {
        "id": action_id,
        "title": _text(locale, f"{prefix}_title", **values),
        "description": _text(locale, f"{prefix}_summary", **values),
        "label": _text(locale, f"{prefix}_action", **values),
        "href": href,
        "why": _text(locale, f"{prefix}_why", **values),
        "verification": _text(locale, f"{prefix}_verify", **values),
        "blocked_by": [],
    }


def _later_steps(locale: str, current_id: str, domain_href: str) -> list[Dict[str, str]]:
    candidates = [
        {
            "id": "confirm_first_report",
            "title": _text(locale, "later_first_report"),
            "href": "/mail-sources",
        },
        {
            "id": "classify_senders",
            "title": _text(locale, "later_classify"),
            "href": f"{domain_href}#sending-sources",
        },
        {
            "id": "configure_notifications",
            "title": _text(locale, "later_notifications"),
            "href": "/settings#notification-settings",
        },
        {
            "id": "open_evidence",
            "title": _text(locale, "later_evidence"),
            "href": f"{domain_href}#recent-reports",
        },
    ]
    return [item for item in candidates if item["id"] != current_id][:4]


def _first_goal(goals: Iterable[object]) -> str:
    return next((str(goal) for goal in goals if goal), "learn_or_explore")


def _evidence_notes(
    locale: str,
    evidence: DiagnosticEvidence,
    domain: Optional[str],
    context: Dict[str, Any],
) -> tuple[list[str], list[str], list[str]]:
    known_facts = [
        _text(locale, "known_domains", count=len(evidence.domain_names)),
        _text(locale, "known_sources", count=evidence.enabled_source_count),
    ]
    unknowns: list[str] = []
    inferences: list[str] = []
    if domain:
        if evidence.dns_evidence_available:
            known_facts.append(
                _text(
                    locale,
                    "known_dmarc" if evidence.has_dmarc else "known_no_dmarc",
                    domain=domain,
                )
            )
        else:
            unknowns.append(_text(locale, "unknown_dns"))
        known_facts.append(
            _text(
                locale,
                "known_reports",
                count=evidence.report_count,
                messages=evidence.message_count,
                domain=domain,
            )
        )
        if evidence.has_dkim:
            known_facts.append(_text(locale, "known_dkim", count=evidence.dkim_selector_count))
        if evidence.dmarc_rua_count or evidence.dmarc_ruf_count:
            known_facts.append(
                _text(
                    locale,
                    "known_report_destinations",
                    rua=evidence.dmarc_rua_count,
                    ruf=evidence.dmarc_ruf_count,
                )
            )
        if evidence.forensic_report_count or evidence.tls_report_count:
            known_facts.append(
                _text(
                    locale,
                    "known_other_reports",
                    forensic=evidence.forensic_report_count,
                    tls=evidence.tls_report_count,
                )
            )
    if context.get("controls_dns") is None:
        unknowns.append(_text(locale, "unknown_control"))
    if context.get("domain_sends_mail") is None:
        unknowns.append(_text(locale, "unknown_sender"))
    if context.get("low_volume") and evidence.report_count == 0:
        inferences.append(_text(locale, "inference_low_volume"))
    return known_facts, inferences, unknowns


def _no_dmarc_action(
    locale: str, domain: str, domain_href: str, controls_dns: Optional[bool]
) -> Dict[str, Any]:
    if controls_dns is False:
        return _action(
            locale,
            "handoff",
            action_id="prepare_dns_handoff",
            href=f"{domain_href}#dns-records",
            domain=domain,
        )
    if controls_dns is True:
        return _action(
            locale,
            "publish",
            action_id="publish_monitoring_dmarc",
            href=f"{domain_href}#dns-records",
            domain=domain,
        )
    return _action(
        locale,
        "check_dns",
        action_id="confirm_dns_control",
        href=f"{domain_href}#dns-records",
        domain=domain,
    )


def _select_current_action(
    locale: str,
    goal: str,
    domain: Optional[str],
    context: Dict[str, Any],
    evidence: DiagnosticEvidence,
) -> tuple[Dict[str, Any], str, str]:
    if not domain:
        current = _action(locale, "add_domain", action_id="add_domain", href="/domains")
        return current, "setup_required", "/domains"
    domain_href = f"/domains/{quote(domain, safe='')}"
    if goal in {"investigate_bounces", "troubleshoot_delivery"} and context.get("bounce_available"):
        current = _action(
            locale,
            "bounce",
            action_id="review_bounce_evidence",
            href=f"{domain_href}#sending-sources",
        )
        return current, "insufficient_dmarc_evidence", domain_href
    if not evidence.has_dmarc:
        current = _no_dmarc_action(locale, domain, domain_href, context.get("controls_dns"))
        return current, "setup_required", domain_href
    if evidence.report_count == 0:
        prefix = "connect" if evidence.enabled_source_count == 0 else "wait"
        action_id = (
            "connect_report_intake"
            if evidence.enabled_source_count == 0
            else "verify_report_intake"
        )
        current = _action(
            locale,
            prefix,
            action_id=action_id,
            href="/mail-sources",
            domain=domain,
        )
        return current, "evidence_waiting", domain_href
    if goal == "protect_against_spoofing" and context.get("domain_sends_mail") is False:
        current = _action(
            locale,
            "spoofing",
            action_id="review_protected_spoofing",
            href=f"{domain_href}#sending-sources",
        )
        return current, "no_action_likely_unauthorized_use", domain_href
    if goal == "understand_reports":
        href = f"/reports/{evidence.latest_report_id}" if evidence.latest_report_id else "/reports"
        current = _action(locale, "reports", action_id="explain_report", href=href, domain=domain)
        return current, "investigation_ready", domain_href
    if evidence.failed_message_count > 0:
        current = _action(
            locale,
            "failures",
            action_id="review_failing_senders",
            href=f"{domain_href}#sending-sources",
            domain=domain,
            failed=evidence.failed_message_count,
        )
        return current, "action_required", domain_href
    current = _action(locale, "ready", action_id="open_domain", href=domain_href, domain=domain)
    return current, "monitoring_ready", domain_href


def build_diagnostic_plan(
    profile: Dict[str, Any],
    evidence: DiagnosticEvidence,
    *,
    locale: str = "en",
) -> Dict[str, Any]:
    """Return one stable next action without performing I/O or provider writes."""
    locale = "de" if locale == "de" else "en"
    goals = profile.get("installation_goals") or []
    goal = _first_goal(goals)
    context = profile.get("mail_context") if isinstance(profile.get("mail_context"), dict) else {}
    domain = evidence.selected_domain or (
        evidence.domain_names[0] if evidence.domain_names else None
    )
    known_facts, inferences, unknowns = _evidence_notes(locale, evidence, domain, context)
    current, conclusion_code, domain_href = _select_current_action(
        locale, goal, domain, context, evidence
    )

    return {
        "schema": PLAN_SCHEMA,
        "plan_version": PLAN_VERSION,
        "generated_from": "persisted_evidence",
        "primary_goal": goal,
        "domain": domain,
        "conclusion": {
            "code": conclusion_code,
            "title": current["title"],
            "summary": current["description"],
        },
        "current_action": current,
        "later_steps": _later_steps(locale, current["id"], domain_href),
        "known_facts": known_facts,
        "inferences": inferences,
        "unknowns": unknowns,
        "evidence": {
            "domain_count": len(evidence.domain_names),
            "report_count": evidence.report_count,
            "forensic_report_count": evidence.forensic_report_count,
            "tls_report_count": evidence.tls_report_count,
            "message_count": evidence.message_count,
            "failed_message_count": evidence.failed_message_count,
            "enabled_source_count": evidence.enabled_source_count,
            "checked_source_count": evidence.checked_source_count,
            "dns_evidence_available": evidence.dns_evidence_available,
            "has_dmarc": evidence.has_dmarc,
            "has_spf": evidence.has_spf,
            "has_dkim": evidence.has_dkim,
            "dkim_selector_count": evidence.dkim_selector_count,
            "dmarc_rua_count": evidence.dmarc_rua_count,
            "dmarc_ruf_count": evidence.dmarc_ruf_count,
            "dns_provider_connected": evidence.dns_provider_connected,
        },
    }
