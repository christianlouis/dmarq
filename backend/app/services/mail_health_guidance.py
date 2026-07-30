"""Localized presentation of immutable mail-health assessments.

Assessment facts and authorization never vary by presentation preference.  This
catalog only controls wording and progressive disclosure for the current task.
"""

from __future__ import annotations

from typing import Any, Dict, Mapping

from app.core.localization import normalize_locale
from app.services.guidance_profile import EXPLANATION_DEPTHS, WORK_CONTEXTS

GUIDANCE_CATALOG_VERSION = "2026-07-v1"

PRIMARY_CONCLUSIONS = (
    "mail_health.action_required",
    "mail_health.investigation_required",
    "mail_health.no_action_likely_unauthorized_use",
    "mail_health.monitor",
    "mail_health.insufficient_evidence",
    "mail_health.healthy",
    "mail_health.confirmed_unauthorized_use_blocked",
    "mail_health.confirmed_unauthorized_use_unprotected",
    "mail_health.expected_forwarding",
    "mail_health.dmarc_pass_bounce_mismatch",
)


def _entry(
    headline: str,
    conclusion: str,
    why: str,
    action: str,
    verification: str,
    *,
    no_action: str = "",
) -> Dict[str, str]:
    return {
        "headline": headline,
        "conclusion": conclusion,
        "why_it_matters": why,
        "next_action_label": action,
        "verification_text": verification,
        "no_action_explanation": no_action,
    }


CATALOG: Dict[str, Dict[str, Dict[str, str]]] = {
    "en": {
        "mail_health.action_required": _entry(
            "Intended mail may be affected",
            "A sender you use is failing DMARC authentication.",
            "Messages from this sender may be rejected or treated as suspicious.",
            "Review the affected sender",
            "Fresh reports show this sender authenticating without DMARC failures.",
        ),
        "mail_health.investigation_required": _entry(
            "Identify an unrecognized sender",
            "DMARQ cannot yet tell whether this failing source belongs to you.",
            "Classifying it prevents unsafe DNS changes and unnecessary alerts.",
            "Classify the sender",
            "The source is classified or fresh evidence identifies its owner.",
        ),
        "mail_health.no_action_likely_unauthorized_use": _entry(
            "Likely spoofing is being handled",
            "An unrecognized sender failed authentication and receivers applied your policy.",
            "This does not currently look like a fault in your intended mail flow.",
            "Review the evidence",
            "Known senders remain healthy and the protective policy remains effective.",
            no_action="No immediate configuration change is required.",
        ),
        "mail_health.monitor": _entry(
            "Keep monitoring",
            "DMARQ is waiting for a meaningful change or more evidence.",
            "No urgent failure is established from the current report data.",
            "Review monitoring evidence",
            "DMARQ reassesses when new report evidence arrives.",
            no_action="No immediate action is required.",
        ),
        "mail_health.insufficient_evidence": _entry(
            "More evidence is needed",
            "Aggregate DMARC data cannot answer this question yet.",
            "DMARQ avoids guessing about delivery or sender ownership.",
            "Open the next evidence source",
            "The required report, bounce, or provider evidence is available.",
        ),
        "mail_health.healthy": _entry(
            "Mail authentication looks healthy",
            "Current reports show successful authentication without a failure pattern.",
            "DMARQ will keep watching for meaningful sender or authentication changes.",
            "Review recent reports",
            "Report intake remains current and no new authentication failures appear.",
            no_action="No action is required now.",
        ),
        "mail_health.confirmed_unauthorized_use_blocked": _entry(
            "Confirmed abuse is being blocked",
            "A source marked unauthorized failed authentication and receivers applied policy.",
            "Your intended sending setup does not currently appear affected.",
            "Review the blocked source",
            "Known senders remain healthy and receivers keep applying protective policy.",
            no_action="No immediate configuration change is required.",
        ),
        "mail_health.confirmed_unauthorized_use_unprotected": _entry(
            "Protect against confirmed unauthorized use",
            "A source marked unauthorized was not consistently quarantined or rejected.",
            "Domain protection may be incomplete, but known senders must be safe first.",
            "Review protection readiness",
            "Fresh reports show protective handling while known senders remain healthy.",
        ),
        "mail_health.expected_forwarding": _entry(
            "Check an expected forwarding path",
            "Forwarding may explain SPF failure, but aligned DKIM still needs evidence.",
            "Adding an intermediary to SPF without sender-side proof can weaken protection.",
            "Review forwarding evidence",
            "Fresh reports isolate the expected forwarding path and aligned DKIM result.",
        ),
        "mail_health.dmarc_pass_bounce_mismatch": _entry(
            "DMARC does not explain the reported bounce",
            "Authentication passed, so the SMTP response or provider event is needed.",
            "DMARC proves neither delivery nor inbox placement.",
            "Review bounce evidence",
            "The SMTP status, receiver, timestamp, and affected sender are identified.",
        ),
    },
    "de": {
        "mail_health.action_required": _entry(
            "Beabsichtigte E-Mails könnten betroffen sein",
            "Ein von dir genutzter Absender besteht die DMARC-Authentifizierung nicht.",
            "Nachrichten dieses Absenders könnten abgewiesen oder als verdächtig behandelt werden.",
            "Betroffenen Absender prüfen",
            "Neue Reports zeigen diesen Absender ohne DMARC-Fehler.",
        ),
        "mail_health.investigation_required": _entry(
            "Unbekannten Absender zuordnen",
            "DMARQ weiß noch nicht, ob diese fehlerhafte Quelle zu dir gehört.",
            "Eine Zuordnung verhindert riskante DNS-Änderungen und unnötige Warnungen.",
            "Absender zuordnen",
            "Die Quelle ist klassifiziert oder neue Nachweise zeigen ihren Eigentümer.",
        ),
        "mail_health.no_action_likely_unauthorized_use": _entry(
            "Wahrscheinliches Spoofing wird abgewehrt",
            "Ein unbekannter Absender ist gescheitert und Empfänger haben deine Richtlinie angewendet.",
            "Derzeit deutet nichts auf einen Fehler in deinem beabsichtigten Mailversand hin.",
            "Nachweise prüfen",
            "Bekannte Absender bleiben gesund und die Schutzrichtlinie bleibt wirksam.",
            no_action="Aktuell ist keine Konfigurationsänderung nötig.",
        ),
        "mail_health.monitor": _entry(
            "Weiter beobachten",
            "DMARQ wartet auf eine relevante Änderung oder weitere Nachweise.",
            "Die aktuellen Reports belegen keinen dringenden Fehler.",
            "Überwachungsdaten prüfen",
            "DMARQ bewertet den Zustand mit neuen Reports erneut.",
            no_action="Aktuell ist keine unmittelbare Aktion nötig.",
        ),
        "mail_health.insufficient_evidence": _entry(
            "Weitere Nachweise erforderlich",
            "Aggregierte DMARC-Daten beantworten diese Frage noch nicht.",
            "DMARQ rät nicht über Zustellung oder Absenderzuordnung.",
            "Nächste Nachweisquelle öffnen",
            "Der erforderliche Report, Bounce oder Provider-Nachweis liegt vor.",
        ),
        "mail_health.healthy": _entry(
            "Mailauthentifizierung sieht gesund aus",
            "Aktuelle Reports zeigen erfolgreiche Authentifizierung ohne Fehlermuster.",
            "DMARQ beobachtet relevante Änderungen bei Absendern und Authentifizierung weiter.",
            "Aktuelle Reports prüfen",
            "Der Report-Eingang bleibt aktuell und es treten keine neuen Authentifizierungsfehler auf.",
            no_action="Derzeit ist keine Aktion nötig.",
        ),
        "mail_health.confirmed_unauthorized_use_blocked": _entry(
            "Bestätigter Missbrauch wird blockiert",
            "Eine als unautorisiert markierte Quelle scheitert und Empfänger wenden die Richtlinie an.",
            "Dein beabsichtigter Mailversand scheint derzeit nicht betroffen.",
            "Blockierte Quelle prüfen",
            "Bekannte Absender bleiben gesund und Empfänger wenden die Schutzrichtlinie weiter an.",
            no_action="Aktuell ist keine Konfigurationsänderung nötig.",
        ),
        "mail_health.confirmed_unauthorized_use_unprotected": _entry(
            "Vor bestätigtem Missbrauch schützen",
            "Eine unautorisierte Quelle wurde nicht durchgehend abgewiesen oder isoliert.",
            "Der Domainschutz könnte unvollständig sein; bekannte Absender müssen zuerst sicher sein.",
            "Schutzbereitschaft prüfen",
            "Neue Reports zeigen Schutzmaßnahmen und weiterhin gesunde bekannte Absender.",
        ),
        "mail_health.expected_forwarding": _entry(
            "Erwartete Weiterleitung prüfen",
            "Weiterleitung kann SPF-Fehler erklären; für ausgerichtetes DKIM fehlen noch Nachweise.",
            "Eine ungeprüfte SPF-Freigabe des Zwischenservers kann den Schutz schwächen.",
            "Weiterleitungsnachweise prüfen",
            "Neue Reports grenzen den Weiterleitungspfad und das ausgerichtete DKIM-Ergebnis ein.",
        ),
        "mail_health.dmarc_pass_bounce_mismatch": _entry(
            "DMARC erklärt den gemeldeten Bounce nicht",
            "Die Authentifizierung war erfolgreich; benötigt wird die SMTP-Antwort oder das Provider-Ereignis.",
            "DMARC beweist weder Zustellung noch Posteingangsplatzierung.",
            "Bounce-Nachweis prüfen",
            "SMTP-Status, Empfänger, Zeitpunkt und betroffener Absender sind identifiziert.",
        ),
    },
}


def render_mail_health_guidance(
    assessment: Mapping[str, Any], *, locale: str, depth: str, context: str
) -> Dict[str, Any]:
    """Render presentation metadata without changing assessment facts."""
    resolved_locale = normalize_locale(locale)
    resolved_depth = depth if depth in EXPLANATION_DEPTHS else "standard"
    resolved_context = context if context in WORK_CONTEXTS else "watch"
    conclusion_key = str((assessment.get("conclusion") or {}).get("key") or "")
    entry = CATALOG.get(resolved_locale, {}).get(conclusion_key) or CATALOG["en"].get(
        conclusion_key
    )
    if entry is None:
        entry = _entry(
            str(assessment.get("title") or "Review mail health"),
            str(assessment.get("summary") or "DMARQ has new mail-health evidence."),
            "Review the linked evidence before changing mail or DNS settings.",
            str(assessment.get("next_step") or "Review evidence"),
            str(assessment.get("verification_condition") or "Review fresh report evidence."),
        )
    evidence_context = resolved_context == "evidence"
    expert_depth = resolved_depth == "expert"
    diagnose_context = resolved_context == "diagnose"
    return {
        "catalog_version": GUIDANCE_CATALOG_VERSION,
        "locale": resolved_locale,
        "depth": resolved_depth,
        "context": resolved_context,
        **entry,
        "impact_label": _impact_label(assessment, resolved_locale),
        "urgency_label": _urgency_label(assessment, resolved_locale),
        "confidence_label": _confidence_label(assessment, resolved_locale),
        "evidence_disclosure_label": (
            "Technische Nachweise anzeigen"
            if resolved_locale == "de"
            else "Show technical evidence"
        ),
        "show_why": resolved_depth != "guided" or diagnose_context or evidence_context,
        "show_observations": diagnose_context or evidence_context or expert_depth,
        "show_inferences": evidence_context or expert_depth,
        "show_unknowns": evidence_context or expert_depth,
        "show_exact_evidence": evidence_context or expert_depth,
    }


def _impact_label(assessment: Mapping[str, Any], locale: str) -> str:
    key = str(assessment.get("intended_mail_impact") or "unknown")
    labels = {
        "en": {
            "likely_affected": "Intended mail may be affected",
            "likely_not_affected": "Intended mail does not appear affected",
            "possible": "Intended mail could be affected",
            "unknown": "Impact on intended mail is not known yet",
        },
        "de": {
            "likely_affected": "Beabsichtigte E-Mails könnten betroffen sein",
            "likely_not_affected": "Beabsichtigte E-Mails scheinen nicht betroffen",
            "possible": "Beabsichtigte E-Mails könnten betroffen sein",
            "unknown": "Auswirkung auf beabsichtigte E-Mails noch unbekannt",
        },
    }
    return labels[locale].get(key, labels[locale]["unknown"])


def _urgency_label(assessment: Mapping[str, Any], locale: str) -> str:
    key = str(assessment.get("urgency") or "monitor")
    labels = {
        "en": {
            "urgent": "Act now",
            "timely": "Action recommended soon",
            "monitor": "Keep monitoring",
            "none": "No immediate action required",
        },
        "de": {
            "urgent": "Jetzt handeln",
            "timely": "Zeitnahe Aktion empfohlen",
            "monitor": "Weiter beobachten",
            "none": "Keine unmittelbare Aktion nötig",
        },
    }
    return labels[locale].get(key, labels[locale]["monitor"])


def _confidence_label(assessment: Mapping[str, Any], locale: str) -> str:
    value = str(assessment.get("confidence") or "Not enough evidence")
    if locale == "en":
        return value
    return {
        "High": "Hoch",
        "Medium": "Mittel",
        "Low": "Niedrig",
        "Not enough evidence": "Nicht genügend Nachweise",
    }.get(value, value)


def missing_catalog_entries() -> Dict[str, list[str]]:
    """Return catalog gaps for tests and startup diagnostics."""
    return {
        locale: [key for key in PRIMARY_CONCLUSIONS if key not in entries]
        for locale, entries in CATALOG.items()
    }
