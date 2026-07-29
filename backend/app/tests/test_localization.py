from pathlib import Path

from starlette.requests import Request

from app.core.localization import (
    DE_TRANSLATIONS,
    normalize_locale,
    resolve_request_locale,
    template_locale_context,
    translate,
)


def _request(*, query: bytes = b"", cookie: str = "") -> Request:
    headers = []
    if cookie:
        headers.append((b"cookie", cookie.encode("ascii")))
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/settings",
            "query_string": query,
            "headers": headers,
            "scheme": "http",
            "server": ("testserver", 80),
            "client": ("127.0.0.1", 50000),
        }
    )


def test_normalize_locale_supports_common_german_variants():
    assert normalize_locale("de") == "de"
    assert normalize_locale("de_DE") == "de"
    assert normalize_locale("de-CH") == "de"


def test_unknown_locale_falls_back_to_configured_default():
    assert normalize_locale("fr", default="de") == "de"
    assert normalize_locale("fr", default="en") == "en"


def test_explicit_cookie_takes_precedence_over_instance_default():
    request = _request(cookie="dmarq_locale=en")
    assert resolve_request_locale(request, default="de") == "en"


def test_query_parameter_takes_precedence_over_cookie():
    request = _request(query=b"lang=de", cookie="dmarq_locale=en")
    assert resolve_request_locale(request, default="en") == "de"


def test_missing_translation_falls_back_to_english_source():
    assert translate("Protocol value p=reject", "de") == "Protocol value p=reject"


def test_template_context_exposes_one_catalog_and_translator():
    context = template_locale_context(_request(cookie="dmarq_locale=de"), default="en")
    assert context["locale"] == "de"
    assert context["_"]("Settings") == "Einstellungen"


def test_english_catalog_translates_legacy_provider_copy():
    assert translate("Kundenkonten", "en") == "Customer accounts"


def test_german_catalog_covers_operational_copy_rendered_after_page_load():
    """Interactive pages must not add English status copy after initial render."""
    expected = {
        "Report intake blocked": "Berichtseingang blockiert",
        "Scheduled checks active": "Geplante Prüfungen aktiv",
        "Pending DNS refresh": "DNS-Aktualisierung ausstehend",
        "DNS queued": "DNS-Prüfung eingeplant",
        "Queued": "Eingeplant",
        "Completed": "Abgeschlossen",
        "Reports Per Page": "Berichte pro Seite",
        "Session Lifetime (minutes)": "Sitzungsdauer (Minuten)",
        "Connected": "Verbunden",
        "Not authorised": "Nicht autorisiert",
        "Settings saved successfully.": "Einstellungen wurden gespeichert.",
        "Failed to load settings": "Einstellungen konnten nicht geladen werden",
    }

    for source, german in expected.items():
        assert DE_TRANSLATIONS[source] == german


def test_base_template_passes_resolved_locale_to_browser_catalog():
    template = (
        Path(__file__).resolve().parents[1] / "templates" / "layouts" / "base.html"
    ).read_text(encoding="utf-8")

    assert '/ui/localization-catalog.js?lang={{ locale }}' in template


def test_setup_template_uses_the_same_browser_locale_catalog():
    template = (
        Path(__file__).resolve().parents[1] / "templates" / "setup.html"
    ).read_text(encoding="utf-8")

    assert 'data-app-locale="{{ locale }}"' in template
    assert '/ui/localization-catalog.js?lang={{ locale }}' in template
    assert 'mailboxRecoveryHint?.summary' not in template
