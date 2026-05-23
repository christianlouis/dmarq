"""Shared test data for DMARC report tests."""

from pathlib import Path


DMARC_FIXTURE_DIR = Path(__file__).with_name("fixtures") / "dmarc_aggregate"


def load_dmarc_fixture(filename: str) -> str:
    """Load a curated aggregate-report fixture as text."""
    return (DMARC_FIXTURE_DIR / filename).read_text(encoding="utf-8")


DMARC_COMPATIBILITY_FIXTURES = [
    {
        "id": "rfc7489-google",
        "filename": "rfc7489-google.xml",
        "domain": "example.com",
        "report_id": "123456789",
        "variant": "rfc7489-compatible",
        "total_count": 2,
    },
    {
        "id": "rfc9990-namespaced-legacy-fields",
        "filename": "rfc9990-namespaced-legacy-fields.xml",
        "domain": "example.com",
        "report_id": "987654321",
        "variant": "rfc9990",
        "total_count": 3,
    },
    {
        "id": "rfc9990-treewalk-extension",
        "filename": "rfc9990-treewalk-extension.xml",
        "domain": "example.org",
        "report_id": "fixture-rfc9990-treewalk",
        "variant": "rfc9990",
        "schema_version": "1.0",
        "total_count": 5,
        "policy": {
            "p": "quarantine",
            "sp": "reject",
            "np": "none",
            "fo": "1",
            "testing": "y",
            "discovery_method": "treewalk",
        },
    },
    {
        "id": "rfc9990-multi-auth-overrides",
        "filename": "rfc9990-multi-auth-overrides.xml",
        "domain": "example.net",
        "report_id": "fixture-rfc9990-multi-auth",
        "variant": "rfc9990",
        "schema_version": "1.0",
        "total_count": 15,
        "policy": {
            "p": "reject",
            "sp": "quarantine",
            "np": "reject",
            "fo": "1:d:s",
            "testing": "n",
            "discovery_method": "psd",
        },
    },
]

SAMPLE_XML = load_dmarc_fixture("rfc7489-google.xml")

SAMPLE_XML_WITH_NAMESPACE = load_dmarc_fixture("rfc9990-namespaced-legacy-fields.xml")
