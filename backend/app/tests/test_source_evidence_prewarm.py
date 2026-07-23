import json
from unittest.mock import AsyncMock

import pytest

from app.models.domain import Domain
from app.models.report import DMARCReport, ReportRecord
from app.services import source_evidence_prewarm
from app.services.ptr_lookup import PtrLookupResult
from app.services.source_network import SourceNetworkIntelligence


@pytest.mark.asyncio
async def test_prewarm_persists_point_in_time_sender_evidence(db_session, monkeypatch):
    domain = Domain(name="example.com", active=True)
    db_session.add(domain)
    db_session.flush()
    report = DMARCReport(
        domain_id=domain.id,
        report_id="report-1",
        org_name="receiver.example",
        begin_date=1783000000,
        end_date=1783086400,
    )
    db_session.add(report)
    db_session.flush()
    record = ReportRecord(
        report_id=report.id,
        source_ip="93.184.216.34",
        count=25,
        disposition="none",
        dkim="pass",
        spf="pass",
    )
    db_session.add(record)
    db_session.commit()
    record_id = record.id

    monkeypatch.setattr(source_evidence_prewarm, "SessionLocal", lambda: db_session)
    monkeypatch.setattr(source_evidence_prewarm, "get_default_provider", lambda _db: object())
    monkeypatch.setattr(
        source_evidence_prewarm,
        "lookup_ptr_with_fallbacks",
        AsyncMock(
            return_value=PtrLookupResult(
                hostname="edge.example.net",
                status="ok",
                provider="test",
            )
        ),
    )
    monkeypatch.setattr(
        source_evidence_prewarm,
        "lookup_sources_network_cached",
        AsyncMock(
            return_value={
                "93.184.216.34": SourceNetworkIntelligence(
                    ip="93.184.216.34",
                    asn="AS15133",
                    as_name="Edgecast Inc.",
                    country_code="US",
                    country="United States",
                    checked_at="2026-07-23T12:00:00Z",
                )
            }
        ),
    )
    monkeypatch.setattr(source_evidence_prewarm, "providers_from_settings", lambda _settings: [])
    monkeypatch.setattr(
        source_evidence_prewarm,
        "lookup_sources_reputation_cached",
        AsyncMock(return_value={}),
    )
    settings = source_evidence_prewarm.get_settings()
    monkeypatch.setattr(settings, "SOURCE_EVIDENCE_PREWARM_ENABLED", True)
    monkeypatch.setattr(settings, "SOURCE_EVIDENCE_PREWARM_LIMIT", 10)

    assert await source_evidence_prewarm.prewarm_source_evidence() == 1

    record = db_session.get(ReportRecord, record_id)
    evidence = json.loads(record.source_evidence)
    assert evidence["ptr"]["hostname"] == "edge.example.net"
    assert evidence["network"]["asn"] == "AS15133"
    assert evidence["network"]["country_code"] == "US"
    assert evidence["reputation"]["status"] == "not_configured"
    assert evidence["captured_at"].endswith("Z")


@pytest.mark.asyncio
async def test_prewarm_does_not_overwrite_historical_evidence(db_session, monkeypatch):
    domain = Domain(name="example.com", active=True)
    db_session.add(domain)
    db_session.flush()
    report = DMARCReport(
        domain_id=domain.id,
        report_id="report-1",
        org_name="receiver.example",
        begin_date=1783000000,
        end_date=1783086400,
    )
    db_session.add(report)
    db_session.flush()
    original = '{"captured_at":"2026-07-20T00:00:00Z","ptr":{"status":"nxdomain"}}'
    record = ReportRecord(
        report_id=report.id,
        source_ip="93.184.216.34",
        count=1,
        disposition="none",
        source_evidence=original,
    )
    db_session.add(record)
    db_session.commit()
    record_id = record.id

    monkeypatch.setattr(source_evidence_prewarm, "SessionLocal", lambda: db_session)
    monkeypatch.setattr(source_evidence_prewarm, "get_default_provider", lambda _db: object())
    monkeypatch.setattr(
        source_evidence_prewarm,
        "lookup_sources_network_cached",
        AsyncMock(return_value={}),
    )
    monkeypatch.setattr(
        source_evidence_prewarm,
        "lookup_ptr_with_fallbacks",
        AsyncMock(return_value=PtrLookupResult(status="timeout")),
    )
    monkeypatch.setattr(source_evidence_prewarm, "providers_from_settings", lambda _settings: [])
    monkeypatch.setattr(
        source_evidence_prewarm,
        "lookup_sources_reputation_cached",
        AsyncMock(return_value={}),
    )

    assert await source_evidence_prewarm.prewarm_source_evidence() == 0
    record = db_session.get(ReportRecord, record_id)
    assert record.source_evidence == original


@pytest.mark.asyncio
async def test_prewarm_retries_transient_ptr_before_freezing_snapshot(db_session, monkeypatch):
    domain = Domain(name="example.com", active=True)
    db_session.add(domain)
    db_session.flush()
    report = DMARCReport(
        domain_id=domain.id,
        report_id="report-transient",
        org_name="receiver.example",
        begin_date=1783000000,
        end_date=1783086400,
    )
    db_session.add(report)
    db_session.flush()
    record = ReportRecord(
        report_id=report.id,
        source_ip="93.184.216.34",
        count=1,
        disposition="none",
    )
    db_session.add(record)
    db_session.commit()
    record_id = record.id

    monkeypatch.setattr(source_evidence_prewarm, "SessionLocal", lambda: db_session)
    monkeypatch.setattr(source_evidence_prewarm, "get_default_provider", lambda _db: object())
    monkeypatch.setattr(
        source_evidence_prewarm,
        "lookup_sources_network_cached",
        AsyncMock(return_value={}),
    )
    monkeypatch.setattr(
        source_evidence_prewarm,
        "lookup_ptr_with_fallbacks",
        AsyncMock(return_value=PtrLookupResult(status="timeout")),
    )
    monkeypatch.setattr(source_evidence_prewarm, "providers_from_settings", lambda _settings: [])
    monkeypatch.setattr(
        source_evidence_prewarm,
        "lookup_sources_reputation_cached",
        AsyncMock(return_value={}),
    )

    assert await source_evidence_prewarm.prewarm_source_evidence() == 0
    assert db_session.get(ReportRecord, record_id).source_evidence is None
