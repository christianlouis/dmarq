from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.middleware.demo import DemoReadOnlyMiddleware


def _build_demo_guard_client(
    demo_mode: bool = True,
    *,
    provider_demo_enabled: bool = False,
) -> TestClient:
    app = FastAPI()
    app.add_middleware(
        DemoReadOnlyMiddleware,
        settings_provider=lambda: SimpleNamespace(
            DEMO_MODE=demo_mode,
            PROVIDER_DEMO_ENABLED=provider_demo_enabled,
        ),
    )

    @app.api_route(
        "/resource",
        methods=["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"],
    )
    async def resource():
        return {"ok": True}

    @app.post("/api/v1/mail-sources/{source_id}/backfills")
    async def simulated_backfill(source_id: int):
        return {"source_id": source_id, "ok": True}

    @app.post("/api/v1/mail-sources/{source_id}/backfills/{job_id}/retry")
    async def simulated_retry(source_id: int, job_id: int):
        return {"source_id": source_id, "job_id": job_id, "ok": True}

    @app.post("/api/v1/operator/demo/support-session")
    async def simulated_support_session():
        return {"ok": True}

    @app.api_route("/api/v1/operator/support-session", methods=["POST", "DELETE"])
    async def product_support_session():
        return {"ok": True}

    return TestClient(app)


def test_demo_mode_allows_safe_methods():
    with _build_demo_guard_client() as client:
        assert client.get("/resource").status_code == 200
        assert client.head("/resource").status_code == 200
        assert client.options("/resource").status_code == 200


def test_demo_mode_blocks_mutating_methods():
    with _build_demo_guard_client() as client:
        for method in (client.post, client.put, client.patch, client.delete):
            response = method("/resource")
            assert response.status_code == 403
            assert response.json()["detail"].startswith("This public demo is read-only.")


def test_demo_mode_allows_synthetic_backfill_simulation_only():
    with _build_demo_guard_client() as client:
        allowed_queue = client.post("/api/v1/mail-sources/9001/backfills")
        allowed_retry = client.post("/api/v1/mail-sources/9002/backfills/9201/retry")
        blocked_real_source = client.post("/api/v1/mail-sources/123/backfills")

        assert allowed_queue.status_code == 200
        assert allowed_retry.status_code == 200
        assert blocked_real_source.status_code == 403


def test_demo_mode_allows_synthetic_support_session_simulation():
    with _build_demo_guard_client() as client:
        response = client.post("/api/v1/operator/demo/support-session")

        assert response.status_code == 200


def test_demo_mode_only_allows_product_support_sessions_for_provider_demo():
    with _build_demo_guard_client() as legacy_client:
        legacy_start = legacy_client.post("/api/v1/operator/support-session")
        legacy_end = legacy_client.delete("/api/v1/operator/support-session")
        assert legacy_start.status_code == 403
        assert legacy_end.status_code == 403

    with _build_demo_guard_client(provider_demo_enabled=True) as provider_client:
        provider_start = provider_client.post("/api/v1/operator/support-session")
        provider_end = provider_client.delete("/api/v1/operator/support-session")
        assert provider_start.status_code == 200
        assert provider_end.status_code == 200


def test_normal_mode_allows_mutating_methods():
    with _build_demo_guard_client(demo_mode=False) as client:
        assert client.post("/resource").status_code == 200
