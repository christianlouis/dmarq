from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.middleware.demo import DemoReadOnlyMiddleware


def _build_demo_guard_client(demo_mode: bool = True) -> TestClient:
    app = FastAPI()
    app.add_middleware(
        DemoReadOnlyMiddleware,
        settings_provider=lambda: SimpleNamespace(DEMO_MODE=demo_mode),
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


def test_normal_mode_allows_mutating_methods():
    with _build_demo_guard_client(demo_mode=False) as client:
        assert client.post("/resource").status_code == 200
