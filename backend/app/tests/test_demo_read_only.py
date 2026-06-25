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

    return TestClient(app)


def test_demo_mode_allows_safe_methods():
    client = _build_demo_guard_client()

    assert client.get("/resource").status_code == 200
    assert client.head("/resource").status_code == 200
    assert client.options("/resource").status_code == 200


def test_demo_mode_blocks_mutating_methods():
    client = _build_demo_guard_client()

    for method in (client.post, client.put, client.patch, client.delete):
        response = method("/resource")
        assert response.status_code == 403
        assert response.json()["detail"].startswith("This public demo is read-only.")


def test_normal_mode_allows_mutating_methods():
    client = _build_demo_guard_client(demo_mode=False)

    assert client.post("/resource").status_code == 200
