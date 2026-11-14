from __future__ import annotations

from fastapi.testclient import TestClient

import main


def test_valid_request_id_echoed() -> None:
    resp = TestClient(main.app).get("/api/health", headers={"X-Request-ID": "abc-123"})
    assert resp.headers["X-Request-ID"] == "abc-123"


def test_invalid_request_id_replaced() -> None:
    client = TestClient(main.app)
    for bad in ("a" * 65, "abc def", "x;y"):
        rid = client.get("/api/health", headers={"X-Request-ID": bad}).headers["X-Request-ID"]
        assert rid != bad and len(rid) == 12
