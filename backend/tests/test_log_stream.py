from __future__ import annotations

import sys
from collections.abc import AsyncGenerator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parent.parent))
import auth
import log_monitor
import main


async def _fake_stream(lines_back: int) -> AsyncGenerator[str, None]:
    yield "data: satir-1|LEVEL:info\n\n"


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setattr(log_monitor, "tail_log_stream", _fake_stream)
    return TestClient(main.app)


@pytest.fixture
def headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {auth.create_token('admin')}"}


def _ticket(client: TestClient, headers: dict[str, str]) -> str:
    resp = client.post("/api/logs/stream-ticket", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["expires_in"] == 60
    return str(resp.json()["ticket"])


def test_ticket_requires_login(client: TestClient) -> None:
    assert client.post("/api/logs/stream-ticket").status_code == 401


def test_stream_with_ticket(client: TestClient, headers: dict[str, str]) -> None:
    resp = client.get(f"/api/logs/stream?ticket={_ticket(client, headers)}")
    assert resp.status_code == 200
    assert "satir-1" in resp.text


def test_ticket_is_single_use(client: TestClient, headers: dict[str, str]) -> None:
    ticket = _ticket(client, headers)
    assert client.get(f"/api/logs/stream?ticket={ticket}").status_code == 200
    assert client.get(f"/api/logs/stream?ticket={ticket}").status_code == 401


def test_expired_ticket_rejected(client: TestClient, headers: dict[str, str], monkeypatch: pytest.MonkeyPatch) -> None:
    ticket = _ticket(client, headers)
    later = auth.time.time() + auth.STREAM_TICKET_TTL + 1
    monkeypatch.setattr(auth.time, "time", lambda: later)
    assert client.get(f"/api/logs/stream?ticket={ticket}").status_code == 401


def test_session_token_in_query_rejected(client: TestClient) -> None:
    token = auth.create_token("admin")
    assert client.get(f"/api/logs/stream?token={token}").status_code == 401
    assert client.get(f"/api/logs/stream?ticket={token}").status_code == 401


def test_bearer_header_still_works(client: TestClient, headers: dict[str, str]) -> None:
    assert client.get("/api/logs/stream", headers=headers).status_code == 200


def test_unknown_ticket_rejected(client: TestClient) -> None:
    assert client.get("/api/logs/stream?ticket=uydurma").status_code == 401
