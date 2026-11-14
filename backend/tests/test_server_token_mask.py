from __future__ import annotations

import sys
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parent.parent))
import auth
import database
import main

TOKEN = "ozel-sunucu-tokeni-0123456789abcdef"


@pytest.fixture
def client() -> TestClient:
    return TestClient(main.app)


@pytest.fixture
def headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {auth.create_token('admin')}"}


@pytest.fixture
def server_id() -> Iterator[int]:
    with database.get_connection() as conn:
        cur = conn.execute(
            "INSERT INTO servers (name, ip_address, port, status, token) VALUES ('maske-test', '192.168.99.88', 8000, 'offline', ?)",
            (TOKEN,),
        )
        sid = int(cur.lastrowid or 0)
    yield sid
    with database.get_connection() as conn:
        conn.execute("DELETE FROM servers WHERE id = ?", (sid,))


def _stored_token(sid: int) -> str:
    with database.get_connection() as conn:
        return str(conn.execute("SELECT token FROM servers WHERE id = ?", (sid,)).fetchone()["token"])


def test_server_list_masks_token(client: TestClient, headers: dict[str, str], server_id: int) -> None:
    body = client.get("/api/servers", headers=headers).text
    assert TOKEN not in body
    srv = next(s for s in client.get("/api/servers", headers=headers).json()["servers"] if s["id"] == server_id)
    assert srv["token"] == "********" + TOKEN[-4:]


def test_last_scan_masks_token(client: TestClient, headers: dict[str, str], server_id: int) -> None:
    resp = client.get(f"/api/servers/{server_id}/last-scan", headers=headers)
    assert resp.status_code == 200
    assert TOKEN not in resp.text
    assert resp.json()["server"]["token"] == "********" + TOKEN[-4:]


def test_masked_token_not_written_back(client: TestClient, headers: dict[str, str], server_id: int) -> None:
    resp = client.patch(f"/api/servers/{server_id}", json={"token": "********" + TOKEN[-4:]}, headers=headers)
    assert resp.status_code == 200
    assert _stored_token(server_id) == TOKEN


def test_new_token_still_saved(client: TestClient, headers: dict[str, str], server_id: int) -> None:
    client.patch(f"/api/servers/{server_id}", json={"token": "yepyeni-token-fedcba9876543210"}, headers=headers)
    assert _stored_token(server_id) == "yepyeni-token-fedcba9876543210"


def test_empty_token_masked_as_empty(client: TestClient, headers: dict[str, str], server_id: int) -> None:
    with database.get_connection() as conn:
        conn.execute("UPDATE servers SET token = '' WHERE id = ?", (server_id,))
    srv = next(s for s in client.get("/api/servers", headers=headers).json()["servers"] if s["id"] == server_id)
    assert srv["token"] == ""


@pytest.mark.parametrize("payload", [{"token": ""}, {"token": "   "}, {"name": "yeni-ad"}, {"token": None}])
def test_empty_token_keeps_existing(client: TestClient, headers: dict[str, str], server_id: int, payload: dict[str, object]) -> None:
    assert client.patch(f"/api/servers/{server_id}", json=payload, headers=headers).status_code == 200
    assert _stored_token(server_id) == TOKEN


def test_clear_token_removes_token(client: TestClient, headers: dict[str, str], server_id: int) -> None:
    resp = client.patch(f"/api/servers/{server_id}", json={"clear_token": True}, headers=headers)
    assert resp.status_code == 200
    assert _stored_token(server_id) == ""


def test_clear_token_with_masked_value_still_clears(client: TestClient, headers: dict[str, str], server_id: int) -> None:
    payload = {"token": "********" + TOKEN[-4:], "clear_token": True}
    assert client.patch(f"/api/servers/{server_id}", json=payload, headers=headers).status_code == 200
    assert _stored_token(server_id) == ""


def test_clear_token_with_new_token_rejected(client: TestClient, headers: dict[str, str], server_id: int) -> None:
    payload = {"token": "yepyeni-token-fedcba9876543210", "clear_token": True}
    assert client.patch(f"/api/servers/{server_id}", json=payload, headers=headers).status_code == 400
    assert _stored_token(server_id) == TOKEN
