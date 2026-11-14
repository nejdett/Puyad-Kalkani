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
import tlsutil
from tests.tls_certs import CERT_A, CERT_B

AGENT_IP = "192.168.77.10"
PORT = 8123


@pytest.fixture
def client() -> TestClient:
    return TestClient(main.app, client=(AGENT_IP, 50000))


@pytest.fixture
def headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {auth.create_token('admin')}"}


@pytest.fixture(autouse=True)
def clean_server() -> Iterator[None]:
    yield
    with database.get_connection() as conn:
        conn.execute("DELETE FROM servers WHERE ip_address = ?", (AGENT_IP,))


def _beat(client: TestClient, headers: dict[str, str], pem: str | None) -> int:
    body: dict[str, object] = {"port": PORT, "hostname": "ajan"}
    if pem is not None:
        body["cert_pem"] = pem
    return client.post("/api/servers/heartbeat", json=body, headers=headers).status_code


def _row() -> dict[str, object]:
    with database.get_connection() as conn:
        row = conn.execute("SELECT * FROM servers WHERE ip_address = ? AND port = ?", (AGENT_IP, PORT)).fetchone()
    return dict(row)


def _approve(client: TestClient, headers: dict[str, str], fp: str) -> int:
    sid = _row()["id"]
    return client.post(f"/api/servers/{sid}/cert/approve", json={"fingerprint": fp}, headers=headers).status_code


def test_first_heartbeat_stores_pending_cert(client: TestClient, headers: dict[str, str]) -> None:
    assert _beat(client, headers, CERT_A) == 200
    row = _row()
    assert row["agent_cert_status"] == "pending" and row["agent_cert_pem"] == CERT_A.strip()
    listed = [s for s in client.get("/api/servers", headers=headers).json()["servers"] if s["id"] == row["id"]][0]
    assert listed["agent_cert_fingerprint"] == tlsutil.fingerprint(CERT_A)
    assert "agent_cert_pem" not in listed


def test_pending_cert_can_be_replaced(client: TestClient, headers: dict[str, str]) -> None:
    _beat(client, headers, CERT_A)
    assert _beat(client, headers, CERT_B) == 200
    assert _row()["agent_cert_pem"] == CERT_B.strip()


def test_approve_requires_current_fingerprint(client: TestClient, headers: dict[str, str]) -> None:
    _beat(client, headers, CERT_A)
    assert _approve(client, headers, tlsutil.fingerprint(CERT_B)) == 409
    assert _row()["agent_cert_status"] == "pending"
    assert _approve(client, headers, tlsutil.fingerprint(CERT_A)) == 200
    assert _row()["agent_cert_status"] == "approved"


def test_approved_cert_change_rejected(client: TestClient, headers: dict[str, str]) -> None:
    _beat(client, headers, CERT_A)
    _approve(client, headers, tlsutil.fingerprint(CERT_A))
    assert _beat(client, headers, CERT_B) == 409
    row = _row()
    assert row["agent_cert_pem"] == CERT_A.strip() and row["agent_cert_status"] == "approved"
    assert _beat(client, headers, CERT_A) == 200


def test_reset_allows_new_cert(client: TestClient, headers: dict[str, str]) -> None:
    _beat(client, headers, CERT_A)
    _approve(client, headers, tlsutil.fingerprint(CERT_A))
    sid = _row()["id"]
    assert client.delete(f"/api/servers/{sid}/cert", headers=headers).status_code == 200
    assert _beat(client, headers, CERT_B) == 200
    row = _row()
    assert row["agent_cert_pem"] == CERT_B.strip() and row["agent_cert_status"] == "pending"


def test_invalid_pem_rejected(client: TestClient, headers: dict[str, str]) -> None:
    assert _beat(client, headers, "-----BEGIN CERTIFICATE-----\nbozuk\n-----END CERTIFICATE-----") == 422


def test_approve_without_cert(client: TestClient, headers: dict[str, str]) -> None:
    _beat(client, headers, None)
    assert _approve(client, headers, "0" * 64) == 400


def test_cert_endpoints_require_auth(client: TestClient) -> None:
    assert client.post("/api/servers/1/cert/approve", json={"fingerprint": "0" * 64}).status_code == 401
    assert client.delete("/api/servers/1/cert").status_code == 401
    assert client.get("/api/agent/install-command", params={"host": "10.0.0.1:8000"}).status_code == 401


@pytest.mark.skipif(not tlsutil.shutil.which("openssl"), reason="openssl yok")
def test_install_command(
    client: TestClient, headers: dict[str, str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cert, key = tmp_path / "c.crt", tmp_path / "c.key"
    tlsutil.generate_self_signed(cert, key, "puyad-controller")
    monkeypatch.setenv("PUYAD_TLS_CERT", str(cert))
    monkeypatch.setenv("PUYAD_TLS_KEY", str(key))
    resp = client.get("/api/agent/install-command", params={"host": "10.0.0.1:8000"}, headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["pin"] == tlsutil.spki_pin(cert)
    assert data["fingerprint"] == tlsutil.fingerprint(cert.read_text())
    assert f"--pinnedpubkey '{data['pin']}' https://10.0.0.1:8000/api/agent/update.sh" in data["command"]
    bad = client.get("/api/agent/install-command", params={"host": "x;id"}, headers=headers)
    assert bad.status_code == 422
