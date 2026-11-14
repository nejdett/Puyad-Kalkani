from __future__ import annotations

import socket
import sys
from pathlib import Path
from typing import Any
from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parent.parent))
import agent_client
import auth
import database
import main


@pytest.fixture
def client() -> TestClient:
    return TestClient(main.app)


@pytest.fixture
def headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {auth.create_token('admin')}"}


@pytest.fixture(autouse=True)
def no_probe() -> Any:
    with patch.object(agent_client.PuyadAgentClient, "check_agent_status", return_value={"online": False}) as probe:
        yield probe


def _cleanup(ip: str) -> None:
    with database.get_connection() as conn:
        conn.execute("DELETE FROM servers WHERE ip_address = ? AND id != 1", (ip,))


def _resolve_to(ip: str) -> list[tuple[Any, ...]]:
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    return [(family, socket.SOCK_STREAM, 6, "", (ip, 0))]


@pytest.mark.parametrize("ip", [
    "127.0.0.1", "127.8.9.10", "::1", "::ffff:127.0.0.1",
    "169.254.169.254", "169.254.1.1", "fe80::1", "0.0.0.0", "::",
])
def test_blocked_ip_rejected(ip: str, client: TestClient, headers: dict[str, str], no_probe: Any) -> None:
    resp = client.post("/api/servers", json={"name": f"blok-{ip}", "ip_address": ip}, headers=headers)
    assert resp.status_code == 422
    assert "eklenemez" in resp.json()["detail"]
    no_probe.assert_not_called()


@pytest.mark.parametrize("ip", ["10.1.2.3", "172.16.5.5", "192.168.1.20", "8.8.8.8"])
def test_private_and_public_ip_allowed(ip: str, client: TestClient, headers: dict[str, str]) -> None:
    try:
        resp = client.post("/api/servers", json={"name": f"izin-{ip}", "ip_address": ip}, headers=headers)
        assert resp.status_code == 200
        assert resp.json()["success"] is True
    finally:
        _cleanup(ip)


@pytest.mark.parametrize("resolved", ["127.0.0.1", "169.254.169.254", "::1"])
def test_hostname_resolving_to_blocked_ip_rejected(resolved: str, client: TestClient, headers: dict[str, str],
                                                   no_probe: Any) -> None:
    with patch.object(main.socket, "getaddrinfo", return_value=_resolve_to(resolved)):
        resp = client.post("/api/servers", json={"name": "kotu-host", "ip_address": "ajan.example"}, headers=headers)
    assert resp.status_code == 422
    assert "eklenemez" in resp.json()["detail"]
    no_probe.assert_not_called()


def test_hostname_with_any_blocked_record_rejected(client: TestClient, headers: dict[str, str]) -> None:
    records = _resolve_to("192.168.1.30") + _resolve_to("127.0.0.1")
    with patch.object(main.socket, "getaddrinfo", return_value=records):
        resp = client.post("/api/servers", json={"name": "karisik", "ip_address": "ajan.example"}, headers=headers)
    assert resp.status_code == 422


def test_hostname_resolving_to_private_ip_allowed(client: TestClient, headers: dict[str, str]) -> None:
    try:
        with patch.object(main.socket, "getaddrinfo", return_value=_resolve_to("192.168.1.40")):
            resp = client.post("/api/servers", json={"name": "ic-ajan", "ip_address": "ajan.lan"}, headers=headers)
        assert resp.status_code == 200
    finally:
        _cleanup("ajan.lan")


def test_unresolvable_hostname_rejected(client: TestClient, headers: dict[str, str]) -> None:
    with patch.object(main.socket, "getaddrinfo", side_effect=socket.gaierror("yok")):
        resp = client.post("/api/servers", json={"name": "yok", "ip_address": "yok.invalid"}, headers=headers)
    assert resp.status_code == 422
    assert "çözümlenemedi" in resp.json()["detail"]
