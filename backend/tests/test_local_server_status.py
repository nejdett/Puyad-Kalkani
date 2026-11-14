from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parent.parent))
import agent_client
import auth
import database
import main
from tests.tls_certs import CERT_A


def test_local_server_online_without_network_request() -> None:
    with database.get_connection() as conn:
        conn.execute("UPDATE servers SET status = 'offline' WHERE id = 1")
    with patch.object(agent_client, "PuyadAgentClient") as client_cls, \
            patch.object(agent_client.socket, "getaddrinfo") as resolve:
        client_cls.return_value.check_agent_status.return_value = {"online": False}
        resp = TestClient(main.app).get(
            "/api/servers/probe-all", headers={"Authorization": f"Bearer {auth.create_token('admin')}"}
        )
    assert resp.status_code == 200
    local = next(r for r in resp.json()["results"] if r["id"] == 1)
    assert local["status"] == "online"
    assert all(c.args[0] != "127.0.0.1" for c in client_cls.call_args_list)
    resolve.assert_not_called()
    with database.get_connection() as conn:
        assert conn.execute("SELECT status FROM servers WHERE id = 1").fetchone()[0] == "online"


def test_loopback_record_other_than_local_still_blocked() -> None:
    with database.get_connection() as conn:
        cur = conn.execute(
            "INSERT INTO servers (name, ip_address, port, status, agent_cert_pem, agent_cert_status) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ("sahte-yerel", "127.0.0.1", 8000, "online", CERT_A, "approved"),
        )
        fake_id = cur.lastrowid
    try:
        with patch.object(agent_client.httpx.Client, "request", return_value=MagicMock(status_code=503)) as request:
            results = agent_client.probe_all_servers()
        fake = next(r for r in results if r["id"] == fake_id)
        assert fake["status"] == "offline"
        assert all("127.0.0.1" not in str(c.args[1]) for c in request.call_args_list)
    finally:
        with database.get_connection() as conn:
            conn.execute("DELETE FROM servers WHERE id = ?", (fake_id,))
