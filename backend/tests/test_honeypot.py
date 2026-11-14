from __future__ import annotations

import os
import socket
import subprocess
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
import auth
import honeypot


class TestCheckPortStatus:
    def test_invalid_ports(self) -> None:
        res_zero = honeypot.check_port_status(0)
        assert res_zero["status"] == "invalid"
        assert res_zero["can_bind"] is False

        res_neg = honeypot.check_port_status(-5)
        assert res_neg["status"] == "invalid"
        assert res_neg["can_bind"] is False

        res_over = honeypot.check_port_status(70000)
        assert res_over["status"] == "invalid"
        assert res_over["can_bind"] is False

    def test_privileged_flag(self) -> None:
        chk_priv = honeypot.check_port_status(21)
        assert chk_priv["is_privileged"] is True

        chk_non_priv = honeypot.check_port_status(9999)
        assert chk_non_priv["is_privileged"] is False

    def test_available_port(self) -> None:
        with patch("subprocess.run") as mock_ss, patch("socket.socket") as mock_sock_cls:
            mock_ss.return_value = subprocess.CompletedProcess(
                args=["ss"], returncode=0, stdout="State Recv-Q Send-Q\n"
            )
            mock_sock = MagicMock()
            mock_sock_cls.return_value = mock_sock

            res = honeypot.check_port_status(21)
            assert res["status"] == "available"
            assert res["can_bind"] is True
            assert res["is_active"] is False
            assert "deaktif" in res["message"].lower()

    def test_occupied_port(self) -> None:
        with patch("subprocess.run") as mock_ss, patch("socket.socket") as mock_sock_cls:
            ss_out = (
                "State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n"
                'LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1234,fd=3))\n'
            )
            mock_ss.return_value = subprocess.CompletedProcess(
                args=["ss"], returncode=0, stdout=ss_out
            )
            mock_sock = MagicMock()
            mock_sock.bind.side_effect = OSError(98, "Address already in use")
            mock_sock_cls.return_value = mock_sock

            res = honeypot.check_port_status(22)
            assert res["status"] == "active"
            assert res["is_active"] is True
            assert res["can_bind"] is False
            assert res["service_name"] == "sshd"
            assert res["pid"] == 1234
            assert "aktif" in res["message"].lower()

    def test_permission_denied_port(self) -> None:
        with patch("subprocess.run") as mock_ss, patch("socket.socket") as mock_sock_cls:
            mock_ss.return_value = subprocess.CompletedProcess(
                args=["ss"], returncode=0, stdout=""
            )
            mock_sock = MagicMock()
            mock_sock.bind.side_effect = PermissionError("Permission denied")
            mock_sock_cls.return_value = mock_sock

            res = honeypot.check_port_status(80)
            assert res["status"] == "permission_denied"
            assert res["can_bind"] is False
            assert res["is_privileged"] is True
            assert "root yetkisi" in res["message"].lower()

    def test_honeypot_active_status(self) -> None:
        with honeypot._lock:
            honeypot._active_pots[9998] = {
                "thread": MagicMock(),
                "stop_event": MagicMock(),
                "server": None,
                "config": {
                    "port": 9998,
                    "service": "telnet",
                    "label": "Test Tuzağı",
                    "active": True,
                },
            }
        try:
            res = honeypot.check_port_status(9998)
            assert res["status"] == "honeypot_active"
            assert res["is_active"] is True
            assert res["can_bind"] is False
            assert "puyad honeypot" in res["message"].lower()
        finally:
            with honeypot._lock:
                honeypot._active_pots.pop(9998, None)


class TestStartAndStopHoneypot:
    def test_start_invalid_service(self) -> None:
        res = honeypot.start_honeypot(8888, "unsupported_service")
        assert res["success"] is False
        assert "geçersiz servis" in res["message"].lower()

    def test_start_occupied_port_rejected(self) -> None:
        with patch("honeypot.check_port_status") as mock_chk:
            mock_chk.return_value = {
                "port": 80,
                "status": "active",
                "can_bind": False,
                "message": "Port 80 sistemde aktif olarak dinleniyor (nginx).",
            }
            res = honeypot.start_honeypot(80, "http")
            assert res["success"] is False
            assert "aktif" in res["message"].lower()

    def test_start_and_stop_flow(self) -> None:
        test_port = 19123
        with patch("honeypot.check_port_status") as mock_chk, patch("honeypot._server_loop"):
            mock_chk.return_value = {
                "port": test_port,
                "status": "available",
                "can_bind": True,
                "is_privileged": False,
                "message": f"Port {test_port} deaktif (boşta).",
            }
            res_start = honeypot.start_honeypot(test_port, "custom", "Birim Testi")
            assert res_start["success"] is True
            assert test_port in honeypot._active_pots

            active_list = honeypot.list_active()
            assert any(p["port"] == test_port for p in active_list)

            res_stop = honeypot.stop_honeypot(test_port)
            assert res_stop["success"] is True
            assert test_port not in honeypot._active_pots

    def test_stop_nonexistent_port(self) -> None:
        res = honeypot.stop_honeypot(64321)
        assert res["success"] is False
        assert "aktif değil" in res["message"].lower()


class TestHoneypotApiEndpoints:
    @pytest.fixture
    def test_client(self) -> Any:
        from fastapi.testclient import TestClient
        import main
        return TestClient(main.app)

    @pytest.fixture
    def auth_headers(self) -> dict[str, str]:
        token = auth.create_token("admin")
        return {"Authorization": f"Bearer {token}"}

    def test_check_port_endpoint(self, test_client: Any, auth_headers: dict[str, str]) -> None:
        with patch("honeypot.check_port_status") as mock_chk:
            mock_chk.return_value = {
                "port": 21,
                "status": "available",
                "is_active": False,
                "can_bind": True,
                "is_privileged": True,
                "message": "Port 21 deaktif (boşta).",
            }
            resp = test_client.get("/api/honeypot/check-port/21", headers=auth_headers)
            assert resp.status_code == 200
            data = resp.json()
            assert data["port"] == 21
            assert data["status"] == "available"

    def test_check_port_invalid_range(self, test_client: Any, auth_headers: dict[str, str]) -> None:
        resp = test_client.get("/api/honeypot/check-port/0", headers=auth_headers)
        assert resp.status_code == 400

    def test_start_honeypot_allows_privileged_port(self, test_client: Any, auth_headers: dict[str, str]) -> None:
        with patch("honeypot.start_honeypot") as mock_start:
            mock_start.return_value = {
                "success": True,
                "message": "Port 21 (FTP) honeypot olarak aktif edildi. Port deaktif/boşta doğrulandı.",
                "port": 21,
                "service": "ftp",
            }
            resp = test_client.post(
                "/api/honeypot/start",
                json={"port": 21, "service": "ftp", "label": "FTP Tuzağı"},
                headers=auth_headers,
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["success"] is True
            assert data["port"] == 21

    def test_start_honeypot_occupied_error(self, test_client: Any, auth_headers: dict[str, str]) -> None:
        with patch("honeypot.start_honeypot") as mock_start:
            mock_start.return_value = {
                "success": False,
                "message": "Port 8000 sistemde aktif olarak dinleniyor (uvicorn). Çakışmayı önlemek için honeypot kurulamaz.",
            }
            resp = test_client.post(
                "/api/honeypot/start",
                json={"port": 8000, "service": "http", "label": "HTTP"},
                headers=auth_headers,
            )
            assert resp.status_code == 400
            assert "aktif" in resp.json()["detail"].lower()


@pytest.mark.parametrize("sep", ["\n", "\r", "\x1b", "\x85", "\u2028", "\u2029", "\x00", "\u200b"])
def test_hit_log_strips_line_breaking_characters(sep: str, caplog: pytest.LogCaptureFixture) -> None:
    payload = f"GET /{sep}HONEYPOT HIT | Port: 1 (SAHTE) | Source: 10.9.9.9:1"
    sock = MagicMock()
    sock.recv.return_value = payload.encode("utf-8")
    with patch.object(honeypot, "_log_hit"), patch.object(honeypot, "_should_run_forensic", return_value=False), \
            caplog.at_level("WARNING", logger="honeypot"):
        honeypot._handle_connection(sock, ("203.0.113.5", 40000), 2222, "ssh")
    msgs = [r.getMessage() for r in caplog.records if "HONEYPOT HIT" in r.getMessage()]
    assert len(msgs) == 1
    assert len(msgs[0].splitlines()) == 1
    assert all(c.isprintable() for c in msgs[0])
    assert "Veri: GET / HONEYPOT HIT" in msgs[0]
