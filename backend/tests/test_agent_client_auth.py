from __future__ import annotations

import socket
import ssl
import sys
import threading
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
import agent_client
import database
from light_agent import security
from tests.tls_certs import CERT_A, agent_tls_files

SECRET = "0123456789abcdef" * 4


AGENT_ID = "b" * 32


def _client(token: str = "", agent_id: str = AGENT_ID) -> agent_client.PuyadAgentClient:
    with patch.object(agent_client.config, "load_config", return_value={"AGENT_SHARED_SECRET": SECRET}):
        return agent_client.PuyadAgentClient(
            "10.0.0.5", 8000, token=token, agent_id=agent_id, cert_pem=CERT_A
        )


def _sent_urls(mock: MagicMock) -> list[str]:
    return [str(c.args[1]) for c in mock.call_args_list]


def _calls(mock: MagicMock, method: str) -> int:
    return sum(1 for c in mock.call_args_list if c.args[0] == method)


def _patch_request(status: int = 401) -> Any:
    return patch.object(agent_client.httpx.Client, "request", return_value=MagicMock(status_code=status))


@pytest.mark.parametrize("token", ["", "eski-token"])
def test_scan_401_returns_error_without_login(token: str) -> None:
    client = _client(token)
    with _patch_request() as req:
        res = client.trigger_remote_scan()
    assert res == {"success": False, "error": agent_client.AUTH_REJECTED_MESSAGE}
    assert not any("/api/auth/login" in u for u in _sent_urls(req))
    assert req.call_count == 1 and _calls(req, "GET") == 1


def test_fix_401_returns_error_without_login() -> None:
    client = _client()
    with _patch_request() as req:
        res = client.trigger_remote_fix("1.1.1")
    assert res == {"success": False, "error": agent_client.AUTH_REJECTED_MESSAGE}
    assert req.call_count == 1 and _calls(req, "POST") == 1
    assert not any("/api/auth/login" in u for u in _sent_urls(req))


def test_secret_never_sent_as_password() -> None:
    client = _client()
    with _patch_request() as req:
        client.trigger_remote_scan(rules=[{"id": "x"}])
        client.trigger_remote_fix("x")
    for c in req.call_args_list:
        body: Any = c.kwargs.get("json") or c.kwargs.get("content") or b""
        assert SECRET not in str(body)


def test_401_does_not_touch_stored_token() -> None:
    with database.get_connection() as conn:
        conn.execute(
            "INSERT INTO servers (name, ip_address, port, status, token) VALUES (?, ?, ?, ?, ?)",
            ("token-korunur-test", "10.0.0.5", 8000, "online", "elle-verilen-token"),
        )
    try:
        client = _client("elle-verilen-token")
        with _patch_request():
            client.trigger_remote_scan()
        with database.get_connection() as conn:
            row = conn.execute("SELECT token FROM servers WHERE name = ?", ("token-korunur-test",)).fetchone()
        assert row["token"] == "elle-verilen-token"
    finally:
        with database.get_connection() as conn:
            conn.execute("DELETE FROM servers WHERE name = ?", ("token-korunur-test",))


def test_unknown_agent_id_blocks_scan_and_fix() -> None:
    client = _client(agent_id="")
    with _patch_request() as req:
        assert client.trigger_remote_scan() == {"success": False, "error": agent_client.AGENT_ID_MISSING_MESSAGE}
        assert client.trigger_remote_fix("1.1.1") == {"success": False, "error": agent_client.AGENT_ID_MISSING_MESSAGE}
    assert req.call_count == 0


def test_unknown_agent_id_sends_unsigned_status_probe() -> None:
    client = _client(agent_id="")
    with _patch_request() as req:
        assert client.check_agent_status()["online"] is False
    assert not any(k.startswith("X-Puyad") for k in req.call_args.kwargs["headers"])


def test_signature_bound_to_target_agent() -> None:
    import agent_auth

    client = _client()
    with _patch_request() as req:
        client.trigger_remote_scan()
    hdrs = req.call_args.kwargs["headers"]
    for target, ok in ((AGENT_ID, True), ("c" * 32, False), (agent_auth.CONTROLLER_TARGET, False)):
        payload = agent_auth.signing_payload(
            hdrs["X-Puyad-Timestamp"], hdrs["X-Puyad-Nonce"], "GET", "/api/scan", b"", target
        )
        import hashlib
        import hmac

        expected = hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
        assert (expected == hdrs["X-Puyad-Signature"]) is ok


def _resolve_to(ip: str) -> list[tuple[Any, ...]]:
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 8000))]


def _hostname_client() -> agent_client.PuyadAgentClient:
    with patch.object(agent_client.config, "load_config", return_value={"AGENT_SHARED_SECRET": SECRET}):
        return agent_client.PuyadAgentClient("ajan.ornek.local", 8000, token="tkn", cert_pem=CERT_A)


def test_dns_rebinding_to_loopback_blocks_second_request() -> None:
    client = _hostname_client()
    resolver = MagicMock(side_effect=[_resolve_to("10.0.0.7"), _resolve_to("127.0.0.1")])
    with patch.object(agent_client.socket, "getaddrinfo", resolver), _patch_request(200) as req:
        assert client.check_agent_status()["online"] is True
        assert client.check_agent_status() == {"online": False, "error": "Bağlantı kurulamadı"}
    assert resolver.call_count == 2
    assert req.call_count == 1


def test_connects_to_resolved_ip_with_hostname_header_and_sni() -> None:
    client = _hostname_client()
    with patch.object(agent_client.socket, "getaddrinfo", return_value=_resolve_to("10.0.0.7")), \
            _patch_request(200) as req:
        client.trigger_remote_fix("1.1.1")
    method, url = req.call_args.args
    assert (method, url) == ("POST", "https://10.0.0.7:8000/api/fix/1.1.1")
    assert req.call_args.kwargs["headers"]["Host"] == "ajan.ornek.local:8000"
    assert req.call_args.kwargs["extensions"] == {"sni_hostname": "ajan.ornek.local"}


def test_unapproved_cert_blocks_all_requests() -> None:
    with patch.object(agent_client.config, "load_config", return_value={"AGENT_SHARED_SECRET": SECRET}):
        client = agent_client.PuyadAgentClient("10.0.0.5", 8000, agent_id=AGENT_ID)
    with _patch_request(200) as req:
        assert client.check_agent_status() == {"online": False, "error": agent_client.CERT_NOT_APPROVED_MESSAGE}
        assert client.trigger_remote_scan() == {"success": False, "error": agent_client.CERT_NOT_APPROVED_MESSAGE}
        assert client.trigger_remote_fix("x") == {"success": False, "error": agent_client.CERT_NOT_APPROVED_MESSAGE}
    assert req.call_count == 0


def _handshake(ctx: ssl.SSLContext, cert: Path, key: Path) -> None:
    server_ctx = security.server_context(cert, key)
    with socket.create_server(("127.0.0.1", 0)) as srv:
        port = srv.getsockname()[1]

        def serve() -> None:
            conn, _ = srv.accept()
            try:
                with server_ctx.wrap_socket(conn, server_side=True):
                    pass
            except (ssl.SSLError, OSError):
                pass

        t = threading.Thread(target=serve, daemon=True)
        t.start()
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=3) as raw:
                with ctx.wrap_socket(raw, server_hostname="10.0.0.5"):
                    pass
        finally:
            t.join(3)


def test_client_pins_agent_cert(tmp_path: Path) -> None:
    agent_cert, agent_key = (Path(p) for p in agent_tls_files())
    agent_pem = agent_cert.read_text()
    with patch.object(agent_client.config, "load_config", return_value={"AGENT_SHARED_SECRET": SECRET}):
        client = agent_client.PuyadAgentClient("10.0.0.5", 8000, agent_id=AGENT_ID, cert_pem=agent_pem)
    with patch.object(agent_client.httpx, "Client") as cls:
        cls.return_value.__enter__.return_value.request.return_value = MagicMock(status_code=200)
        client.trigger_remote_fix("x")
    ctx = cls.call_args.kwargs["verify"]
    assert isinstance(ctx, ssl.SSLContext)
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.get_ca_certs(binary_form=True) == [ssl.PEM_cert_to_DER_cert(agent_pem)]

    _handshake(ctx, agent_cert, agent_key)

    other_cert, other_key = tmp_path / "other.crt", tmp_path / "other.key"
    security.ensure_cert(other_cert, other_key)
    with pytest.raises(ssl.SSLCertVerificationError):
        _handshake(ctx, other_cert, other_key)


@pytest.mark.parametrize(
    ("status", "pem", "expected"),
    [("approved", CERT_A, CERT_A), ("pending", CERT_A, ""), ("", "", ""), ("approved", None, "")],
)
def test_approved_cert_pem(status: str, pem: str | None, expected: str) -> None:
    assert agent_client.approved_cert_pem({"agent_cert_status": status, "agent_cert_pem": pem}) == expected
