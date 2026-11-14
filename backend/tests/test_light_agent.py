from __future__ import annotations

import json
import shutil
import ssl
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
import sys
import pytest
from starlette.requests import Request

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT_DIR / "backend"))
sys.path.insert(0, str(ROOT_DIR))

from light_agent import collector, security
from light_agent.agent import AgentConfig, PuyadAgentServer
import main
import database

AGENT_ID = "a1b2c3d4e5f60718293a4b5c6d7e8f90"
FP = "ab" * 32

needs_openssl = pytest.mark.skipif(not shutil.which("openssl"), reason="openssl yok")


def _trusting_context(cert_pem: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.load_verify_locations(cadata=cert_pem)
    return ctx


class TestLightAgentAuth:

    def setup_method(self) -> None:
        security.reset_nonce_cache()

    def test_build_headers_format(self) -> None:
        headers = security.build_headers("b" * 64, "GET", "/api/health", target=AGENT_ID)
        assert "X-Puyad-Timestamp" in headers
        assert "X-Puyad-Nonce" in headers
        assert "X-Puyad-Signature" in headers
        assert len(headers["X-Puyad-Signature"]) == 64

    def test_verify_request_hmac_success(self) -> None:
        secret = "a" * 64
        headers = security.build_headers(secret, "GET", "/api/health", target=AGENT_ID)
        ok, reason = security.verify_request(headers, "GET", "/api/health", secret=secret, agent_id=AGENT_ID)
        assert ok is True
        assert reason == ""

    def test_verify_request_bearer_token(self) -> None:
        token = "d" * 64
        headers = {"Authorization": f"Bearer {token}"}
        ok, reason = security.verify_request(headers, "GET", "/api/health", token=token)
        assert ok is True
        assert reason == ""

        bad_headers = {"Authorization": "Bearer wrong-token"}
        ok, reason = security.verify_request(bad_headers, "GET", "/api/health", token=token)
        assert ok is False
        assert "geçersiz" in reason.lower()

    def test_verify_request_nonce_replay(self) -> None:
        secret = "b" * 64
        headers = security.build_headers(secret, "GET", "/api/health", target=AGENT_ID)
        ok1, _ = security.verify_request(headers, "GET", "/api/health", secret=secret, agent_id=AGENT_ID)
        assert ok1 is True
        ok2, reason2 = security.verify_request(headers, "GET", "/api/health", secret=secret, agent_id=AGENT_ID)
        assert ok2 is False
        assert "nonce" in reason2.lower()

    def test_verify_request_expired_timestamp(self) -> None:
        secret = "b" * 64
        headers = security.build_headers(secret, "GET", "/api/health", target=AGENT_ID)
        headers["X-Puyad-Timestamp"] = str(int(time.time()) - 400)
        ok, reason = security.verify_request(headers, "GET", "/api/health", secret=secret, agent_id=AGENT_ID)
        assert ok is False
        assert "zaman aşımı" in reason.lower()

    def test_verify_request_tampered_sig(self) -> None:
        secret = "b" * 64
        headers = security.build_headers(secret, "GET", "/api/health", target=AGENT_ID)
        headers["X-Puyad-Signature"] = "0" * 64
        ok, reason = security.verify_request(headers, "GET", "/api/health", secret=secret, agent_id=AGENT_ID)
        assert ok is False
        assert "geçersiz" in reason.lower()

    def test_verify_request_body_bound(self) -> None:
        secret = "b" * 64
        body = b'{"fix_command": "id"}'
        headers = security.build_headers(secret, "POST", "/api/fix/r1", body, target=AGENT_ID)
        assert security.verify_request(headers, "POST", "/api/fix/r1", b'{"fix_command": "rm -rf /"}', secret=secret, agent_id=AGENT_ID)[0] is False
        assert security.verify_request(headers, "POST", "/api/fix/r1", body, secret=secret, agent_id=AGENT_ID) == (True, "")

    def test_verify_request_bodyless_signature_rejected(self) -> None:
        secret = "b" * 64
        headers = security.build_headers(secret, "POST", "/api/update/agent.py", target=AGENT_ID)
        ok, _ = security.verify_request(headers, "POST", "/api/update/agent.py", b"print(1)", secret=secret, agent_id=AGENT_ID)
        assert ok is False

    def test_verify_request_other_path_rejected(self) -> None:
        secret = "b" * 64
        headers = security.build_headers(secret, "POST", "/api/fix/r1", b"{}", target=AGENT_ID)
        ok, reason = security.verify_request(headers, "POST", "/api/update/agent.py", b"{}", secret=secret, agent_id=AGENT_ID)
        assert ok is False
        assert "imza" in reason.lower()

    def test_verify_request_old_v1_rejected(self) -> None:
        import hashlib
        import hmac

        secret = "b" * 64
        ts, nonce = str(int(time.time())), "f" * 16
        for payload in (f"{ts}.{nonce}.POST./api/fix/r1.{{}}", f"{ts}.{nonce}.POST./api/fix/r1.", f"{ts}.{nonce}.POST./api/fix/r1"):
            sig = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
            headers = {"X-Puyad-Timestamp": ts, "X-Puyad-Nonce": nonce, "X-Puyad-Signature": sig}
            assert security.verify_request(headers, "POST", "/api/fix/r1", b"{}", secret=secret, agent_id=AGENT_ID)[0] is False

    def test_invalid_signature_does_not_consume_nonce(self) -> None:
        secret = "b" * 64
        headers = security.build_headers(secret, "GET", "/api/status", target=AGENT_ID)
        forged = dict(headers, **{"X-Puyad-Signature": "0" * 64})
        assert security.verify_request(forged, "GET", "/api/status", secret=secret, agent_id=AGENT_ID)[0] is False
        assert security.verify_request(headers, "GET", "/api/status", secret=secret, agent_id=AGENT_ID) == (True, "")

    def test_full_nonce_cache_rejects_without_evicting(self, monkeypatch: pytest.MonkeyPatch) -> None:
        secret = "b" * 64
        monkeypatch.setattr(security, "_NONCE_MAX", 1)
        first = security.build_headers(secret, "GET", "/api/status", target=AGENT_ID)
        assert security.verify_request(first, "GET", "/api/status", secret=secret, agent_id=AGENT_ID)[0] is True
        ok, reason = security.verify_request(security.build_headers(secret, "GET", "/api/status", target=AGENT_ID), "GET", "/api/status", secret=secret, agent_id=AGENT_ID)
        assert ok is False
        assert "kapasite" in reason.lower()
        assert "replay" in security.verify_request(first, "GET", "/api/status", secret=secret, agent_id=AGENT_ID)[1].lower()

    def test_signature_for_other_agent_rejected(self) -> None:
        secret = "b" * 64
        headers = security.build_headers(secret, "POST", "/api/fix/r1", b"{}", target="f" * 32)
        ok, reason = security.verify_request(headers, "POST", "/api/fix/r1", b"{}", secret=secret, agent_id=AGENT_ID)
        assert ok is False
        assert "imza" in reason.lower()
        controller_sig = security.build_headers(secret, "POST", "/api/fix/r1", b"{}")
        assert security.verify_request(controller_sig, "POST", "/api/fix/r1", b"{}", secret=secret, agent_id=AGENT_ID)[0] is False

    def test_missing_agent_id_rejects_hmac(self) -> None:
        secret = "b" * 64
        headers = security.build_headers(secret, "GET", "/api/status", target=AGENT_ID)
        ok, reason = security.verify_request(headers, "GET", "/api/status", secret=secret)
        assert ok is False
        assert "agent_id" in reason

    def test_old_v2_signature_rejected(self) -> None:
        import hashlib
        import hmac

        secret = "b" * 64
        ts, nonce = str(int(time.time())), "e" * 16
        payload = f"v2.{ts}.{nonce}.POST./api/fix/r1.{hashlib.sha256(b'{}').hexdigest()}"
        sig = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
        headers = {"X-Puyad-Timestamp": ts, "X-Puyad-Nonce": nonce, "X-Puyad-Signature": sig}
        assert security.verify_request(headers, "POST", "/api/fix/r1", b"{}", secret=secret, agent_id=AGENT_ID)[0] is False

    @pytest.mark.parametrize("sig", ["ç" * 64, "\udcff" * 64, "A" * 64, "0" * 63])
    def test_malformed_signature_rejected_without_error(self, sig: str) -> None:
        secret = "b" * 64
        headers = dict(security.build_headers(secret, "GET", "/api/status", target=AGENT_ID), **{"X-Puyad-Signature": sig})
        assert security.verify_request(headers, "GET", "/api/status", secret=secret, agent_id=AGENT_ID) == (False, "Geçersiz agent imzası.")

    def test_non_ascii_bearer_token_rejected_without_error(self) -> None:
        ok, reason = security.verify_request({"Authorization": "Bearer çğü"}, "GET", "/api/status", token="t" * 40)
        assert ok is False
        assert "token" in reason.lower()


class TestLightAgentId:

    def test_generated_and_persisted(self, tmp_path: Path) -> None:
        cpath = tmp_path / "config.json"
        cpath.write_text(json.dumps({"secret": "s" * 64}))
        first = AgentConfig.load(str(cpath))
        assert security.AGENT_ID_RE.fullmatch(first.agent_id)
        stored = json.loads(cpath.read_text())
        assert stored == {"secret": "s" * 64, "agent_id": first.agent_id}
        assert cpath.stat().st_mode & 0o777 == 0o600
        assert AgentConfig.load(str(cpath)).agent_id == first.agent_id

    def test_created_when_config_missing(self, tmp_path: Path) -> None:
        cpath = tmp_path / "config.json"
        cfg = AgentConfig.load(str(cpath))
        assert json.loads(cpath.read_text()) == {"agent_id": cfg.agent_id}

    def test_corrupt_config_not_overwritten(self, tmp_path: Path) -> None:
        cpath = tmp_path / "config.json"
        cpath.write_text("{bozuk")
        cfg = AgentConfig.load(str(cpath))
        assert security.AGENT_ID_RE.fullmatch(cfg.agent_id)
        assert cpath.read_text() == "{bozuk"

    def test_heartbeat_carries_agent_id_and_cert(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        cert = tmp_path / "agent.crt"
        cert.write_text("PEM")
        cfg = AgentConfig(
            controller="https://127.0.0.1:1", secret="s" * 64, agent_id=AGENT_ID,
            controller_fingerprint=FP, cert_file=str(cert),
        )
        server = PuyadAgentServer.__new__(PuyadAgentServer)
        server.agent_config = cfg
        captured: dict[str, Any] = {}

        def fake_open(req: urllib.request.Request, fingerprint: str, timeout: float) -> Any:
            captured["body"] = json.loads(req.data)  # type: ignore[arg-type]
            captured["fingerprint"] = fingerprint
            raise OSError("bağlantı yok")

        monkeypatch.setattr(security, "controller_open", fake_open)
        assert server.send_heartbeat() is False
        assert captured["body"]["agent_id"] == AGENT_ID
        assert captured["body"]["cert_pem"] == "PEM"
        assert captured["fingerprint"] == FP

    def test_fingerprint_loaded_from_config(self, tmp_path: Path) -> None:
        cpath = tmp_path / "config.json"
        cpath.write_text(json.dumps({"controller": "https://10.0.0.1:8000/", "controller_fingerprint": FP.upper()}))
        cfg = AgentConfig.load(str(cpath))
        assert cfg.controller == "https://10.0.0.1:8000"
        assert cfg.controller_fingerprint == FP


class TestAgentTLS:

    @pytest.mark.parametrize(
        ("url", "fp", "ok"),
        [
            ("https://10.0.0.1:8000", FP, True),
            ("http://10.0.0.1:8000", FP, False),
            ("https://10.0.0.1:8000", "", False),
            ("https://10.0.0.1:8000", "zz" * 32, False),
        ],
    )
    def test_controller_problem(self, url: str, fp: str, ok: bool) -> None:
        assert (security.controller_problem(url, fp) == "") is ok

    def test_controller_open_refuses_http(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def no_network(*_a: Any, **_k: Any) -> Any:
            raise AssertionError("ağa çıkılmamalı")

        monkeypatch.setattr(urllib.request.OpenerDirector, "open", no_network)
        req = urllib.request.Request("http://10.0.0.1:8000/api/rules")
        with pytest.raises(security.ControllerPinError, match="https"):
            security.controller_open(req, FP, timeout=1)

    def test_missing_openssl(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(security.shutil, "which", lambda _n: None)
        with pytest.raises(security.TLSSetupError, match="openssl bulunamadı"):
            security.ensure_cert(tmp_path / "a.crt", tmp_path / "a.key")
        assert not (tmp_path / "a.key").exists()

    @needs_openssl
    def test_ensure_cert_once(self, tmp_path: Path) -> None:
        cert, key = tmp_path / "a.crt", tmp_path / "a.key"
        security.ensure_cert(cert, key)
        assert key.stat().st_mode & 0o777 == 0o600
        first = cert.read_text()
        security.ensure_cert(cert, key)
        assert cert.read_text() == first
        assert len(security.cert_fingerprint(first)) == 64

    def test_prepare_tls_rejects_http_controller(self, tmp_path: Path) -> None:
        from light_agent import agent

        cfg = AgentConfig(controller="http://10.0.0.1:8000", controller_fingerprint=FP, cert_file=str(tmp_path / "c"))
        assert "https://" in agent.prepare_tls(cfg)
        assert not (tmp_path / "c").exists()

    @needs_openssl
    def test_controller_open_does_not_follow_http_redirect(self, tmp_path: Path) -> None:
        import http.server
        import socket

        sink = socket.socket()
        sink.bind(("127.0.0.1", 0))
        sink.listen(1)
        sink.settimeout(0.5)
        sink_port = sink.getsockname()[1]
        seen: list[dict[str, str]] = []

        class Redirect(http.server.BaseHTTPRequestHandler):

            def do_GET(self) -> None:
                seen.append(dict(self.headers))
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.1:{sink_port}/api/rules")
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *_a: Any) -> None:
                pass

        cert, key = tmp_path / "c.crt", tmp_path / "c.key"
        security.ensure_cert(cert, key)
        httpd = http.server.HTTPServer(("127.0.0.1", 0), Redirect)
        httpd.socket = security.server_context(cert, key).wrap_socket(httpd.socket, server_side=True)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        headers = security.build_headers("c" * 64, "GET", "/api/rules", target=AGENT_ID)
        headers["Authorization"] = "Bearer gizli"
        req = urllib.request.Request(f"https://127.0.0.1:{httpd.server_port}/api/rules", headers=headers)
        try:
            with pytest.raises(urllib.error.HTTPError) as exc_info:
                security.controller_open(req, security.cert_fingerprint(cert.read_text()), timeout=3)
            assert exc_info.value.code == 302
            with pytest.raises(socket.timeout):
                sink.accept()
        finally:
            httpd.shutdown()
            httpd.server_close()
            sink.close()
        assert len(seen) == 1
        assert seen[0].get("Authorization") == "Bearer gizli"


class TestLightAgentCollector:

    def test_get_system_info(self) -> None:
        info = collector.get_system_info()
        assert "hostname" in info
        assert "os" in info
        assert "kernel" in info
        assert "uptime_seconds" in info
        assert "uptime_human" in info
        assert "memory" in info
        assert isinstance(info["cpu_count"], int)
        assert info["cpu_count"] >= 1

    def test_get_active_connections(self) -> None:
        conns = collector.get_active_connections()
        assert "total" in conns
        assert "established_count" in conns
        assert "listening_count" in conns
        assert "connections" in conns
        assert isinstance(conns["connections"], list)

    def test_run_basic_audit(self) -> None:
        audit = collector.run_basic_audit()
        assert "summary" in audit
        assert "results" in audit
        assert audit["summary"]["total"] == 0

    def test_audit_rules(self) -> None:
        rules = [
            {"id": "r1", "check_command": "echo OK"},
            {"id": "r2", "check_command": "echo FAIL"},
        ]
        audit = collector.audit_rules(rules)
        assert audit["summary"]["total"] == 2
        assert audit["summary"]["ok"] == 1
        assert audit["summary"]["warnings"] == 1
        assert audit["summary"]["score"] == 50

    def test_check_rule_outcomes(self) -> None:
        r_ok = collector.check_rule({"id": "t1", "check_command": "echo OK"})
        assert r_ok["status"] == "ok"

        r_warn = collector.check_rule({"id": "t2", "check_command": "echo FAIL"})
        assert r_warn["status"] == "warning"

        r_empty = collector.check_rule({"id": "t3", "check_command": ""})
        assert r_empty["status"] == "warning"


@needs_openssl
class TestLightAgentServer:

    @classmethod
    def setup_class(cls) -> None:
        cls.port = 18991
        cls.secret = "c" * 64
        cls.tls_dir = Path(tempfile.mkdtemp())
        cert, key = cls.tls_dir / "agent.crt", cls.tls_dir / "agent.key"
        security.ensure_cert(cert, key)
        cls.cert_pem = cert.read_text()
        cls.ctx = _trusting_context(cls.cert_pem)
        cls.cfg = AgentConfig(
            host="127.0.0.1", port=cls.port, secret=cls.secret, agent_id=AGENT_ID,
            cert_file=str(cert), key_file=str(key),
        )
        cls.server = PuyadAgentServer(cls.cfg)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        time.sleep(0.3)

    @classmethod
    def teardown_class(cls) -> None:
        cls.server.shutdown_cleanly()
        cls.server.server_close()
        shutil.rmtree(cls.tls_dir, ignore_errors=True)

    def test_plain_http_not_served(self) -> None:
        import http.client

        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            with pytest.raises((http.client.HTTPException, OSError)):
                conn.request("GET", "/api/health")
                conn.getresponse()
        finally:
            conn.close()

    def test_controller_open_accepts_matching_pin(self) -> None:
        fp = security.cert_fingerprint(self.cert_pem)
        req = urllib.request.Request(f"https://127.0.0.1:{self.port}/api/health")
        # 401 TLS'in geçtiğini gösteriyor, istek imzasız
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            security.controller_open(req, fp, timeout=3)
        assert exc_info.value.code == 401

    def test_controller_open_rejects_other_pin(self) -> None:
        req = urllib.request.Request(f"https://127.0.0.1:{self.port}/api/health")
        with pytest.raises(security.ControllerPinError, match="uyuşmuyor"):
            security.controller_open(req, "0" * 64, timeout=3)

    def test_health_with_valid_hmac(self) -> None:
        url = f"https://127.0.0.1:{self.port}/api/health"
        headers = security.build_headers(self.secret, "GET", "/api/health", target=AGENT_ID)
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=3, context=self.ctx) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            assert data["status"] == "ok"
            assert data["mode"] == "light_agent"
            assert "hostname" in data
            assert "active_connections" in data

    def test_health_unauthorized_when_secret_set(self) -> None:
        url = f"https://127.0.0.1:{self.port}/api/health"
        req = urllib.request.Request(url)
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req, timeout=3, context=self.ctx)
        assert exc_info.value.code == 401

    def test_status_endpoint(self) -> None:
        url = f"https://127.0.0.1:{self.port}/api/status"
        headers = security.build_headers(self.secret, "GET", "/api/status", target=AGENT_ID)
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=3, context=self.ctx) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            assert data["status"] == "ok"
            assert "system" in data
            assert "connections_summary" in data

    def test_network_connections_endpoint(self) -> None:
        url = f"https://127.0.0.1:{self.port}/api/network/connections"
        headers = security.build_headers(self.secret, "GET", "/api/network/connections", target=AGENT_ID)
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=3, context=self.ctx) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            assert "total" in data
            assert "connections" in data

    def test_scan_endpoint(self) -> None:
        url = f"https://127.0.0.1:{self.port}/api/scan"
        headers = security.build_headers(self.secret, "GET", "/api/scan", target=AGENT_ID)
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=30, context=self.ctx) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            assert "summary" in data
            assert "score" in data["summary"]
            assert "results" in data

    def test_scan_post_with_rules(self) -> None:
        url = f"https://127.0.0.1:{self.port}/api/scan"
        sample_rules = [
            {
                "id": "mock_rule_ok",
                "name": "Mock Rule OK",
                "category": "Test",
                "severity": "low",
                "check_command": "echo 'OK'",
                "fix_command": "echo fixed",
                "description": "Mock description",
            },
            {
                "id": "mock_rule_warn",
                "name": "Mock Rule Warn",
                "category": "Test",
                "severity": "high",
                "check_command": "echo 'FAIL'",
                "fix_command": "echo fixed",
                "description": "Mock warning description",
            },
        ]
        body = json.dumps({"rules": sample_rules})
        headers = security.build_headers(self.secret, "POST", "/api/scan", body, target=AGENT_ID)
        headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=body.encode("utf-8"), headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=5, context=self.ctx) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            assert data["summary"]["total"] == 2
            assert data["summary"]["ok"] == 1
            assert data["summary"]["warnings"] == 1
            assert data["summary"]["score"] == 50
            results = data["results"]
            assert len(results) == 2
            assert results[0]["id"] == "mock_rule_ok"
            assert results[0]["status"] == "ok"
            assert results[1]["id"] == "mock_rule_warn"
            assert results[1]["status"] == "warning"

    def test_fix_endpoint(self) -> None:
        url = f"https://127.0.0.1:{self.port}/api/fix/test_fix_1"
        body = json.dumps({"fix_command": "echo 'fix applied successfully'"})
        headers = security.build_headers(self.secret, "POST", "/api/fix/test_fix_1", body, target=AGENT_ID)
        headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=body.encode("utf-8"), headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=5, context=self.ctx) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            assert data["success"] is True
            assert data["rule_id"] == "test_fix_1"
            assert "fix applied successfully" in data["output"]

    def _post(self, path: str, body: bytes, headers: dict[str, str]) -> int:
        req = urllib.request.Request(f"https://127.0.0.1:{self.port}{path}", data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=5, context=self.ctx) as resp:
                return int(resp.status)
        except urllib.error.HTTPError as e:
            return int(e.code)

    def test_fix_tampered_body_rejected(self, tmp_path: Path) -> None:
        marker = tmp_path / "pwned"
        headers = security.build_headers(self.secret, "POST", "/api/fix/r1", b'{"fix_command": "true"}', target=AGENT_ID)
        evil = json.dumps({"fix_command": f"touch {marker}"}).encode()
        assert self._post("/api/fix/r1", evil, headers) == 401
        assert not marker.exists()

    def test_fix_replayed_nonce_rejected(self) -> None:
        body = b'{"fix_command": "true"}'
        headers = security.build_headers(self.secret, "POST", "/api/fix/r1", body, target=AGENT_ID)
        assert self._post("/api/fix/r1", body, headers) == 200
        assert self._post("/api/fix/r1", body, headers) == 401

    def test_fix_expired_timestamp_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        body = b'{"fix_command": "true"}'
        past = time.time() - security.HMAC_WINDOW_SECONDS - 100
        monkeypatch.setattr(security.time, "time", lambda: past)
        headers = security.build_headers(self.secret, "POST", "/api/fix/r1", body, target=AGENT_ID)
        monkeypatch.undo()
        assert self._post("/api/fix/r1", body, headers) == 401

    def _raw_post(self, content_length: str) -> int:
        import http.client

        conn = http.client.HTTPSConnection("127.0.0.1", self.port, timeout=5, context=self.ctx)
        try:
            conn.putrequest("POST", "/api/fix/r1")
            conn.putheader("Content-Length", content_length)
            conn.endheaders()
            return conn.getresponse().status
        finally:
            conn.close()

    def test_oversized_body_rejected_without_reading(self) -> None:
        from light_agent import agent

        assert self._raw_post(str(agent.MAX_BODY_BYTES + 1)) == 413

    @pytest.mark.parametrize("value", ["abc", "-5"])
    def test_invalid_content_length_rejected(self, value: str) -> None:
        assert self._raw_post(value) == 400

    def test_signature_for_other_path_rejected(self) -> None:
        body = b'{"fix_command": "true"}'
        headers = security.build_headers(self.secret, "POST", "/api/fix/r1", body, target=AGENT_ID)
        assert self._post("/api/fix/r2", body, headers) == 401


class TestServerHeartbeatEndpoint:

    known_ip = "192.168.99.10"
    other_ip = "192.168.99.20"

    def setup_method(self) -> None:
        self._cleanup()
        with database.get_connection() as conn:
            conn.execute(
                "INSERT INTO servers (name, ip_address, port, status, last_score, token) VALUES (?, ?, 8000, 'offline', 50, '')",
                ("Test-Heartbeat-Server", self.known_ip),
            )

    def teardown_method(self) -> None:
        self._cleanup()

    def _cleanup(self) -> None:
        with database.get_connection() as conn:
            conn.execute("DELETE FROM servers WHERE ip_address IN (?, ?)", (self.known_ip, self.other_ip))

    def _row(self, ip: str) -> Any:
        with database.get_connection() as conn:
            return conn.execute("SELECT * FROM servers WHERE ip_address = ? AND port = 8000", (ip,)).fetchone()

    def _heartbeat(self, client_ip: str, headers: dict[str, str] | None = None, **fields: Any) -> dict[str, object]:
        from schemas import AgentHeartbeatModel

        raw_headers = [(k.lower().encode("latin-1"), v.encode("latin-1")) for k, v in (headers or {}).items()]
        scope = {
            "type": "http",
            "method": "POST",
            "path": "/api/servers/heartbeat",
            "query_string": b"",
            "headers": raw_headers,
            "client": (client_ip, 12345),
        }
        body = AgentHeartbeatModel(port=8000, **fields)
        return main.server_heartbeat(request=Request(scope), body=body, current_user="agent")

    def test_heartbeat_updates_existing_server(self) -> None:
        res = self._heartbeat(self.known_ip, score=85)
        assert res["success"] is True
        assert res["status"] == "online"
        srv = self._row(self.known_ip)
        assert srv["status"] == "online"
        assert srv["last_score"] == 85

    def test_body_ip_ignored_and_logged(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level("WARNING", logger="main"):
            self._heartbeat(self.other_ip, ip_address=self.known_ip, score=1)

        known = self._row(self.known_ip)
        assert known["status"] == "offline"
        assert known["last_score"] == 50
        assert self._row(self.other_ip)["last_score"] == 1
        assert any(self.known_ip in r.getMessage() and self.other_ip in r.getMessage() for r in caplog.records)

    def test_matching_body_ip_not_logged(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level("WARNING", logger="main"):
            self._heartbeat(self.known_ip, ip_address=self.known_ip, score=70)
        assert self._row(self.known_ip)["last_score"] == 70
        assert not [r for r in caplog.records if "Heartbeat" in r.getMessage()]

    def test_forwarded_ip_used_behind_trusted_proxy(self) -> None:
        self._heartbeat("127.0.0.1", headers={"X-Forwarded-For": f"10.0.0.1, {self.known_ip}"}, score=90)
        assert self._row(self.known_ip)["last_score"] == 90

    def test_spoofed_forwarded_chain_uses_proxy_entry(self) -> None:
        self._heartbeat("127.0.0.1", headers={"X-Forwarded-For": f"{self.known_ip}, {self.other_ip}"}, score=7)
        assert self._row(self.known_ip)["last_score"] == 50
        assert self._row(self.other_ip)["last_score"] == 7

    @pytest.mark.parametrize("fwd", ["169.254.169.254", "127.0.0.1", "0.0.0.0", "::ffff:169.254.169.254"])
    def test_blocked_forwarded_address_rejected(self, fwd: str) -> None:
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc:
            self._heartbeat("127.0.0.1", headers={"X-Forwarded-For": f"{self.known_ip}, {fwd}"})
        assert exc.value.status_code == 422
        assert self._row(self.known_ip)["status"] == "offline"

    def test_blocked_client_address_rejected(self) -> None:
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc:
            self._heartbeat("169.254.169.254")
        assert exc.value.status_code == 422

    @pytest.mark.parametrize("fwd", ["evil.example", "10.0.0.1 x", ""])
    def test_invalid_forwarded_address_rejected(self, fwd: str) -> None:
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc:
            self._heartbeat("127.0.0.1", headers={"X-Forwarded-For": f"{self.known_ip}, {fwd}"})
        assert exc.value.status_code == 400

    def test_forwarded_ip_ignored_from_untrusted_client(self) -> None:
        self._heartbeat(self.other_ip, headers={"X-Forwarded-For": self.known_ip}, score=5)
        assert self._row(self.known_ip)["last_score"] == 50
        assert self._row(self.other_ip)["last_score"] == 5


def test_start_restricts_existing_log_and_pid_modes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import os

    from light_agent import agent

    log, pid = tmp_path / "agent.log", tmp_path / "agent.pid"
    log.write_text("eski log")
    pid.write_text("999999")
    os.chmod(log, 0o666)
    os.chmod(pid, 0o666)
    monkeypatch.setattr(agent, "is_process_running", lambda _pid: True)
    agent.cmd_start(AgentConfig(pid_file=str(pid), log_file=str(log), agent_id="a" * 32))
    assert log.stat().st_mode & 0o777 == 0o600
    assert pid.stat().st_mode & 0o777 == 0o600


def test_restrict_file_modes_skips_symlink_and_missing(tmp_path: Path) -> None:
    import os

    from light_agent import agent

    target = tmp_path / "hedef"
    target.write_text("x")
    os.chmod(target, 0o644)
    link = tmp_path / "agent.log"
    link.symlink_to(target)
    agent._restrict_file_modes([link, tmp_path / "yok.pid"])
    assert target.stat().st_mode & 0o777 == 0o644


def test_cli_accepts_every_config_field(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from light_agent import agent

    seen: dict[str, Any] = {}
    monkeypatch.setattr(agent, "cmd_status", lambda cfg: seen.update(vars(cfg)))
    monkeypatch.setattr(
        sys, "argv",
        ["agent.py", "status", "--config", str(tmp_path / "c.json"), "--controller-fingerprint", FP,
         "--cert-file", "x.crt", "--key-file", "x.key"],
    )
    agent.main()
    assert seen["controller_fingerprint"] == FP
    assert (seen["cert_file"], seen["key_file"]) == ("x.crt", "x.key")


def test_run_cmd_shell_yok() -> None:
    assert collector._run_cmd(["echo", "a; id $(whoami)"]) == "a; id $(whoami)"
    assert collector._run_cmd(["boyle-bir-komut-yok"]) == ""
