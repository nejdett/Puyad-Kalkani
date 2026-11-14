from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import sys
import time
from pathlib import Path
from typing import Any

import pytest
from fastapi import HTTPException
from starlette.requests import Request

sys.path.insert(0, str(Path(__file__).parent.parent))
import agent_auth

SECRET = "c" * 64
PATH = "/api/servers/heartbeat"
BODY = b'{"hostname": "web-1", "port": 8001}'


def _request(method: str = "POST", path: str = PATH, query: str = "", headers: dict[str, str] | None = None,
             body: bytes = b"") -> Request:
    raw_headers = [(k.lower().encode("latin-1"), v.encode("latin-1")) for k, v in (headers or {}).items()]
    scope = {"type": "http", "method": method, "path": path, "query_string": query.encode(), "headers": raw_headers}

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": body, "more_body": False}

    return Request(scope, receive)


def _verify(req: Request, secret: str = SECRET) -> None:
    asyncio.run(agent_auth.verify_agent_request(req, secret))


def _rejected(req: Request, secret: str = SECRET) -> HTTPException:
    with pytest.raises(HTTPException) as exc_info:
        _verify(req, secret)
    return exc_info.value


def _sign(ts: str, nonce: str, method: str, path: str, body: bytes) -> dict[str, str]:
    payload = agent_auth.signing_payload(ts, nonce, method, path, body)
    sig = hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return {"X-Puyad-Timestamp": ts, "X-Puyad-Nonce": nonce, "X-Puyad-Signature": sig}


@pytest.fixture(autouse=True)
def _clean_nonces() -> None:
    agent_auth.reset_nonce_cache()


def test_is_loopback_ip() -> None:
    for ip in ("127.0.0.1", "localhost", "::1", "::ffff:127.0.0.1", "127.100.0.5"):
        assert agent_auth.is_loopback_ip(ip) is True
    for ip in ("192.168.1.1", "10.0.0.1", "8.8.8.8"):
        assert agent_auth.is_loopback_ip(ip) is False


def test_build_agent_headers_format() -> None:
    headers = agent_auth.build_agent_headers(SECRET, "POST", PATH, BODY)
    assert set(headers) == {"X-Puyad-Timestamp", "X-Puyad-Nonce", "X-Puyad-Signature"}
    assert len(headers["X-Puyad-Signature"]) == 64


def test_valid_signature_with_body() -> None:
    headers = agent_auth.build_agent_headers(SECRET, "POST", PATH, BODY)
    _verify(_request(headers=headers, body=BODY))


def test_valid_signature_without_body() -> None:
    headers = agent_auth.build_agent_headers(SECRET, "GET", "/api/rules")
    _verify(_request(method="GET", path="/api/rules", headers=headers))


def test_valid_signature_with_query() -> None:
    headers = agent_auth.build_agent_headers(SECRET, "GET", "/api/scan?server_id=2")
    _verify(_request(method="GET", path="/api/scan", query="server_id=2", headers=headers))


def test_tampered_body_rejected() -> None:
    headers = agent_auth.build_agent_headers(SECRET, "POST", PATH, BODY)
    err = _rejected(_request(headers=headers, body=b'{"hostname": "evil", "port": 8001}'))
    assert err.status_code == 401
    assert "imza" in str(err.detail).lower()


def test_bodyless_signature_rejected_for_request_with_body() -> None:
    headers = agent_auth.build_agent_headers(SECRET, "POST", PATH)
    assert _rejected(_request(headers=headers, body=BODY)).status_code == 401


def test_tampered_query_rejected() -> None:
    headers = agent_auth.build_agent_headers(SECRET, "GET", "/api/scan?server_id=2")
    assert _rejected(_request(method="GET", path="/api/scan", query="server_id=3", headers=headers)).status_code == 401


def test_replayed_nonce_rejected() -> None:
    headers = agent_auth.build_agent_headers(SECRET, "POST", PATH, BODY)
    _verify(_request(headers=headers, body=BODY))
    err = _rejected(_request(headers=headers, body=BODY))
    assert err.status_code == 401
    assert "replay" in str(err.detail).lower()


def test_expired_timestamp_rejected() -> None:
    ts = str(int(time.time()) - agent_auth.HMAC_WINDOW_SECONDS - 100)
    headers = _sign(ts, "a" * 16, "POST", PATH, BODY)
    err = _rejected(_request(headers=headers, body=BODY))
    assert err.status_code == 401
    assert "zaman aşımına" in str(err.detail)


def test_signature_for_other_path_rejected() -> None:
    headers = agent_auth.build_agent_headers(SECRET, "POST", "/api/fix/rule_1", BODY)
    assert _rejected(_request(path="/api/fix/rule_2", headers=headers, body=BODY)).status_code == 401


def test_signature_for_other_method_rejected() -> None:
    headers = agent_auth.build_agent_headers(SECRET, "GET", PATH)
    assert _rejected(_request(method="POST", headers=headers)).status_code == 401


def test_old_v1_signature_rejected() -> None:
    ts, nonce = str(int(time.time())), "b" * 16
    for payload in (f"{ts}.{nonce}.POST.{PATH}.{BODY.decode()}", f"{ts}.{nonce}.POST.{PATH}.", f"{ts}.{nonce}.POST.{PATH}"):
        sig = hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
        headers = {"X-Puyad-Timestamp": ts, "X-Puyad-Nonce": nonce, "X-Puyad-Signature": sig}
        assert _rejected(_request(headers=headers, body=BODY)).status_code == 401


def test_invalid_signature_does_not_consume_nonce() -> None:
    ts, nonce = str(int(time.time())), "d" * 16
    forged = {"X-Puyad-Timestamp": ts, "X-Puyad-Nonce": nonce, "X-Puyad-Signature": "0" * 64}
    assert _rejected(_request(headers=forged, body=BODY)).status_code == 401
    _verify(_request(headers=_sign(ts, nonce, "POST", PATH, BODY), body=BODY))


def test_full_cache_rejects_without_evicting(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent_auth, "_NONCE_MAX", 2)
    first = agent_auth.build_agent_headers(SECRET, "POST", PATH, BODY)
    _verify(_request(headers=first, body=BODY))
    _verify(_request(headers=agent_auth.build_agent_headers(SECRET, "POST", PATH, BODY), body=BODY))

    assert _rejected(_request(headers=agent_auth.build_agent_headers(SECRET, "POST", PATH, BODY), body=BODY)).status_code == 503
    assert "replay" in str(_rejected(_request(headers=first, body=BODY)).detail).lower()


def test_expired_nonces_free_capacity(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent_auth, "_NONCE_MAX", 1)
    _verify(_request(headers=agent_auth.build_agent_headers(SECRET, "POST", PATH, BODY), body=BODY))
    later = time.time() + 2 * agent_auth.HMAC_WINDOW_SECONDS + 1
    monkeypatch.setattr(agent_auth.time, "time", lambda: later)
    _verify(_request(headers=agent_auth.build_agent_headers(SECRET, "POST", PATH, BODY), body=BODY))


def test_malformed_nonce_rejected() -> None:
    ts = str(int(time.time()))
    for nonce in ("nonce123", "A" * 16, "a" * 16 + "\n", "a" * 65):
        headers = _sign(ts, nonce, "POST", PATH, BODY)
        assert _rejected(_request(headers=headers, body=BODY)).status_code == 401


def test_default_or_empty_secret() -> None:
    req = _request(headers={"x-puyad-timestamp": "123", "x-puyad-nonce": "abc", "x-puyad-signature": "sig"})
    for weak in agent_auth._WEAK_SECRETS:
        assert _rejected(req, weak).status_code == 500


def test_missing_headers() -> None:
    err = _rejected(_request(headers={}))
    assert err.status_code == 401
    assert "eksik" in str(err.detail)


def test_invalid_timestamp() -> None:
    headers = {"x-puyad-timestamp": "not-an-int", "x-puyad-nonce": "a" * 16, "x-puyad-signature": "ab"}
    err = _rejected(_request(headers=headers))
    assert err.status_code == 401
    assert "timestamp" in str(err.detail).lower()


def test_reset_nonce_cache() -> None:
    headers = agent_auth.build_agent_headers(SECRET, "POST", PATH, BODY)
    _verify(_request(headers=headers, body=BODY))
    agent_auth.reset_nonce_cache()
    _verify(_request(headers=headers, body=BODY))


def test_agent_and_controller_produce_same_signature() -> None:
    sys.path.insert(0, str(Path(__file__).parent.parent.parent / "light_agent"))
    import security

    args = ("1700000000", "e" * 16, "post", "/api/scan?x=1", BODY, "a" * 32)
    assert security.signing_payload(*args) == agent_auth.signing_payload(*args)
    assert security.signing_payload(*args).startswith(f"v3.1700000000.{'e' * 16}.{'a' * 32}.POST.")
    assert security.signing_payload(*args[:5]) == agent_auth.signing_payload(*args[:5])
    assert agent_auth.CONTROLLER_TARGET == security.CONTROLLER_TARGET


def test_signature_for_agent_target_rejected_by_controller() -> None:
    headers = agent_auth.build_agent_headers(SECRET, "POST", PATH, BODY, "a" * 32)
    assert _rejected(_request(headers=headers, body=BODY)).status_code == 401


def test_old_v2_signature_rejected() -> None:
    ts, nonce = str(int(time.time())), "c" * 16
    payload = f"v2.{ts}.{nonce}.POST.{PATH}.{hashlib.sha256(BODY).hexdigest()}"
    sig = hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    headers = {"X-Puyad-Timestamp": ts, "X-Puyad-Nonce": nonce, "X-Puyad-Signature": sig}
    assert _rejected(_request(headers=headers, body=BODY)).status_code == 401


@pytest.mark.parametrize("sig", ["ç" * 64, "A" * 64, "0" * 65])
def test_malformed_signature_returns_401(sig: str) -> None:
    headers = dict(agent_auth.build_agent_headers(SECRET, "POST", PATH, BODY), **{"X-Puyad-Signature": sig})
    exc = _rejected(_request(headers=headers, body=BODY))
    assert exc.status_code == 401


def test_non_ascii_signature_endpoint_returns_401(monkeypatch: pytest.MonkeyPatch) -> None:
    from fastapi.testclient import TestClient

    import main

    monkeypatch.setenv("PUYAD_AGENT_SHARED_SECRET", SECRET)
    client = TestClient(main.app, client=("192.168.99.78", 50000), raise_server_exceptions=False)
    headers = agent_auth.build_agent_headers(SECRET, "POST", PATH, BODY)
    headers["X-Puyad-Signature"] = "ç" * 64
    raw = [(k.encode("latin-1"), v.encode("latin-1")) for k, v in headers.items()]
    resp = client.post(PATH, content=BODY, headers=raw)
    assert resp.status_code == 401


def test_endpoint_reads_body_after_verification(monkeypatch: pytest.MonkeyPatch) -> None:
    from fastapi.testclient import TestClient

    import database
    import main

    monkeypatch.setenv("PUYAD_AGENT_SHARED_SECRET", SECRET)
    ip = "192.168.99.77"
    client = TestClient(main.app, client=(ip, 50000))
    body = b'{"hostname": "imza-test", "port": 8001}'
    json_headers = {"Content-Type": "application/json"}

    try:
        headers = agent_auth.build_agent_headers(SECRET, "POST", PATH, body)
        tampered = client.post(PATH, content=body.replace(b"8001", b"8002"), headers={**headers, **json_headers})
        assert tampered.status_code == 401

        headers = agent_auth.build_agent_headers(SECRET, "POST", PATH, body)
        assert client.post(PATH, content=body, headers={**headers, **json_headers}).status_code == 200
        assert client.post(PATH, content=body, headers={**headers, **json_headers}).status_code == 401

        with database.get_connection() as conn:
            rows = conn.execute("SELECT name, port FROM servers WHERE ip_address = ?", (ip,)).fetchall()
        assert [(r["name"], r["port"]) for r in rows] == [("imza-test", 8001)]

        agent_id = "d" * 32
        body = json.dumps({"hostname": "imza-test", "port": 8001, "agent_id": agent_id}).encode()
        headers = agent_auth.build_agent_headers(SECRET, "POST", PATH, body)
        assert client.post(PATH, content=body, headers={**headers, **json_headers}).status_code == 200
        with database.get_connection() as conn:
            row = conn.execute("SELECT agent_id FROM servers WHERE ip_address = ?", (ip,)).fetchone()
        assert row["agent_id"] == agent_id

        body = json.dumps({"hostname": "imza-test", "port": 8001, "agent_id": "kısa"}).encode()
        headers = agent_auth.build_agent_headers(SECRET, "POST", PATH, body)
        assert client.post(PATH, content=body, headers={**headers, **json_headers}).status_code == 422
    finally:
        with database.get_connection() as conn:
            conn.execute("DELETE FROM servers WHERE ip_address = ?", (ip,))
