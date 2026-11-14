from __future__ import annotations

import socket
import struct
import sys
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
import honeypot_services as hs


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(hs, "FAIL_DELAY", 0)
    monkeypatch.setattr(hs, "SESSION_SECONDS", 3.0)


class Peer:

    def __init__(self, service: str, port: int = 80) -> None:
        self.client, server = socket.socketpair()
        self.client.settimeout(3)
        self.result: dict[str, Any] = {}

        def serve() -> None:
            try:
                self.result["data"] = hs.run(server, service, port)
            finally:
                server.close()

        self.thread = threading.Thread(target=serve, daemon=True)
        self.thread.start()
        self.buf = b""

    def send(self, data: bytes) -> None:
        self.client.sendall(data)

    def until(self, marker: bytes) -> bytes:
        while marker not in self.buf:
            chunk = self.client.recv(4096)
            if not chunk:
                raise AssertionError(f"{marker!r} gelmedi: {self.buf!r}")
            self.buf += chunk
        out, _, self.buf = self.buf.partition(marker)
        return out + marker

    def rest(self) -> bytes:
        out = self.buf
        while True:
            chunk = self.client.recv(4096)
            if not chunk:
                break
            out += chunk
        self.buf = b""
        return out

    def done(self) -> bytes:
        self.thread.join(5)
        assert not self.thread.is_alive()
        self.client.close()
        return bytes(self.result["data"])


@pytest.fixture
def peers() -> Iterator[list[Peer]]:
    made: list[Peer] = []
    yield made
    for p in made:
        p.client.close()


def _peer(peers: list[Peer], service: str, port: int = 80) -> Peer:
    p = Peer(service, port)
    peers.append(p)
    return p


def test_ssh_surum_ve_kexinit(peers: list[Peer]) -> None:
    p = _peer(peers, "ssh")
    assert p.until(b"\r\n") == b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n"
    p.send(b"SSH-2.0-libssh_0.10\r\n")
    head = b""
    while len(head) < 5:
        head += p.client.recv(5 - len(head))
    length, pad = struct.unpack(">IB", head)
    assert (length + 4) % 8 == 0 and pad >= 4
    body = b""
    while len(body) < length - 1:
        body += p.client.recv(length - 1 - len(body))
    assert body[0] == 20
    assert b"curve25519-sha256" in body and b"ssh-ed25519" in body
    p.send(b"\x00\x00\x00\x0c\x0a\x14istemci-kex")
    assert b"SSH-2.0-libssh_0.10" in p.done()


def test_ssh_gecersiz_kimlik(peers: list[Peer]) -> None:
    p = _peer(peers, "ssh")
    p.until(b"\r\n")
    p.send(b"GET / HTTP/1.1\r\n")
    assert p.rest() == b"Invalid SSH identification string.\r\n"
    p.done()


def _http(peers: list[Peer], req: bytes) -> tuple[str, dict[str, str], bytes]:
    p = _peer(peers, "http", 8080)
    p.send(req)
    raw = p.rest()
    p.done()
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.decode().split("\r\n")
    headers = dict(line.split(": ", 1) for line in lines[1:])
    return lines[0], headers, body


def test_http_ana_sayfa(peers: list[Peer]) -> None:
    status, h, body = _http(peers, b"GET / HTTP/1.1\r\nHost: 192.0.2.1\r\nUser-Agent: curl\r\n\r\n")
    assert status == "HTTP/1.1 200 OK"
    assert h["Server"] == "Apache/2.4.58 (Ubuntu)"
    assert h["Date"].endswith("GMT")
    assert int(h["Content-Length"]) == len(body)
    assert b"It works!" in body


def test_http_hatalar(peers: list[Peer]) -> None:
    status, _, body = _http(peers, b"GET /wp-login.php HTTP/1.1\r\nHost: a\r\n\r\n")
    assert status == "HTTP/1.1 404 Not Found"
    assert b"Server at a Port 8080" in body
    status, h, _ = _http(peers, b"POST / HTTP/1.1\r\nHost: a\r\n\r\n")
    assert status == "HTTP/1.1 405 Method Not Allowed"
    assert "GET" in h["Allow"]
    status, _, _ = _http(peers, b"\x16\x03\x01 bozuk\r\n\r\n")
    assert status == "HTTP/1.1 400 Bad Request"


def test_http_head_govdesiz(peers: list[Peer]) -> None:
    status, h, body = _http(peers, b"HEAD / HTTP/1.0\r\n\r\n")
    assert status == "HTTP/1.1 200 OK"
    assert int(h["Content-Length"]) > 0
    assert body == b""


def test_http_host_kacisli(peers: list[Peer]) -> None:
    _, _, body = _http(peers, b"GET /x HTTP/1.1\r\nHost: <script>alert(1)</script>\r\n\r\n")
    assert b"<script>" not in body
    assert b"&lt;script&gt;" in body


def test_ftp_akisi(peers: list[Peer]) -> None:
    p = _peer(peers, "ftp")
    assert p.until(b"\r\n") == b"220 (vsFTPd 3.0.5)\r\n"
    p.send(b"PASS x\r\n")
    assert p.until(b"\r\n").startswith(b"503")
    p.send(b"USER anonymous\r\n")
    assert p.until(b"\r\n").startswith(b"331")
    p.send(b"PASS a@b\r\n")
    assert p.until(b"\r\n") == b"530 Login incorrect.\r\n"
    p.send(b"SYST\r\nLIST\r\n")
    assert p.until(b"\r\n").startswith(b"215")
    assert p.until(b"\r\n").startswith(b"530 Please login")
    p.send(b"QUIT\r\n")
    assert p.rest() == b"221 Goodbye.\r\n"
    assert b"USER anonymous" in p.done()


def test_smtp_akisi(peers: list[Peer]) -> None:
    p = _peer(peers, "smtp")
    assert p.until(b"\r\n").startswith(b"220 mail.localdomain ESMTP")
    p.send(b"MAIL FROM:<a@b>\r\n")
    assert p.until(b"\r\n").startswith(b"503")
    p.send(b"EHLO test\r\n")
    ehlo = p.until(b"250 SMTPUTF8\r\n")
    assert b"250-AUTH PLAIN LOGIN" in ehlo
    p.send(b"MAIL FROM:<a@b>\r\nRCPT TO:<x@example.com>\r\nDATA\r\nAUTH LOGIN\r\nXYZ\r\n")
    assert p.until(b"\r\n").startswith(b"250 2.1.0")
    assert b"Relay access denied" in p.until(b"\r\n")
    assert p.until(b"\r\n").startswith(b"554")
    assert p.until(b"\r\n").startswith(b"535")
    assert p.until(b"\r\n").startswith(b"502")
    p.send(b"QUIT\r\n")
    assert p.rest() == b"221 2.0.0 Bye\r\n"
    p.done()


def test_telnet_giris_reddi(peers: list[Peer]) -> None:
    p = _peer(peers, "telnet")
    assert p.until(b"login: ").startswith(b"\xff\xfd\x18")
    p.send(b"\xff\xfb\x18root\r\n")
    p.until(b"Password: ")
    p.send(b"123456\r\n")
    assert b"Login incorrect" in p.until(b"login: ")
    p.client.shutdown(socket.SHUT_WR)
    data = p.done()
    assert b"root" in data and b"\xff" not in data


def test_komut_siniri(peers: list[Peer]) -> None:
    p = _peer(peers, "ftp")
    p.until(b"\r\n")
    p.send(b"NOOP\r\n" * 15)
    replies = p.rest()
    assert replies.count(b"200 NOOP ok.") == hs.MAX_COMMANDS
    p.done()


def test_bayt_siniri(peers: list[Peer]) -> None:
    p = _peer(peers, "http")
    try:
        p.send(b"A" * (hs.MAX_BYTES + 4000))
    except OSError:
        pass
    data = p.done()
    assert len(data) == 1024


def test_sure_siniri(peers: list[Peer], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(hs, "SESSION_SECONDS", 0.3)
    start = time.monotonic()
    p = _peer(peers, "smtp")
    p.until(b"\r\n")
    p.done()
    assert time.monotonic() - start < 2


def test_ozel_servis_sessiz(peers: list[Peer]) -> None:
    p = _peer(peers, "custom", 9999)
    p.send(b"merhaba")
    assert p.done() == b"merhaba"
