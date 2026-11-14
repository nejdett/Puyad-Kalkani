from __future__ import annotations

import socket
import ssl
import subprocess
import threading
from pathlib import Path

import pytest

import tlsutil

needs_openssl = pytest.mark.skipif(not tlsutil.shutil.which("openssl"), reason="openssl yok")


def _make(tmp_path: Path, name: str) -> tuple[Path, Path]:
    cert, key = tmp_path / f"{name}.crt", tmp_path / f"{name}.key"
    tlsutil.generate_self_signed(cert, key, name)
    return cert, key


@needs_openssl
def test_generate_and_fingerprint(tmp_path: Path) -> None:
    cert, key = _make(tmp_path, "a")
    assert key.stat().st_mode & 0o777 == 0o600
    out = subprocess.run(
        ["openssl", "x509", "-in", str(cert), "-noout", "-fingerprint", "-sha256"],
        capture_output=True, text=True, check=True,
    ).stdout
    expected = out.strip().split("=", 1)[1].replace(":", "").lower()
    assert tlsutil.fingerprint(cert.read_text()) == expected


@needs_openssl
def test_spki_pin_format(tmp_path: Path) -> None:
    cert, _ = _make(tmp_path, "a")
    pin = tlsutil.spki_pin(cert)
    assert pin.startswith("sha256//") and len(pin) == len("sha256//") + 44


def test_missing_openssl_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tlsutil.shutil, "which", lambda _name: None)
    with pytest.raises(tlsutil.TLSSetupError, match="openssl bulunamadı"):
        tlsutil.generate_self_signed(tmp_path / "c", tmp_path / "k", "x")
    assert not (tmp_path / "k").exists()


@needs_openssl
def test_ensure_controller_cert_generates_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PUYAD_TLS_CERT", raising=False)
    monkeypatch.delenv("PUYAD_TLS_KEY", raising=False)
    monkeypatch.setattr(tlsutil, "CERT_DIR", tmp_path / "tls")
    cert, _ = tlsutil.ensure_controller_cert()
    first = cert.read_text()
    tlsutil.ensure_controller_cert()
    assert cert.read_text() == first


def test_env_cert_must_exist(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PUYAD_TLS_CERT", str(tmp_path / "yok.crt"))
    monkeypatch.setenv("PUYAD_TLS_KEY", str(tmp_path / "yok.key"))
    with pytest.raises(tlsutil.TLSSetupError):
        tlsutil.ensure_controller_cert()
    monkeypatch.delenv("PUYAD_TLS_KEY")
    with pytest.raises(tlsutil.TLSSetupError, match="birlikte"):
        tlsutil.controller_cert_paths()


def _serve_once(cert: Path, key: Path) -> tuple[int, threading.Thread]:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert), str(key))
    listener = socket.create_server(("127.0.0.1", 0))
    port = listener.getsockname()[1]

    def run() -> None:
        with listener:
            conn, _ = listener.accept()
            try:
                with ctx.wrap_socket(conn, server_side=True) as tls:
                    tls.sendall(b"ok")
            except (ssl.SSLError, OSError):
                pass

    t = threading.Thread(target=run, daemon=True)
    t.start()
    return port, t


@needs_openssl
def test_pinned_context_accepts_only_pinned_cert(tmp_path: Path) -> None:
    cert_a, key_a = _make(tmp_path, "a")
    cert_b, _ = _make(tmp_path, "b")

    port, t = _serve_once(cert_a, key_a)
    ctx = tlsutil.pinned_client_context(cert_a.read_text())
    with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
        with ctx.wrap_socket(raw) as tls:
            assert tls.recv(2) == b"ok"
    t.join(5)

    port, t = _serve_once(cert_a, key_a)
    ctx = tlsutil.pinned_client_context(cert_b.read_text())
    with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
        with pytest.raises(ssl.SSLCertVerificationError):
            ctx.wrap_socket(raw)
    t.join(5)


@needs_openssl
def test_cert_has_san(tmp_path: Path) -> None:
    cert, _ = _make(tmp_path, "puyad-controller")
    out = subprocess.run(
        ["openssl", "x509", "-in", str(cert), "-noout", "-ext", "subjectAltName"],
        capture_output=True, text=True, check=True,
    ).stdout
    assert "DNS:puyad-controller" in out
