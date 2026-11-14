from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import main
import tlsutil

needs_openssl = pytest.mark.skipif(not tlsutil.shutil.which("openssl"), reason="openssl yok")


@pytest.fixture
def controller_cert(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    cert, key = tmp_path / "c.crt", tmp_path / "c.key"
    tlsutil.generate_self_signed(cert, key, "puyad-controller")
    monkeypatch.setenv("PUYAD_TLS_CERT", str(cert))
    monkeypatch.setenv("PUYAD_TLS_KEY", str(key))
    return cert


@needs_openssl
def test_update_script_pins_controller(controller_cert: Path) -> None:
    client = TestClient(main.app)
    pin = tlsutil.spki_pin(controller_cert)
    fp = tlsutil.fingerprint(controller_cert.read_text())
    for host in ("10.0.0.5:8000", "panel.example.com", "[::1]:8000"):
        resp = client.get("/api/agent/update.sh", headers={"Host": host})
        assert resp.status_code == 200
        assert f'BASE="https://{host}"' in resp.text
        assert f'PIN="{pin}"' in resp.text and f'FP="{fp}"' in resp.text
        assert "http://" not in resp.text
        assert '--pinnedpubkey "$PIN"' in resp.text


@needs_openssl
def test_update_script_rejects_shell_chars(controller_cert: Path) -> None:
    resp = TestClient(main.app).get("/api/agent/update.sh", headers={"Host": "x$(id)"})
    assert resp.status_code == 400


def test_update_script_without_cert_is_503(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PUYAD_TLS_CERT", str(tmp_path / "yok.crt"))
    monkeypatch.setenv("PUYAD_TLS_KEY", str(tmp_path / "yok.key"))
    resp = TestClient(main.app).get("/api/agent/update.sh", headers={"Host": "10.0.0.5:8000"})
    assert resp.status_code == 503
