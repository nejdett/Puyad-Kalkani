from __future__ import annotations

import base64
import hashlib
import os
import shutil
import ssl
import subprocess
import tempfile
from pathlib import Path

CERT_DIR: Path = Path(__file__).resolve().parent / "tls"
CERT_DAYS: int = 3650
OPENSSL_MISSING_MESSAGE: str = (
    "openssl bulunamadı, TLS sertifikası üretilemiyor. openssl paketini kurun "
    "(örn: sudo apt install openssl) ya da PUYAD_TLS_CERT ve PUYAD_TLS_KEY ile hazır sertifika verin."
)


class TLSSetupError(RuntimeError):
    pass


def _openssl() -> str:
    path = shutil.which("openssl")
    if not path:
        raise TLSSetupError(OPENSSL_MISSING_MESSAGE)
    return path


def generate_self_signed(cert_path: Path, key_path: Path, common_name: str) -> None:
    openssl = _openssl()
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=str(key_path.parent)) as tmp:
        tmp_key = Path(tmp) / "key.pem"
        tmp_cert = Path(tmp) / "cert.pem"
        result = subprocess.run(
            [
                openssl, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                "-nodes", "-days", str(CERT_DAYS), "-subj", f"/CN={common_name}",
                "-addext", f"subjectAltName=DNS:{common_name}",
                "-keyout", str(tmp_key), "-out", str(tmp_cert),
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode != 0:
            raise TLSSetupError(f"Sertifika üretilemedi: {result.stderr.strip()[:300]}")
        os.chmod(tmp_key, 0o600)
        os.chmod(tmp_cert, 0o644)
        os.replace(tmp_key, key_path)
        os.replace(tmp_cert, cert_path)


def controller_cert_paths() -> tuple[Path, Path]:
    cert = os.environ.get("PUYAD_TLS_CERT", "").strip()
    key = os.environ.get("PUYAD_TLS_KEY", "").strip()
    if cert or key:
        if not (cert and key):
            raise TLSSetupError("PUYAD_TLS_CERT ve PUYAD_TLS_KEY birlikte verilmeli.")
        return Path(cert), Path(key)
    return CERT_DIR / "controller.crt", CERT_DIR / "controller.key"


def ensure_controller_cert() -> tuple[Path, Path]:
    cert, key = controller_cert_paths()
    if cert.is_file() and key.is_file():
        return cert, key
    if os.environ.get("PUYAD_TLS_CERT", "").strip():
        raise TLSSetupError(f"Verilen sertifika ya da anahtar dosyası yok: {cert}, {key}")
    generate_self_signed(cert, key, "puyad-controller")
    return cert, key


def fingerprint(cert_pem: str) -> str:
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert_pem.strip())).hexdigest()


def spki_pin(cert_path: Path) -> str:
    openssl = _openssl()
    pubkey = subprocess.run(
        [openssl, "x509", "-in", str(cert_path), "-pubkey", "-noout"],
        capture_output=True, check=True, timeout=15,
    ).stdout
    der = subprocess.run(
        [openssl, "pkey", "-pubin", "-outform", "der"],
        input=pubkey, capture_output=True, check=True, timeout=15,
    ).stdout
    return "sha256//" + base64.b64encode(hashlib.sha256(der).digest()).decode("ascii")


_pin_cache: dict[tuple[str, int], tuple[str, str]] = {}


def controller_pins() -> tuple[str, str]:
    cert, _key = controller_cert_paths()
    if not cert.is_file():
        raise TLSSetupError("Controller TLS sertifikası yok. Backend'i serve.py ile başlatın.")
    cache_key = (str(cert), cert.stat().st_mtime_ns)
    if cache_key not in _pin_cache:
        _pin_cache.clear()
        _pin_cache[cache_key] = (spki_pin(cert), fingerprint(cert.read_text(encoding="utf-8")))
    return _pin_cache[cache_key]


def pinned_client_context(cert_pem: str) -> ssl.SSLContext:
    # Sertifika IP'ye kesilmiyor — hostname yerine güven deposunda yalnızca bu sertifika var
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cadata=cert_pem)
    return ctx
