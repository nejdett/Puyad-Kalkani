from __future__ import annotations

import functools
import hashlib
import hmac
import http.client
import os
import re
import secrets
import shutil
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

HMAC_WINDOW_SECONDS: int = 300
MIN_SECRET_LENGTH: int = 32
# backend/agent_auth.py'deki listenin kopyası — ajan yalnızca stdlib kullanıyor
_WEAK_SECRETS: frozenset[str] = frozenset({
    "puyad-secure-key-degistirin",
    "guclu-bir-secret-key-buraya-yazin",
    "BURAYA_BACKEND_AGENT_SHARED_SECRET_DEGERI_YAZILMALI",
    "",
})
WEAK_SECRET_HELP: str = (
    "Yeni bir değer üretin: panelde Sunucu Yönetimi sayfasından ya da "
    "python3 -c \"import secrets; print(secrets.token_hex(32))\" komutuyla. "
    "Değeri config.json içine, --secret / --token ile ya da PUYAD_AGENT_SECRET ile verin."
)

_WEAK_SECRETS_NORMALIZED: frozenset[str] = frozenset(s.lower() for s in _WEAK_SECRETS)

_used_nonces: dict[str, float] = {}
_nonce_lock: threading.Lock = threading.Lock()
_NONCE_MAX: int = 16384
_NONCE_RE: re.Pattern[str] = re.compile(r"[0-9a-f]{16,64}")
# backend/agent_auth.py ile aynı şema — biri değişirse diğeri de değişmeli
SIGNATURE_VERSION: str = "v3"
CONTROLLER_TARGET: str = "controller"
AGENT_ID_RE: re.Pattern[str] = re.compile(r"[A-Za-z0-9_-]{8,64}")
_SIG_RE: re.Pattern[str] = re.compile(r"[0-9a-f]{64}")


def is_weak_secret(value: str) -> bool:
    clean = value.strip()
    return not clean or clean.lower() in _WEAK_SECRETS_NORMALIZED or len(clean) < MIN_SECRET_LENGTH


def credential_problem(secret: str, token: str) -> str:
    if not secret and not token:
        return "secret veya token tanımlı değil. Kimlik doğrulaması olmadan ajan çalışmaz."
    if secret and is_weak_secret(secret):
        return f"secret zayıf (boş, örnek değer ya da {MIN_SECRET_LENGTH} karakterden kısa)."
    if token and is_weak_secret(token):
        return f"token zayıf (boş, örnek değer ya da {MIN_SECRET_LENGTH} karakterden kısa)."
    return ""


def signing_payload(
    ts: str, nonce: str, method: str, path: str, body: bytes | str, target: str = CONTROLLER_TARGET
) -> str:
    raw = body.encode("utf-8") if isinstance(body, str) else body
    digest = hashlib.sha256(raw).hexdigest()
    return f"{SIGNATURE_VERSION}.{ts}.{nonce}.{target}.{method.upper()}.{path}.{digest}"


def build_headers(
    secret: str, method: str, path: str, body: bytes | str = b"", target: str = CONTROLLER_TARGET
) -> dict[str, str]:
    timestamp: str = str(int(time.time()))
    nonce: str = secrets.token_hex(8)
    payload = signing_payload(timestamp, nonce, method, path, body, target)
    sig: str = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return {
        "X-Puyad-Timestamp": timestamp,
        "X-Puyad-Nonce": nonce,
        "X-Puyad-Signature": sig,
    }


def _store_nonce(nonce: str, expires_at: float, now_ts: float) -> str:
    with _nonce_lock:
        for k in [k for k, exp in _used_nonces.items() if exp < now_ts]:
            del _used_nonces[k]
        if nonce in _used_nonces:
            return "Nonce tekrar kullanıldı (replay)."
        # Pencere içindeki nonce tahliye edilirse replay mümkün olur — doluysa reddet
        if len(_used_nonces) >= _NONCE_MAX:
            return "Nonce kapasitesi dolu, kısa süre sonra tekrar deneyin."
        _used_nonces[nonce] = expires_at
        return ""


def reset_nonce_cache() -> None:
    with _nonce_lock:
        _used_nonces.clear()


def verify_request(
    headers: dict[str, str],
    method: str,
    path: str,
    body: bytes | str = b"",
    secret: str = "",
    token: str = "",
    agent_id: str = "",
) -> tuple[bool, str]:
    problem = credential_problem(secret, token)
    if problem:
        return False, f"Ajan yapılandırması geçersiz: {problem} {WEAK_SECRET_HELP}"

    hdrs = {k.lower(): v for k, v in headers.items()}
    auth_header = hdrs.get("authorization", "")

    if token:
        if auth_header.startswith("Bearer "):
            client_token = auth_header[7:].strip()
            # str compare_digest ASCII dışı değerde TypeError fırlatıyor
            if hmac.compare_digest(
                client_token.encode("utf-8", "surrogateescape"), token.encode("utf-8", "surrogateescape")
            ):
                return True, ""
            return False, "Geçersiz Bearer token."

    if not secret:
        return False, "Yetkilendirme gerekli."
    if not agent_id:
        return False, "Ajan kimliği (agent_id) tanımlı değil."

    ts_raw = hdrs.get("x-puyad-timestamp")
    nonce = hdrs.get("x-puyad-nonce")
    sig = hdrs.get("x-puyad-signature")

    if not ts_raw or not nonce or not sig:
        return False, "Agent kimlik doğrulama başlıkları eksik (X-Puyad-* veya Bearer)."

    try:
        ts_int = int(ts_raw)
    except ValueError:
        return False, "Geçersiz timestamp."

    now_ts = time.time()
    if abs(now_ts - ts_int) > HMAC_WINDOW_SECONDS:
        return False, "İmza zaman aşımına uğradı (replay koruması)."

    if not _NONCE_RE.fullmatch(nonce):
        return False, "Geçersiz nonce."
    if not _SIG_RE.fullmatch(sig):
        return False, "Geçersiz agent imzası."

    # Hedef imzada — başka ajana gönderilmiş istek burada tutmaz
    payload = signing_payload(ts_raw, nonce, method, path, body, agent_id)
    expected = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig):
        return False, "Geçersiz agent imzası."

    problem = _store_nonce(nonce, ts_int + HMAC_WINDOW_SECONDS, now_ts)
    if problem:
        return False, problem
    return True, ""


FINGERPRINT_RE: re.Pattern[str] = re.compile(r"[0-9a-f]{64}")
CERT_DAYS: int = 3650
OPENSSL_MISSING_MESSAGE: str = (
    "openssl bulunamadı, ajan TLS sertifikası üretilemiyor. openssl paketini kurun "
    "(örn: sudo apt install openssl)."
)
CONTROLLER_SETUP_HELP: str = "Kurulum komutunu paneldeki Sunucular sayfasından alıp ajan dizininde yeniden çalıştırın."


class TLSSetupError(RuntimeError):
    pass


def ensure_cert(cert_path: Path, key_path: Path, common_name: str = "puyad-agent") -> None:
    if cert_path.is_file() and key_path.is_file():
        return
    openssl = shutil.which("openssl")
    if not openssl:
        raise TLSSetupError(OPENSSL_MISSING_MESSAGE)
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


def cert_fingerprint(pem: str) -> str:
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem.strip())).hexdigest()


def server_context(cert_path: Path, key_path: Path) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(str(cert_path), str(key_path))
    return ctx


def controller_problem(controller_url: str, fingerprint: str) -> str:
    if not controller_url.startswith("https://"):
        return f"Controller adresi https:// ile başlamalı ({controller_url})."
    if not FINGERPRINT_RE.fullmatch(fingerprint):
        return "controller_fingerprint tanımlı değil ya da geçersiz."
    return ""


class ControllerPinError(OSError):
    pass


class _PinnedHTTPSConnection(http.client.HTTPSConnection):

    def __init__(self, *args: Any, fingerprint: str, **kwargs: Any) -> None:
        # Sertifika kendinden imzalı ve IP'ye kesilmiyor — zincir yerine parmak izi kontrol ediliyor
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        kwargs["context"] = ctx
        super().__init__(*args, **kwargs)
        self._fingerprint = fingerprint

    def connect(self) -> None:
        super().connect()
        der = self.sock.getpeercert(binary_form=True) if isinstance(self.sock, ssl.SSLSocket) else None
        actual = hashlib.sha256(der).hexdigest() if der else ""
        if not hmac.compare_digest(actual, self._fingerprint):
            self.close()
            raise ControllerPinError(f"Controller parmak izi uyuşmuyor (gelen: {actual or 'yok'}).")


class PinnedHTTPSHandler(urllib.request.HTTPSHandler):

    def __init__(self, fingerprint: str) -> None:
        super().__init__()
        self._fingerprint = fingerprint

    def https_open(self, req: urllib.request.Request) -> http.client.HTTPResponse:
        return self.do_open(
            functools.partial(_PinnedHTTPSConnection, fingerprint=self._fingerprint), req
        )


def controller_open(req: urllib.request.Request, fingerprint: str, timeout: float) -> Any:
    problem = controller_problem(req.full_url, fingerprint)
    if problem:
        raise ControllerPinError(problem)
    # build_opener düz HTTPHandler ve yönlendirme ekliyor — imzalı başlıklar http:// hedefe gidebilirdi
    opener = urllib.request.OpenerDirector()
    for handler in (
        urllib.request.ProxyHandler(),
        PinnedHTTPSHandler(fingerprint),
        urllib.request.HTTPDefaultErrorHandler(),
        urllib.request.HTTPErrorProcessor(),
    ):
        opener.add_handler(handler)
    try:
        return opener.open(req, timeout=timeout)
    except urllib.error.URLError as e:
        # urllib pin hatasını URLError'a sarıyor — çağıran ayırt edebilsin
        if isinstance(e.reason, ControllerPinError):
            raise e.reason from None
        raise
