from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import threading
import time

from fastapi import HTTPException, Request

HMAC_ALGORITHM: str = "sha256"
HMAC_WINDOW_SECONDS: int = 300
_LOOPBACK_IPS: set[str] = {"127.0.0.1", "localhost", "::1", "::ffff:127.0.0.1"}
# Eski veya varsayılan secret değerleri — bunlar kabul edilmez
_WEAK_SECRETS: frozenset[str] = frozenset({
    "puyad-secure-key-degistirin",
    "guclu-bir-secret-key-buraya-yazin",
    "BURAYA_BACKEND_AGENT_SHARED_SECRET_DEGERI_YAZILMALI",
    "",
})

_WEAK_SECRETS_NORMALIZED: frozenset[str] = frozenset(s.lower() for s in _WEAK_SECRETS)

_used_nonces: dict[str, float] = {}
_nonce_lock: threading.Lock = threading.Lock()
_NONCE_MAX: int = 16384
_NONCE_RE: re.Pattern[str] = re.compile(r"[0-9a-f]{16,64}")
SIGNATURE_VERSION: str = "v3"
# Ajandan controller'a giden isteklerin hedefi — controller tek, kimliği sabit
CONTROLLER_TARGET: str = "controller"
AGENT_ID_RE: re.Pattern[str] = re.compile(r"[A-Za-z0-9_-]{8,64}")
_SIG_RE: re.Pattern[str] = re.compile(r"[0-9a-f]{64}")


def is_weak_secret(secret: str) -> bool:
    # "  Puyad-Secure-Key-Degistirin " gibi varyasyonlar da örnek değer sayılır
    return secret.strip().lower() in _WEAK_SECRETS_NORMALIZED


def is_loopback_ip(ip: str) -> bool:
    clean = ip.strip().lower()
    return clean in _LOOPBACK_IPS or clean.startswith("127.") or clean.startswith("::ffff:127.")


def signing_payload(
    ts: str, nonce: str, method: str, path: str, body: bytes | str, target: str = CONTROLLER_TARGET
) -> str:
    raw = body.encode("utf-8") if isinstance(body, str) else body
    digest = hashlib.sha256(raw).hexdigest()
    return f"{SIGNATURE_VERSION}.{ts}.{nonce}.{target}.{method.upper()}.{path}.{digest}"


def build_agent_headers(
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


def _store_nonce(nonce: str, expires_at: float, now_ts: float) -> None:
    with _nonce_lock:
        for k in [k for k, exp in _used_nonces.items() if exp < now_ts]:
            del _used_nonces[k]
        if nonce in _used_nonces:
            raise HTTPException(status_code=401, detail="Nonce tekrar kullanıldı (replay).")
        # Pencere içindeki nonce tahliye edilirse replay mümkün olur — doluysa reddet
        if len(_used_nonces) >= _NONCE_MAX:
            raise HTTPException(status_code=503, detail="Nonce kapasitesi dolu, kısa süre sonra tekrar deneyin.")
        _used_nonces[nonce] = expires_at


async def verify_agent_request(request: Request, secret: str) -> None:
    if is_weak_secret(secret):
        raise HTTPException(status_code=500, detail="Ajan sırrı yapılandırılmamış — AGENT_SHARED_SECRET değiştirilmeli.")

    ts_raw: str | None = request.headers.get("x-puyad-timestamp")
    nonce: str | None = request.headers.get("x-puyad-nonce")
    sig: str | None = request.headers.get("x-puyad-signature")

    if not ts_raw or not nonce or not sig:
        raise HTTPException(status_code=401, detail="Agent kimlik doğrulama başlıkları eksik.")

    try:
        ts_int: int = int(ts_raw)
    except ValueError:
        raise HTTPException(status_code=401, detail="Geçersiz timestamp.")

    now_ts: float = time.time()
    if abs(now_ts - ts_int) > HMAC_WINDOW_SECONDS:
        raise HTTPException(status_code=401, detail="İmza zaman aşımına uğradı (replay koruması).")

    if not _NONCE_RE.fullmatch(nonce):
        raise HTTPException(status_code=401, detail="Geçersiz nonce.")
    # ASCII dışı str compare_digest'te TypeError fırlatıyor — 500 yerine 401 dönsün
    if not _SIG_RE.fullmatch(sig):
        raise HTTPException(status_code=401, detail="Geçersiz agent imzası.")

    path: str = request.scope["path"]
    query: bytes = request.scope.get("query_string", b"")
    if query:
        path = f"{path}?{query.decode('latin-1')}"
    body: bytes = await request.body()

    payload = signing_payload(ts_raw, nonce, request.method, path, body)
    expected = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig):
        raise HTTPException(status_code=401, detail="Geçersiz agent imzası.")

    _store_nonce(nonce, ts_int + HMAC_WINDOW_SECONDS, now_ts)


def reset_nonce_cache() -> None:
    with _nonce_lock:
        _used_nonces.clear()
