from __future__ import annotations

import base64
import hashlib
import hmac as _hmac
import json
import logging
import os
import re
import secrets
import tempfile
import threading
import time
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, cast

import bcrypt
from fastapi import HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

CREDS_FILE: Path = Path(__file__).parent / "credentials.json"
SECRET_KEY_FILE: Path = Path(__file__).parent / ".secret_key"
TOKEN_EXPIRY_HOURS: float = float(os.environ.get("PUYAD_TOKEN_EXPIRY_HOURS", "72.0"))
SECRET_KEY: str | None = None

HMAC_ALGORITHM: str = "sha256"
PAYLOAD_DELIM: str = "|"
TOKEN_SEGMENT_COUNT: int = 2
PAYLOAD_FIELD_COUNT: int = 4
_SIG_RE: re.Pattern[str] = re.compile(r"[0-9a-f]{64}")

_creds_lock: threading.Lock = threading.Lock()

_bearer: HTTPBearer = HTTPBearer(auto_error=False)
logger = logging.getLogger(__name__)

DEFAULT_USERNAME: str = "admin"
DEFAULT_PASSWORD: str = "puyad2026"


def _get_secret() -> str:
    global SECRET_KEY
    if SECRET_KEY:
        return SECRET_KEY

    env_key: str | None = os.environ.get("PUYAD_SECRET_KEY")
    if env_key:
        if len(env_key.strip()) < 16:
            raise RuntimeError("PUYAD_SECRET_KEY çok kısa (en az 16 karakter).")
        SECRET_KEY = env_key.strip()
        return SECRET_KEY

    secret_file: Path = SECRET_KEY_FILE
    if secret_file.exists():
        try:
            content = secret_file.read_text().strip()
        except OSError:
            content = ""
        if content and len(content) >= 32:
            SECRET_KEY = content
            return SECRET_KEY
        try:
            secret_file.unlink(missing_ok=True)
        except OSError:
            pass

    new_secret = secrets.token_hex(32)
    try:
        fd, tmp = tempfile.mkstemp(dir=str(secret_file.parent), prefix=".secret_key.tmp.")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(new_secret)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, str(secret_file))
    except OSError:
        try:
            secret_file.write_text(new_secret)
            secret_file.chmod(0o600)
        except OSError:
            pass
    SECRET_KEY = new_secret
    return SECRET_KEY


def _hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def _load_credentials() -> dict[str, Any]:
    if CREDS_FILE.exists():
        try:
            with open(CREDS_FILE, "r") as f:
                data: Any = json.load(f)
                loaded = cast(dict[str, Any], data)
                if "username" in loaded and "password_hash" in loaded:
                    return loaded
                raise ValueError("credentials.json eksik alan")
        except (OSError, json.JSONDecodeError, ValueError) as e:
            logger.error("Kimlik dosyası okunamadı (%s): %s", CREDS_FILE, e)
            raise HTTPException(
                status_code=500,
                detail="Kimlik dosyası bozuk — sunucu loguna bakın, dosyayı düzeltin veya silin.",
            ) from e
    default: dict[str, Any] = {
        "username": DEFAULT_USERNAME,
        "password_hash": _hash_password(DEFAULT_PASSWORD),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    _save_credentials(default)
    return default


def ensure_credentials() -> None:
    _load_credentials()


def _save_credentials(creds: dict[str, Any]) -> None:
    try:
        fd, tmp = tempfile.mkstemp(dir=str(CREDS_FILE.parent), prefix=".credentials.tmp.")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(creds, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, str(CREDS_FILE))
    except OSError:
        with open(CREDS_FILE, "w") as f:
            json.dump(creds, f, indent=2)
        try:
            CREDS_FILE.chmod(0o600)
        except OSError:
            pass


def _generate_jti() -> str:
    return secrets.token_hex(16)


def revoke_all_tokens() -> None:
    # Bellekte değil dosyada — yeniden başlatınca iptal edilen oturumlar geri gelmesin
    with _creds_lock:
        creds = _load_credentials()
        creds["sessions_valid_after"] = datetime.now(timezone.utc).isoformat()
        _save_credentials(creds)


def revoke_token(token: str) -> bool:
    # Tek kullanıcılı model — logout o kullanıcının tüm oturumlarını kapatıyor
    if verify_token(token) is None:
        return False
    revoke_all_tokens()
    return True


def create_token(username: str) -> str:
    if not username or "|" in username or ":" in username or "\n" in username:
        raise ValueError("Geçersiz kullanıcı adı (pipe/colon/newline içeremez).")
    now: datetime = datetime.now(timezone.utc)
    expiry: str = (now + timedelta(hours=TOKEN_EXPIRY_HOURS)).isoformat()
    iat: str = now.isoformat()
    jti: str = _generate_jti()
    payload: str = f"{username}{PAYLOAD_DELIM}{expiry}{PAYLOAD_DELIM}{iat}{PAYLOAD_DELIM}{jti}"
    payload_b64: str = base64.urlsafe_b64encode(payload.encode()).decode()
    sig: str = _hmac.new(
        _get_secret().encode(), payload_b64.encode(), hashlib.sha256
    ).hexdigest()
    return f"{payload_b64}.{sig}"


def verify_token(token: str) -> str | None:
    try:
        parts: list[str] = token.split(".")
        if len(parts) != TOKEN_SEGMENT_COUNT:
            return None
        payload_b64, sig = parts
        # compare_digest ASCII dışı str'de TypeError atıyor
        if not _SIG_RE.fullmatch(sig):
            return None
        expected: str = _hmac.new(
            _get_secret().encode(), payload_b64.encode(), hashlib.sha256
        ).hexdigest()
        if not _hmac.compare_digest(sig, expected):
            return None
        padded = payload_b64 + "=" * (-len(payload_b64) % 4)
        payload: str = base64.urlsafe_b64decode(padded).decode()
        fields: list[str] = payload.split(PAYLOAD_DELIM)
        if len(fields) != PAYLOAD_FIELD_COUNT:
            return None
        username, expiry_str, iat_str, _jti = fields
        now: datetime = datetime.now(timezone.utc)
        expiry_dt = datetime.fromisoformat(expiry_str)
        iat_dt = datetime.fromisoformat(iat_str)
        if expiry_dt.tzinfo is None:
            expiry_dt = expiry_dt.replace(tzinfo=timezone.utc)
        if iat_dt.tzinfo is None:
            iat_dt = iat_dt.replace(tzinfo=timezone.utc)
        if iat_dt > expiry_dt:
            return None
        if expiry_dt < now:
            return None
        if iat_dt > now + timedelta(minutes=5):
            return None
        if (expiry_dt - iat_dt) > timedelta(hours=TOKEN_EXPIRY_HOURS + 1):
            return None
        try:
            creds = _load_credentials()
            if username != creds.get("username"):
                return None
            for key in ("password_changed_at", "sessions_valid_after"):
                cutoff = creds.get(key)
                if not cutoff:
                    continue
                try:
                    cutoff_dt = datetime.fromisoformat(cutoff)
                    if cutoff_dt.tzinfo is None:
                        cutoff_dt = cutoff_dt.replace(tzinfo=timezone.utc)
                    if iat_dt < cutoff_dt:
                        return None
                except (ValueError, TypeError):
                    pass
        except HTTPException:
            return None
        return username
    except Exception:
        return None


def _check_password(stored_hash: str, password: str) -> bool:
    if stored_hash.startswith("$2"):
        return bcrypt.checkpw(password.encode(), stored_hash.encode())
    # Eski sha256 hash'ler — login sırasında bcrypt'e taşınıyor
    return _hmac.compare_digest(hashlib.sha256(password.encode()).hexdigest().encode(), stored_hash.encode())


LOCKOUT_THRESHOLD: int = 10
LOCKOUT_WINDOW_SECONDS: int = 15 * 60
LOCKOUT_SECONDS: int = 15 * 60

# IP başına rate limit proxy arkasında tek kova — hesap kilidi IP'den bağımsız
_failed_logins: list[float] = []
_locked_until: float = 0.0
_lockout_lock: threading.Lock = threading.Lock()
_unlock_timer: threading.Timer | None = None
_now: Callable[[], float] = time.monotonic


def _check_lockout() -> None:
    with _lockout_lock:
        remaining = _locked_until - _now()
    if remaining > 0:
        raise HTTPException(
            status_code=429,
            detail=f"Çok fazla başarısız giriş denemesi. Hesap {LOCKOUT_SECONDS // 60} dakika kilitli.",
            headers={"Retry-After": str(int(remaining) + 1)},
        )


def _record_failed_login() -> None:
    global _locked_until, _unlock_timer
    with _lockout_lock:
        now = _now()
        _failed_logins[:] = [t for t in _failed_logins if now - t < LOCKOUT_WINDOW_SECONDS]
        _failed_logins.append(now)
        if len(_failed_logins) < LOCKOUT_THRESHOLD:
            return
        _failed_logins.clear()
        _locked_until = now + LOCKOUT_SECONDS
        _unlock_timer = threading.Timer(LOCKOUT_SECONDS, _on_lockout_expired)
        _unlock_timer.daemon = True
        _unlock_timer.start()
    logger.warning(
        "%d başarısız giriş denemesi, hesap %d dakika kilitlendi.", LOCKOUT_THRESHOLD, LOCKOUT_SECONDS // 60
    )


def _on_lockout_expired() -> None:
    global _locked_until, _unlock_timer
    with _lockout_lock:
        if not _locked_until or _now() < _locked_until:
            return
        _locked_until = 0.0
        _unlock_timer = None
    logger.warning("Hesap kilidi kalktı, girişler yeniden kabul ediliyor.")
    try:
        from telegram_manager import PuyadTelegramManager

        if PuyadTelegramManager._is_enabled():
            PuyadTelegramManager.send_simple_message(
                f"Puyad Kalkanı: {LOCKOUT_THRESHOLD} başarısız giriş denemesi sonrası konan hesap kilidi kalktı."
            )
    except Exception as e:
        logger.warning("Kilit bildirimi Telegram'a gönderilemedi: %s", type(e).__name__)


def reset_lockout() -> None:
    global _locked_until, _unlock_timer
    with _lockout_lock:
        if _unlock_timer:
            _unlock_timer.cancel()
        _unlock_timer = None
        _locked_until = 0.0
        _failed_logins.clear()


def login(username: str, password: str) -> dict[str, Any]:
    if len(password) > 512:
        raise HTTPException(status_code=400, detail="Parola çok uzun.")
    if len(username) > 128 or "|" in username or ":" in username:
        raise HTTPException(status_code=400, detail="Geçersiz kullanıcı adı.")
    _check_lockout()
    creds: dict[str, Any] = _load_credentials()
    stored_hash: str = creds["password_hash"]
    password_ok = _check_password(stored_hash, password)
    if password_ok and not stored_hash.startswith("$2"):
        creds["password_hash"] = _hash_password(password)
        _save_credentials(creds)

    if username != creds["username"] or not password_ok:
        _record_failed_login()
        raise HTTPException(status_code=401, detail="Kullanıcı adı veya şifre hatalı.")
    with _lockout_lock:
        _failed_logins.clear()
    return {
        "access_token": create_token(username),
        "token_type": "bearer",
        "expires_in": TOKEN_EXPIRY_HOURS * 3600,
        "username": username,
    }


def change_password(username: str, old_password: str, new_password: str) -> dict[str, Any]:
    if len(old_password) > 512 or len(new_password) > 512:
        raise HTTPException(status_code=400, detail="Parola çok uzun (max 512).")
    creds: dict[str, Any] = _load_credentials()
    password_ok = _check_password(creds["password_hash"], old_password)
    if username != creds["username"] or not password_ok:
        raise HTTPException(status_code=401, detail="Mevcut şifre hatalı.")
    if len(new_password) < 8:
        raise HTTPException(status_code=400, detail="Yeni şifre en az 8 karakter olmalıdır.")
    if len(new_password) > 128:
        raise HTTPException(status_code=400, detail="Yeni şifre en fazla 128 karakter olabilir.")
    if new_password == old_password:
        raise HTTPException(status_code=400, detail="Yeni şifre eskisiyle aynı olamaz.")
    creds["password_hash"] = _hash_password(new_password)
    creds["password_changed_at"] = datetime.now(timezone.utc).isoformat()
    _save_credentials(creds)
    return {"success": True, "message": "Şifre başarıyla değiştirildi."}


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Security(_bearer),
) -> str:
    if not credentials:
        raise HTTPException(status_code=401, detail="Kimlik doğrulama gerekli.")
    username: str | None = verify_token(credentials.credentials)
    if not username:
        raise HTTPException(status_code=401, detail="Geçersiz veya süresi dolmuş token.")
    return username


STREAM_TICKET_TTL: int = 60
_stream_tickets: dict[str, tuple[str, float]] = {}
_stream_lock: threading.Lock = threading.Lock()


def create_stream_ticket(username: str) -> str:
    ticket = secrets.token_urlsafe(32)
    now = time.time()
    with _stream_lock:
        for k in [k for k, (_, exp) in _stream_tickets.items() if exp < now]:
            del _stream_tickets[k]
        _stream_tickets[ticket] = (username, now + STREAM_TICKET_TTL)
    return ticket


def consume_stream_ticket(ticket: str) -> str | None:
    with _stream_lock:
        entry = _stream_tickets.pop(ticket, None)
    if not entry or entry[1] < time.time():
        return None
    return entry[0]
