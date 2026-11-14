from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import tempfile
import threading
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, cast

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from fileutil import atomic_write_json

logger = logging.getLogger(__name__)
RATE_LIMIT_LOG_DIR: Path = Path(__file__).parent.parent / "logs"
RATE_LIMIT_LOG_FILE: Path = RATE_LIMIT_LOG_DIR / "rate_limit.log"
RATE_LIMIT_LOG_JSON: Path = RATE_LIMIT_LOG_DIR / "rate_limit.json"
RATE_LIMIT_LOG_MAX_SIZE: int = 10 * 1024 * 1024
RATE_LIMIT_LOG_MAX_ENTRIES: int = 2000
RATE_LIMIT_LOG_MAX_ARCHIVES: int = 5


def _sanitize_log_field(s: str, max_len: int = 200) -> str:
    s = re.sub(r"[\x00-\x1f\x7f]", "", s.replace("\n", " "))
    if len(s) > max_len:
        s = s[:max_len]
    return s


class RateLimitRule:
    __slots__ = ("block_seconds", "max_requests", "window_seconds")

    def __init__(self, max_requests: int, window_seconds: int, block_seconds: int = 300) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.block_seconds = block_seconds


class RateLimitEntry:
    __slots__ = ("blocked_until", "timestamps")

    def __init__(self) -> None:
        self.timestamps: list[float] = []
        self.blocked_until: float = 0.0


DEFAULT_RULES_CONFIG: dict[str, dict[str, int]] = {
    "auth":     {"max": 5,   "window": 60, "block": 300},
    "api":      {"max": 120, "window": 60, "block": 300},
    "heavy":    {"max": 20,  "window": 60, "block": 300},
    "export":   {"max": 10,  "window": 60, "block": 300},
    "telegram": {"max": 10,  "window": 60, "block": 600},
}


def _read_json_log() -> list[dict[str, Any]]:
    if not RATE_LIMIT_LOG_JSON.exists():
        return []
    try:
        with open(RATE_LIMIT_LOG_JSON, "r", encoding="utf-8") as f:
            return cast(list[dict[str, Any]], json.load(f))
    except (json.JSONDecodeError, OSError) as exc:
        logger.debug("Rate limit JSON logu okunamadı: %s", exc)
        return []


def _int_or(cfg: dict[str, Any], key: str, default: int) -> int:
    try:
        return int(cfg.get(key, default))
    except (ValueError, TypeError):
        return default


class RateLimitLogger:
    def __init__(self) -> None:
        self._lock: threading.Lock = threading.Lock()
        self._ensure_log_dir()

    def _ensure_log_dir(self) -> None:
        try:
            RATE_LIMIT_LOG_DIR.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(RATE_LIMIT_LOG_DIR, 0o700)
            except OSError:
                pass
        except OSError as exc:
            logger.debug("Rate limit log dizini oluşturulamadı: %s", exc)

    def log_blocked(self, client_ip: str, category: str, rule: RateLimitRule,
                    request_count: int, path: str = "", method: str = "") -> None:
        entry = {
            "timestamp": datetime.now().isoformat(),
            "event": "blocked",
            "ip": _sanitize_log_field(client_ip, 64),
            "category": _sanitize_log_field(category, 32),
            "limit": rule.max_requests,
            "window": rule.window_seconds,
            "block_duration": rule.block_seconds,
            "request_count": request_count,
            "path": _sanitize_log_field(path, 200),
            "method": _sanitize_log_field(method, 16),
        }
        self._write_log(entry)

    def log_blocked_attempt(self, client_ip: str, category: str,
                            retry_after: int, path: str = "", method: str = "") -> None:
        entry = {
            "timestamp": datetime.now().isoformat(),
            "event": "blocked_attempt",
            "ip": _sanitize_log_field(client_ip, 64),
            "category": _sanitize_log_field(category, 32),
            "retry_after": retry_after,
            "path": _sanitize_log_field(path, 200),
            "method": _sanitize_log_field(method, 16),
        }
        self._write_log(entry)

    def log_unblocked(self, client_ip: str, category: str) -> None:
        entry = {
            "timestamp": datetime.now().isoformat(),
            "event": "unblocked",
            "ip": _sanitize_log_field(client_ip, 64),
            "category": _sanitize_log_field(category, 32),
        }
        self._write_log(entry)

    def _write_log(self, entry: dict[str, Any]) -> None:
        with self._lock:
            try:
                self._write_json_log(entry)
                self._write_text_log(entry)
            except OSError as exc:
                logger.debug("Rate limit kaydı yazılamadı: %s", exc)

    def _write_json_log(self, entry: dict[str, Any]) -> None:
        entries = _read_json_log()
        entries.append(entry)

        if len(entries) > RATE_LIMIT_LOG_MAX_ENTRIES:
            entries = entries[-RATE_LIMIT_LOG_MAX_ENTRIES:]

        try:
            atomic_write_json(RATE_LIMIT_LOG_JSON, entries)
        except OSError as exc:
            logger.debug("Rate limit JSON loguna yazılamadı: %s", exc)

    def _write_text_log(self, entry: dict[str, Any]) -> None:
        event = _sanitize_log_field(str(entry.get("event", "unknown")), 32)
        ip = _sanitize_log_field(str(entry.get("ip", "unknown")), 64)
        category = _sanitize_log_field(str(entry.get("category", "unknown")), 32)
        ts = _sanitize_log_field(str(entry.get("timestamp", "")), 64)

        if event == "blocked":
            line = f"[{ts}] BLOCKED | IP: {ip} | Category: {category} | Limit: {entry.get('limit')}/{entry.get('window')}s | Block: {entry.get('block_duration')}s\n"
        elif event == "blocked_attempt":
            line = f"[{ts}] ATTEMPT | IP: {ip} | Category: {category} | Retry-After: {entry.get('retry_after')}s\n"
        elif event == "unblocked":
            line = f"[{ts}] UNBLOCKED | IP: {ip} | Category: {category}\n"
        else:
            line = f"[{ts}] {event.upper()} | IP: {ip} | Category: {category}\n"

        try:
            if RATE_LIMIT_LOG_FILE.exists() and RATE_LIMIT_LOG_FILE.stat().st_size > RATE_LIMIT_LOG_MAX_SIZE:
                archive = RATE_LIMIT_LOG_FILE.with_suffix(f".{int(time.time())}.log")
                RATE_LIMIT_LOG_FILE.rename(archive)
                try:
                    archives = sorted(RATE_LIMIT_LOG_DIR.glob("rate_limit.*.log"), key=lambda p: p.stat().st_mtime)
                    while len(archives) > RATE_LIMIT_LOG_MAX_ARCHIVES:
                        oldest = archives.pop(0)
                        try:
                            oldest.unlink()
                        except OSError:
                            pass
                except OSError:
                    pass
            write_new = not RATE_LIMIT_LOG_FILE.exists()
            with open(RATE_LIMIT_LOG_FILE, "a", encoding="utf-8") as f:
                f.write(line)
            if write_new:
                try:
                    os.chmod(RATE_LIMIT_LOG_FILE, 0o600)
                except OSError:
                    pass
        except OSError as exc:
            logger.debug("Rate limit metin loguna yazılamadı: %s", exc)

    def get_logs(self, limit: int = 100, event_filter: str | None = None,
                 ip_filter: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            entries = _read_json_log()

        if event_filter:
            entries = [e for e in entries if e.get("event") == event_filter]
        if ip_filter:
            entries = [e for e in entries if e.get("ip") == ip_filter]

        entries = entries[-limit:]
        entries.reverse()
        return entries

    def purge_older_than(self, cutoff: datetime) -> int:
        removed = 0
        cutoff_iso = cutoff.isoformat()
        with self._lock:
            entries = _read_json_log()
            kept = [e for e in entries if str(e.get("timestamp", "")) >= cutoff_iso]
            if len(kept) != len(entries):
                removed += len(entries) - len(kept)
                atomic_write_json(RATE_LIMIT_LOG_JSON, kept)
            if RATE_LIMIT_LOG_FILE.exists():
                with open(RATE_LIMIT_LOG_FILE, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                # Satır başı "[2026-01-01T...]" — ISO metin karşılaştırması tarih sırasıyla aynı
                kept_lines = [ln for ln in lines if not ln.startswith("[") or ln[1:ln.find("]")] >= cutoff_iso]
                if len(kept_lines) != len(lines):
                    removed += len(lines) - len(kept_lines)
                    fd, tmp = tempfile.mkstemp(dir=str(RATE_LIMIT_LOG_DIR), prefix=".rate_limit.tmp.")
                    with os.fdopen(fd, "w", encoding="utf-8") as f:
                        f.writelines(kept_lines)
                    os.chmod(tmp, 0o600)
                    os.replace(tmp, str(RATE_LIMIT_LOG_FILE))
            for archive in RATE_LIMIT_LOG_DIR.glob("rate_limit.*.log"):
                if archive.stat().st_mtime < cutoff.timestamp():
                    archive.unlink()
                    removed += 1
        return removed

    def get_text_logs(self, lines: int = 50) -> list[str]:
        if not RATE_LIMIT_LOG_FILE.exists():
            return []

        try:
            with open(RATE_LIMIT_LOG_FILE, "r", encoding="utf-8") as f:
                all_lines = f.readlines()
            return [line.rstrip("\n") for line in all_lines[-lines:]]
        except OSError as exc:
            logger.debug("Rate limit metin logu okunamadı: %s", exc)
            return []

    def get_stats(self) -> dict[str, Any]:
        entries = _read_json_log()
        by_event: dict[str, int] = defaultdict(int)
        by_ip: dict[str, int] = defaultdict(int)
        by_category: dict[str, int] = defaultdict(int)

        for entry in entries:
            by_event[entry.get("event", "unknown")] += 1
            by_ip[entry.get("ip", "unknown")] += 1
            by_category[entry.get("category", "unknown")] += 1

        return {
            "total": len(entries),
            "by_event": dict(by_event),
            "by_ip": dict(by_ip),
            "by_category": dict(by_category),
        }

    def clear_logs(self) -> None:
        with self._lock:
            try:
                if RATE_LIMIT_LOG_JSON.exists():
                    RATE_LIMIT_LOG_JSON.unlink()
                if RATE_LIMIT_LOG_FILE.exists():
                    RATE_LIMIT_LOG_FILE.unlink()
                for p in RATE_LIMIT_LOG_DIR.glob("rate_limit.*.log"):
                    try:
                        p.unlink()
                    except OSError:
                        pass
            except OSError as exc:
                logger.debug("Rate limit logları temizlenemedi: %s", exc)


class RateLimiter:
    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self._store: dict[str, dict[str, RateLimitEntry]] = defaultdict(
            lambda: defaultdict(RateLimitEntry)
        )
        self._rules: dict[str, RateLimitRule] = {}
        self._enabled: bool = True
        self._lock: threading.Lock = threading.Lock()
        self._last_cleanup: float = time.time()
        self._cleanup_interval: float = 300
        self.logger: RateLimitLogger = RateLimitLogger()

        self.reload_from_config(config)

    def reload_from_config(self, config: dict[str, Any] | None = None) -> dict[str, Any]:
        if config is None:
            try:
                from config import load_config
                cfg = load_config()
            except Exception:
                cfg = {}
        else:
            cfg = config

        self._enabled = cfg.get("RATE_LIMIT_ENABLED", True)

        with self._lock:
            for category, defaults in DEFAULT_RULES_CONFIG.items():
                prefix = f"RATE_LIMIT_{category.upper()}"
                self._rules[category] = RateLimitRule(
                    max_requests=_int_or(cfg, f"{prefix}_MAX", defaults["max"]),
                    window_seconds=_int_or(cfg, f"{prefix}_WINDOW", defaults["window"]),
                    block_seconds=_int_or(cfg, f"{prefix}_BLOCK", defaults["block"]),
                )

        return self.get_current_rules()

    def get_current_rules(self) -> dict[str, Any]:
        with self._lock:
            return {
                "enabled": self._enabled,
                "rules": {
                    cat: {
                        "max_requests": rule.max_requests,
                        "window_seconds": rule.window_seconds,
                        "block_seconds": rule.block_seconds,
                    }
                    for cat, rule in self._rules.items()
                },
            }

    def set_rule(self, category: str, max_requests: int, window_seconds: int,
                 block_seconds: int = 300) -> None:
        with self._lock:
            self._rules[category] = RateLimitRule(max_requests, window_seconds, block_seconds)

    def _cleanup_old_entries(self) -> None:
        now = time.time()
        if now - self._last_cleanup < self._cleanup_interval:
            return
        self._last_cleanup = now

        max_window = max((r.window_seconds for r in self._rules.values()), default=60)
        expired_cutoff = now - max_window - 60
        for ip in list(self._store.keys()):
            for cat in list(self._store[ip].keys()):
                entry = self._store[ip][cat]
                entry.timestamps = [t for t in entry.timestamps if t > expired_cutoff]
                if not entry.timestamps and entry.blocked_until < now:
                    del self._store[ip][cat]
            if not self._store[ip]:
                del self._store[ip]

    def check(self, client_ip: str, category: str = "api",
              path: str = "", method: str = "") -> tuple[bool, dict[str, Any]]:
        if not self._enabled:
            return True, {
                "limit": 0, "remaining": 0, "retry_after": 0,
                "reset": 0, "blocked": False, "disabled": True,
            }

        log_blocked: tuple[str, str, RateLimitRule, int, str, str] | None = None
        log_attempt: tuple[str, str, int, str, str] | None = None
        result: tuple[bool, dict[str, Any]] | None = None

        with self._lock:
            self._cleanup_old_entries()

            rule = self._rules.get(category, self._rules["api"])

            now = time.time()
            entry = self._store[client_ip][category]

            if entry.blocked_until > now:
                retry_after = int(entry.blocked_until - now) + 1
                log_attempt = (client_ip, category, retry_after, path, method)
                result = (False, {
                    "limit": rule.max_requests,
                    "remaining": 0,
                    "retry_after": retry_after,
                    "reset": int(entry.blocked_until),
                    "blocked": True,
                })
            else:
                window_start = now - rule.window_seconds
                entry.timestamps = [t for t in entry.timestamps if t > window_start]

                if len(entry.timestamps) >= rule.max_requests:
                    entry.blocked_until = now + rule.block_seconds
                    entry.timestamps = []
                    log_blocked = (client_ip, category, rule, rule.max_requests, path, method)
                    result = (False, {
                        "limit": rule.max_requests,
                        "remaining": 0,
                        "retry_after": rule.block_seconds,
                        "reset": int(now + rule.block_seconds),
                        "blocked": True,
                    })
                else:
                    entry.timestamps.append(now)
                    remaining = rule.max_requests - len(entry.timestamps)
                    reset_time = int(now + rule.window_seconds)
                    result = (True, {
                        "limit": rule.max_requests,
                        "remaining": remaining,
                        "retry_after": 0,
                        "reset": reset_time,
                        "blocked": False,
                    })

        if log_attempt is not None:
            try:
                self.logger.log_blocked_attempt(*log_attempt)
            except Exception:
                pass
        if log_blocked is not None:
            try:
                self.logger.log_blocked(*log_blocked)
            except Exception:
                pass

        assert result is not None
        return result

    def get_stats(self) -> dict[str, Any]:
        with self._lock:
            now = time.time()
            stats: dict[str, Any] = {}
            for ip, categories in self._store.items():
                stats[ip] = {}
                for cat, entry in categories.items():
                    rule = self._rules.get(cat)
                    stats[ip][cat] = {
                        "requests": len(entry.timestamps),
                        "limit": rule.max_requests if rule else 0,
                        "blocked": entry.blocked_until > now,
                    }
            return stats

    def reset(self, client_ip: str | None = None, category: str | None = None) -> None:
        with self._lock:
            if client_ip is None:
                self._store.clear()
            elif category is None:
                self._store.pop(client_ip, None)
            else:
                if client_ip in self._store:
                    self._store[client_ip].pop(category, None)

        if client_ip:
            self.logger.log_unblocked(client_ip, category or "all")


limiter = RateLimiter()


TRUSTED_PROXIES: set[str] = {"127.0.0.1", "::1", "::ffff:127.0.0.1"}


def _get_client_ip(request: Request) -> str:
    if request.client:
        return request.client.host
    return "unknown"


def _get_forwarded_ip(request: Request) -> str | None:
    client_host = request.client.host if request.client else None
    is_trusted = client_host in TRUSTED_PROXIES if client_host else False
    if is_trusted:
        fwd = request.headers.get("X-Forwarded-For")
        # Soldaki öğeleri istemci yazabilir — güvenilen proxy'nin eklediği en sağdaki
        if fwd:
            return _sanitize_log_field(fwd.split(",")[-1].strip(), 64)
    return None


def _is_loopback(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return addr.is_loopback


def _limit_key(request: Request) -> tuple[str, bool]:
    host = _get_client_ip(request)
    if "X-Forwarded-For" not in request.headers:
        return host, _is_loopback(host)
    fwd = _get_forwarded_ip(request)
    if fwd is None:
        return host, False
    try:
        ip = str(ipaddress.ip_address(fwd))
    except ValueError:
        return host, False
    # Dev proxy XFF ekliyor; sağdaki adres loopback ise istek yerelden
    return ip, _is_loopback(ip)


def rate_limit(category: str = "api") -> Any:
    from fastapi import Depends

    async def _check(request: Request) -> dict[str, Any]:
        client_ip = _get_client_ip(request)
        allowed, info = limiter.check(
            client_ip, category,
            path=request.scope["path"],
            method=request.method,
        )

        if not allowed:
            raise HTTPException(
                status_code=429,
                detail={
                    "error": "Çok fazla istek gönderdiniz. Lütfen bekleyin.",
                    "retry_after": info["retry_after"],
                    "limit": info["limit"],
                },
                headers={
                    "Retry-After": str(info["retry_after"]),
                    "X-RateLimit-Limit": str(info["limit"]),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(info["reset"]),
                },
            )

        return info

    return Depends(_check)


def rate_limit_middleware(app: Any) -> None:
    @app.middleware("http")  # type: ignore[untyped-decorator]
    async def _global_throttle(request: Request, call_next: Any) -> Any:
        if not limiter._enabled:
            return await call_next(request)

        client_ip, local = _limit_key(request)
        path = request.scope["path"]

        skip_paths = ("/api/health", "/docs", "/openapi.json", "/redoc")
        if any(path.startswith(p) for p in skip_paths):
            return await call_next(request)
        if local and path.lower().rstrip("/") != "/api/auth/login":
            return await call_next(request)

        category = _categorize_path(path)

        allowed, info = limiter.check(
            client_ip, category,
            path=path,
            method=request.method,
        )

        if not allowed:
            return JSONResponse(
                status_code=429,
                content={
                    "error": "Çok fazla istek gönderdiniz. Lütfen bekleyin.",
                    "detail": f"Rate limit aşıldı ({category}).",
                    "retry_after": info["retry_after"],
                    "limit": info["limit"],
                },
                headers={
                    "Retry-After": str(info["retry_after"]),
                    "X-RateLimit-Limit": str(info["limit"]),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(info["reset"]),
                },
            )

        response = await call_next(request)

        response.headers["X-RateLimit-Limit"] = str(info["limit"])
        response.headers["X-RateLimit-Remaining"] = str(info["remaining"])
        response.headers["X-RateLimit-Reset"] = str(info["reset"])

        return response


def _categorize_path(path: str) -> str:
    p = path.lower()
    if "/auth/" in p:
        return "auth"
    if "/telegram/" in p:
        return "telegram"
    if any(kw in p for kw in ["/scan", "/cve", "/forensic", "/network", "/fix", "/snapshots", "/honeypot"]):
        return "heavy"
    if "/report/" in p or "/pdf" in p:
        return "export"
    return "api"
