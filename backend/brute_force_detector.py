from __future__ import annotations

import re
import threading
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any

import database

_BRUTEFORCE_DDL: str = """CREATE TABLE IF NOT EXISTS bruteforce_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    src_ip TEXT NOT NULL,
    attempts INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT (datetime('now','localtime'))
)"""

THRESHOLD: int = 5
WINDOW_MINUTES: int = 15

_failed_attempts: dict[str, list[datetime]] = defaultdict(list)
_lock: threading.Lock = threading.Lock()

_AUTH_LOG_PATHS: list[str] = ["/var/log/auth.log", "/var/log/secure"]
_IP_RE: re.Pattern[str] = re.compile(r"from\s+(\d+\.\d+\.\d+\.\d+)")
_KEYWORDS: list[str] = ["Failed password", "authentication failure"]


def _get_auth_failures() -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for log_path in _AUTH_LOG_PATHS:
        try:
            with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                lines: list[str] = f.readlines()
        except Exception:
            continue
        for line in lines:
            lower = line.lower()
            if not any(kw.lower() in lower for kw in _KEYWORDS):
                continue
            match: re.Match[str] | None = _IP_RE.search(line)
            if not match:
                continue
            ip: str = match.group(1).strip()
            results.append({
                "ip": ip,
                "timestamp": datetime.now().isoformat(),
                "line": line.strip(),
            })
    return results


def _save_bruteforce_log(src_ip: str, attempts: int) -> None:
    try:
        with database.get_connection() as conn:
            conn.execute(_BRUTEFORCE_DDL)
            conn.execute(
                "INSERT INTO bruteforce_log (src_ip, attempts) VALUES (?, ?)",
                (src_ip, attempts),
            )
    except Exception:
        pass


def check_brute_force() -> list[dict[str, Any]]:
    failures: list[dict[str, Any]] = _get_auth_failures()
    now: datetime = datetime.now()
    cutoff: datetime = now - timedelta(minutes=WINDOW_MINUTES)

    to_alert: list[tuple[str, int]] = []
    with _lock:
        for entry in failures:
            ip = entry["ip"]
            _failed_attempts[ip].append(now)

        for ip in list(_failed_attempts.keys()):
            _failed_attempts[ip] = [t for t in _failed_attempts[ip] if t > cutoff]
            if not _failed_attempts[ip]:
                del _failed_attempts[ip]

        for ip, timestamps in _failed_attempts.items():
            if len(timestamps) >= THRESHOLD:
                to_alert.append((ip, len(timestamps)))

    if not to_alert:
        return []

    alerts: list[dict[str, Any]] = []
    for src_ip, attempts in to_alert:
        message: str = f"{src_ip} adresinden {attempts} başarısız giriş denemesi algılandı."
        alert: dict[str, Any] = {
            "ip": src_ip,
            "attempts": attempts,
            "message": message,
            "type": "BruteForce Attack",
            "timestamp": now.isoformat(),
        }
        alerts.append(alert)

        _save_bruteforce_log(src_ip, attempts)

        try:
            import forensic_manager

            threading.Thread(
                target=forensic_manager.PuyadForensicManager.collect_evidence,
                args=(f"BruteForce Alert: {src_ip}", 1),
                daemon=True,
            ).start()
        except Exception:
            pass

        try:
            from telegram_manager import PuyadTelegramManager

            PuyadTelegramManager.send_approval_notification(
                "BruteForce Saldırı Tespiti",
                f"<b>{src_ip}</b> adresinden {attempts} başarısız deneme.",
                "block_ip",
                {"ip": src_ip},
            )
        except Exception:
            pass

    with _lock:
        for src_ip, _ in to_alert:
            _failed_attempts.pop(src_ip, None)

    return alerts


def get_recent_alerts(limit: int = 50) -> list[dict[str, Any]]:
    try:
        with database.get_connection() as conn:
            conn.execute(_BRUTEFORCE_DDL)
            rows = conn.execute(
                "SELECT * FROM bruteforce_log ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]
    except Exception:
        return []


def clear_attempts(src_ip: str | None = None) -> None:
    with _lock:
        if src_ip is None:
            _failed_attempts.clear()
        else:
            _failed_attempts.pop(src_ip, None)
