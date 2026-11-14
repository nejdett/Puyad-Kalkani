from __future__ import annotations

import html
import json
import logging
import os
import re
import socket
import subprocess
import threading
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, cast

import backup_manager
import compat
import config as app_config
import database
from fileutil import atomic_write_json
import firewall
import forensic_manager
import honeypot_services

logger = logging.getLogger(__name__)

_active_pots: dict[int, dict[str, Any]] = {}
_lock: threading.Lock = threading.Lock()
_pool: ThreadPoolExecutor = ThreadPoolExecutor(max_workers=50, thread_name_prefix="honeypot-conn")

ALLOWED_SERVICES: set[str] = {"ftp", "telnet", "ssh", "http", "smtp", "custom"}

_failed_attempts: defaultdict[str, list[datetime]] = defaultdict(list)

_FORENSIC_IP_COOLDOWN_SECONDS: int = 600
_FORENSIC_MAX_PER_HOUR: int = 6
_last_forensic_by_ip: dict[str, datetime] = {}
_forensic_runs: list[datetime] = []

_last_prune: datetime | None = None


def _threshold() -> tuple[int, int]:
    cfg = app_config.load_config()
    try:
        count = int(cfg.get("HONEYPOT_AUTOBLOCK_COUNT", 5))
        minutes = int(cfg.get("HONEYPOT_AUTOBLOCK_MINUTES", 15))
    except (TypeError, ValueError):
        return 5, 15
    return max(2, count), max(1, minutes)


def _prune_failed_attempts(now: datetime, minutes: int) -> None:
    global _last_prune
    if _last_prune is not None and (now - _last_prune).total_seconds() < 60:
        return
    _last_prune = now
    cutoff = now - timedelta(minutes=minutes)
    for ip in list(_failed_attempts.keys()):
        _failed_attempts[ip] = [t for t in _failed_attempts[ip] if t > cutoff]
        if not _failed_attempts[ip]:
            _failed_attempts.pop(ip, None)


def _should_run_forensic(src_ip: str, now: datetime) -> bool:
    with _lock:
        last_ip: datetime | None = _last_forensic_by_ip.get(src_ip)
        if last_ip is not None and (now - last_ip).total_seconds() < _FORENSIC_IP_COOLDOWN_SECONDS:
            return False
        hour_ago = now - timedelta(hours=1)
        _forensic_runs[:] = [t for t in _forensic_runs if t > hour_ago]
        # Farklı IP'lerden gelen tarama her bağlantıda ps/ss çalıştırmasın
        if len(_forensic_runs) >= _FORENSIC_MAX_PER_HOUR:
            return False
        _last_forensic_by_ip[src_ip] = now
        _forensic_runs.append(now)
        if len(_last_forensic_by_ip) > 1024:
            cutoff: datetime = now - timedelta(seconds=_FORENSIC_IP_COOLDOWN_SECONDS)
            for k in list(_last_forensic_by_ip.keys()):
                v: datetime | None = _last_forensic_by_ip.get(k)
                if v is not None and v < cutoff:
                    _last_forensic_by_ip.pop(k, None)
        return True


CONFIG_FILE: Path = Path(__file__).parent / "honeypot_config.json"

def load_config() -> list[dict[str, Any]]:
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                data: Any = json.load(f)
                return cast(list[dict[str, Any]], data)
        except (json.JSONDecodeError, OSError) as exc:
            logger.debug("Honeypot yapılandırması okunamadı: %s", exc)
    return []


def save_config(pots: list[dict[str, Any]]) -> None:
    try:
        atomic_write_json(CONFIG_FILE, pots)
    except OSError as exc:
        logger.warning("Honeypot yapılandırması kaydedilemedi: %s", exc)


def _ensure_table() -> None:
    with database.get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS honeypot_hits (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                port       INTEGER NOT NULL,
                service    TEXT,
                src_ip     TEXT NOT NULL,
                src_port   INTEGER,
                data       TEXT,
                created_at DATETIME DEFAULT (datetime('now','localtime'))
            )
        """)


def _log_hit(port: int, service: str, src_ip: str, src_port: int, data: str = "") -> None:
    data = data.replace("\r", " ").replace("\n", " ")[:500]
    _ensure_table()
    with database.get_connection() as conn:
        conn.execute(
            "INSERT INTO honeypot_hits (port, service, src_ip, src_port, data) VALUES (?,?,?,?,?)",
            (port, service, src_ip, src_port, data)
        )


def get_hits(limit: int = 100) -> list[dict[str, Any]]:
    _ensure_table()
    limit = max(1, min(limit, 1000))
    with database.get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM honeypot_hits ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


def get_hits_since(since_id: int, limit: int = 100) -> list[dict[str, Any]]:
    _ensure_table()
    limit = max(1, min(limit, 1000))
    with database.get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM honeypot_hits WHERE id > ? ORDER BY id ASC LIMIT ?",
            (since_id, limit)
        ).fetchall()
    return [dict(r) for r in rows]


def _handle_connection(conn_sock: socket.socket, addr: tuple[str, int], port: int, service: str) -> None:
    src_ip: str = addr[0]
    src_port: int = addr[1]
    data: str = ""

    try:
        data = honeypot_services.run(conn_sock, service, port).decode("utf-8", errors="replace").strip()
    except Exception:
        logger.exception("Honeypot oturumu beklenmedik şekilde bitti: port %d", port)
    finally:
        try:
            conn_sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            conn_sock.close()
        except OSError:
            pass

    _log_hit(port, service, src_ip, src_port, data)

    now: datetime = datetime.now()
    should_alert: bool = False
    attempt_count: int = 0
    limit, minutes = _threshold()
    with _lock:
        _failed_attempts[src_ip].append(now)
        cutoff: datetime = now - timedelta(minutes=minutes)
        _failed_attempts[src_ip] = [t for t in _failed_attempts[src_ip] if t > cutoff]
        if not _failed_attempts[src_ip]:
            _failed_attempts.pop(src_ip, None)
        else:
            attempt_count = len(_failed_attempts[src_ip])
            if attempt_count >= limit:
                should_alert = True
                _failed_attempts.pop(src_ip, None)
        _prune_failed_attempts(now, minutes)

    # U+0085/U+2028/U+2029 de splitlines() ile satır bölüyor — yazdırılamayan her şey boşluk
    safe_data = html.escape("".join(c if c.isprintable() else " " for c in data[:80])) if data else ""
    msg: str = (
        f"HONEYPOT HIT | Port: {port} ({service.upper()}) | "
        f"Kaynak: {src_ip}:{src_port}"
        + (f" | Veri: {safe_data}" if safe_data else "")
    )
    logger.warning(msg)

    if should_alert:
        _on_threshold(src_ip, src_port, port, service, attempt_count, minutes)

    if not _should_run_forensic(src_ip, now):
        return

    try:
        threading.Thread(
            target=forensic_manager.PuyadForensicManager.collect_evidence,
            args=("HoneyPot Alert", 1),
            daemon=True
        ).start()
    except Exception:
        pass


def _on_threshold(src_ip: str, src_port: int, port: int, service: str, count: int, minutes: int) -> None:
    try:
        if firewall.is_protected(src_ip):
            logger.info("Eşik aşıldı ama %s korumalı listede, işlem yapılmadı.", src_ip)
            return
    except Exception:
        logger.exception("Koruma listesi kontrol edilemedi: %s", src_ip)
        return
    from telegram_manager import PuyadTelegramManager
    detail = (
        f"Saldırı Kaynağı: <b>{html.escape(src_ip)}:{src_port}</b>\n"
        f"Port: {port} ({html.escape(service.upper())})\n"
        f"<b>{count}</b> deneme / {minutes} dk eşik aşıldı."
    )
    if not app_config.load_config().get("HONEYPOT_AUTOBLOCK_ENABLED"):
        try:
            PuyadTelegramManager.send_approval_notification("HoneyPot Saldırı Tespiti", detail, "block_ip", {"ip": src_ip})
        except Exception:
            pass
        return

    if not backup_manager.SYSTEM_CHANGE_LOCK.acquire(timeout=30):
        logger.warning("Otomatik engel atlandı, başka bir sistem değişikliği sürüyor: %s", src_ip)
        return
    try:
        res = firewall.block(src_ip, f"Honeypot {port}/{service}: {count} bağlantı / {minutes} dk", "auto")
    finally:
        backup_manager.SYSTEM_CHANGE_LOCK.release()
    if not res["success"]:
        logger.warning("Otomatik engel başarısız: %s", src_ip)
        return
    try:
        PuyadTelegramManager.send_simple_message(
            f"<b>HoneyPot otomatik engel</b>\n{detail}\nBitiş: {html.escape(str(res['expires_at']))}"
        )
    except Exception:
        pass


def _server_loop(port: int, service: str, stop_event: threading.Event) -> None:
    srv: socket.socket | None = None
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", port))  # nosec B104 honeypot dışarıyı dinler
        srv.listen(10)
        srv.settimeout(1.0)
    except OSError as exc:
        logger.warning("Honeypot %d portunu dinleyemedi: %s", port, exc)
        with _lock:
            _active_pots.pop(port, None)
        if srv is not None:
            try:
                srv.close()
            except OSError:
                pass
        return

    with _lock:
        if port in _active_pots:
            _active_pots[port]["server"] = srv

    while not stop_event.is_set():
        try:
            client_sock: socket.socket
            addr: tuple[str, int]
            client_sock, addr = srv.accept()
            try:
                _pool.submit(_handle_connection, client_sock, addr, port, service)
            except RuntimeError:
                t = threading.Thread(target=_handle_connection, args=(client_sock, addr, port, service), daemon=True)
                t.start()
        except TimeoutError:
            continue
        except OSError as exc:
            logger.debug("Honeypot %d portunda bağlantı kabulü durdu: %s", port, exc)
            break

    try:
        srv.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        srv.close()
    except OSError:
        pass


def _port_status(port: int, status: str, message: str, *, is_active: bool = False, can_bind: bool = False,
                 service_name: str | None = None, pid: int | None = None, protocol: str | None = None) -> dict[str, Any]:
    return {
        "port": port,
        "status": status,
        "is_active": is_active,
        "service_name": service_name,
        "pid": pid,
        "protocol": protocol,
        "can_bind": can_bind,
        "is_privileged": 1 <= port < 1024,
        "message": message,
    }


def check_port_status(port: int) -> dict[str, Any]:
    if not 1 <= port <= 65535:
        return _port_status(port, "invalid", f"Port {port} geçersiz (1-65535 aralığında olmalıdır).")

    with _lock:
        if port in _active_pots:
            pot_cfg: dict[str, Any] = _active_pots[port].get("config", {})
            svc = str(pot_cfg.get("service", "custom")).upper()
            lbl = str(pot_cfg.get("label", ""))
            return _port_status(
                port, "honeypot_active",
                f"Port {port} halihazırda Puyad Honeypot ({svc}) olarak aktif ({lbl or 'Tuzak'}).",
                is_active=True, service_name=f"Puyad Honeypot ({svc})", pid=os.getpid(), protocol="TCP",
            )

    ss_active = False
    service_name: str | None = None
    pid: int | None = None
    protocol: str | None = None

    try:
        r: subprocess.CompletedProcess[str] = subprocess.run(
            ["ss", "-tunlpn", f"sport = :{port}"],
            executable=compat.need_cmd("ss"),
            capture_output=True,
            text=True,
            timeout=3,
        )
        if r.returncode == 0:
            lines = [line.strip() for line in r.stdout.strip().splitlines() if line.strip()]
            if len(lines) > 1:
                ss_active = True
                first_line = lines[1]
                parts = first_line.split()
                if parts:
                    protocol = parts[0].upper()
                pm = re.search(r'users:\(\(\"([^\"]+)\",pid=(\d+)', first_line)
                if pm:
                    service_name = pm.group(1)
                    try:
                        pid = int(pm.group(2))
                    except ValueError:
                        pass
    except Exception as exc:
        logger.debug("%d portu ss ile kontrol edilemedi: %s", port, exc)

    can_bind = False
    permission_denied = False

    try:
        test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        test_sock.bind(("0.0.0.0", port))  # nosec B104 port denemesi
        test_sock.close()
        can_bind = True
    except PermissionError:
        permission_denied = True
    except OSError:
        pass

    if permission_denied:
        return _port_status(
            port, "permission_denied",
            f"Port {port} 1024 altında ayrıcalıklı bir porttur. Bağlamak için root yetkisi gereklidir.",
            service_name=service_name, pid=pid, protocol=protocol,
        )

    if ss_active or not can_bind:
        svc_desc = service_name or "Bilinmeyen Servis"
        pid_desc = f" (PID: {pid})" if pid else ""
        return _port_status(
            port, "active",
            f"Port {port} sistemde aktif olarak dinleniyor ({svc_desc}{pid_desc}). Çakışmayı önlemek için honeypot kurulamaz.",
            is_active=True, service_name=service_name, pid=pid, protocol=protocol or "TCP",
        )

    priv_note = " (Ayrıcalıklı Port, Root İzni Doğrulandı)" if port < 1024 else ""
    return _port_status(
        port, "available",
        f"Port {port} deaktif (boşta){priv_note} — honeypot için kullanılabilir.",
        can_bind=True,
    )


def start_honeypot(port: int, service: str = "custom", label: str = "") -> dict[str, Any]:
    if not 1 <= port <= 65535:
        return {"success": False, "message": f"Port {port} geçersiz (1-65535)."}
    if service not in ALLOWED_SERVICES:
        return {"success": False, "message": f"Geçersiz servis: {service}."}
    with _lock:
        if port in _active_pots:
            return {"success": False, "message": f"Port {port} zaten aktif."}

    chk: dict[str, Any] = check_port_status(port)
    if not chk.get("can_bind", False):
        return {
            "success": False,
            "message": str(chk.get("message", f"Port {port} başka bir servis tarafından kullanılıyor.")),
            "port_status": chk,
        }

    stop_event: threading.Event = threading.Event()

    t: threading.Thread = threading.Thread(
        target=_server_loop,
        args=(port, service, stop_event),
        daemon=True
    )

    with _lock:
        _active_pots[port] = {
            "thread": t,
            "stop_event": stop_event,
            "server": None,
            "config": {
                "port": port,
                "service": service,
                "label": label or f"Tuzak {service.upper()} ({port})",
                "started_at": datetime.now().isoformat(),
                "active": True,
            }
        }

    t.start()
    _persist_config()

    try:
        from telegram_manager import PuyadTelegramManager
        PuyadTelegramManager.send_simple_message(
            f"<b>🛡️ Puyad Honeypot Aktif Edildi</b>\n"
            f"<b>Port:</b> {port} ({service.upper()})\n"
            f"<b>Etiket:</b> {html.escape(label or 'Tuzak ' + service.upper())}\n"
            f"<b>Durum:</b> Port deaktif (boşta) doğrulandı ve tuzak dinlemeye alındı."
        )
    except Exception:
        pass

    return {
        "success": True,
        "message": f"Port {port} ({service.upper()}) honeypot olarak aktif edildi. Port deaktif/boşta doğrulandı.",
        "port": port,
        "service": service,
        "port_status": chk,
    }


def stop_honeypot(port: int) -> dict[str, Any]:
    with _lock:
        pot: dict[str, Any] | None = _active_pots.get(port)
        if not pot:
            return {"success": False, "message": f"Port {port} aktif değil."}

        pot["stop_event"].set()
        if pot.get("server"):
            try:
                pot["server"].shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                pot["server"].close()
            except Exception:
                pass
        _active_pots.pop(port, None)

    _persist_config()

    try:
        from telegram_manager import PuyadTelegramManager
        PuyadTelegramManager.send_simple_message(
            f"<b>🛑 Puyad Honeypot Durduruldu</b>\n"
            f"<b>Port:</b> {port}\n"
            f"<b>Durum:</b> Honeypot sonlandırıldı, port serbest bırakıldı."
        )
    except Exception:
        pass

    return {"success": True, "message": f"Port {port} honeypot'u durduruldu."}


def list_active() -> list[dict[str, Any]]:
    with _lock:
        return [pot["config"] for pot in _active_pots.values()]


def _persist_config() -> None:
    # Kilit dışında yazınca eski anlık görüntü yenisinin üstüne yazılabiliyordu
    with _lock:
        configs: list[dict[str, Any]] = [pot["config"] for pot in _active_pots.values()]
        save_config(configs)


def restore_from_config() -> None:
    saved: list[dict[str, Any]] = load_config()
    for cfg in saved:
        if cfg.get("active"):
            start_honeypot(cfg["port"], cfg.get("service", "custom"), cfg.get("label", ""))
