from __future__ import annotations

import ipaddress
import json
import logging
import socket
import subprocess
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import compat
import config
import database
from fileutil import atomic_write_json

logger = logging.getLogger(__name__)

COMMENT: str = "puyad-honeypot"
LAST_LOGIN_FILE: Path = Path(__file__).parent / "last_login.json"
_lock: threading.Lock = threading.Lock()
_own_cache: tuple[float, set[str]] = (0.0, set())


def _tool(ip: str) -> str:
    return "ip6tables" if ipaddress.ip_address(ip).version == 6 else "iptables"


def _spec(ip: str) -> list[str]:
    return ["-s", ip, "-m", "comment", "--comment", COMMENT, "-j", "DROP"]


def _ipt(ip: str, *args: str) -> subprocess.CompletedProcess[str]:
    tool = _tool(ip)
    return subprocess.run(
        [tool, "-w", "5", *args], executable=compat.need_cmd(tool), capture_output=True, text=True, timeout=15
    )


def _rule_exists(ip: str) -> bool:
    return _ipt(ip, "-C", "INPUT", *_spec(ip)).returncode == 0


def _add_rule(ip: str) -> bool:
    if _rule_exists(ip):
        return True
    res = _ipt(ip, "-I", "INPUT", "1", *_spec(ip))
    if res.returncode != 0:
        logger.warning("%s kuralı eklenemedi (%s): %s", _tool(ip), ip, res.stderr.strip())
        return False
    return True


def _remove_rule(ip: str) -> None:
    # Eski sürüm aynı kuralı birden çok kez eklemiş olabilir
    for _ in range(20):
        if not _rule_exists(ip):
            return
        res = _ipt(ip, "-D", "INPUT", *_spec(ip))
        if res.returncode != 0:
            logger.warning("%s kuralı silinemedi (%s): %s", _tool(ip), ip, res.stderr.strip())
            return


def _own_addresses() -> set[str]:
    global _own_cache
    # monotonic açılıştan sayıyor, ilk 5 dakikada boş önbellek taze sanılmasın
    if time.monotonic() < _own_cache[0]:
        return _own_cache[1]
    found: set[str] = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            found.add(str(info[4][0]))
    except OSError:
        pass
    try:
        res = subprocess.run(
            ["ip", "-j", "addr"], executable=compat.need_cmd("ip"), capture_output=True, text=True, timeout=5
        )
        for link in json.loads(res.stdout or "[]"):
            for a in link.get("addr_info", []):
                if a.get("local"):
                    found.add(str(a["local"]))
    except Exception:
        pass
    _own_cache = (time.monotonic() + 300, found)
    return found


def _agent_addresses() -> set[str]:
    found: set[str] = set()
    with database.get_connection() as conn:
        hosts = [r[0] for r in conn.execute("SELECT ip_address FROM servers").fetchall()]
    for host in hosts:
        try:
            found.add(str(ipaddress.ip_address(host)))
        except ValueError:
            try:
                found.update(str(i[4][0]) for i in socket.getaddrinfo(host, None))
            except OSError:
                pass
    return found


def _last_login_ip() -> str:
    try:
        return str(json.loads(LAST_LOGIN_FILE.read_text(encoding="utf-8")).get("ip", ""))
    except (OSError, ValueError, AttributeError):
        return ""


def record_login(ip: str) -> None:
    try:
        clean = str(ipaddress.ip_address(ip))
    except ValueError:
        return
    try:
        atomic_write_json(LAST_LOGIN_FILE, {"ip": clean, "at": datetime.now().isoformat(timespec="seconds")})
    except OSError as exc:
        logger.warning("Son giriş IP'si kaydedilemedi: %s", exc)


def _whitelist() -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    raw = str(config.load_config().get("HONEYPOT_WHITELIST", ""))
    for item in raw.replace(";", ",").split(","):
        item = item.strip()
        if not item:
            continue
        try:
            nets.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            logger.warning("Beyaz listede geçersiz değer atlandı: %s", item[:64])
    return nets


def is_protected(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    if addr.is_loopback or addr.is_unspecified or addr.is_link_local or addr.is_multicast:
        return True
    text = str(addr)
    if text == _last_login_ip():
        return True
    if any(addr in net for net in _whitelist()):
        return True
    return text in _own_addresses() or text in _agent_addresses()


def _block_hours() -> int:
    try:
        hours = int(config.load_config().get("HONEYPOT_BLOCK_HOURS", 24))
    except (TypeError, ValueError):
        hours = 24
    return max(1, min(hours, 24 * 365))


def block(ip: str, reason: str, source: str) -> dict[str, Any]:
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return {"success": False, "message": "Geçersiz IP adresi formatı."}
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    clean = str(addr)
    try:
        protected = is_protected(clean)
    except Exception:
        logger.exception("Koruma listesi kontrol edilemedi: %s", clean)
        return {"success": False, "message": "IP engelleme komutu çalıştırılamadı."}
    if protected:
        return {"success": False, "message": "Bu adres korumalı listede, engellenmedi."}

    until = (datetime.now() + timedelta(hours=_block_hours())).strftime("%Y-%m-%d %H:%M:%S")
    with _lock:
        try:
            ok = _add_rule(clean)
        except compat.CommandNotFound as exc:
            logger.error("IP engellenemedi (%s): %s", clean, exc)
            return {"success": False, "message": str(exc)}
        except Exception:
            logger.exception("IP engelleme komutu çalıştırılamadı: %s", clean)
            return {"success": False, "message": "IP engelleme komutu çalıştırılamadı."}
        if not ok:
            return {"success": False, "message": "Güvenlik duvarı kuralı eklenemedi."}
        with database.get_connection() as conn:
            row = conn.execute(
                "SELECT id FROM ip_blocks WHERE ip = ? AND removed_at IS NULL", (clean,)
            ).fetchone()
            if row:
                conn.execute("UPDATE ip_blocks SET expires_at = MAX(expires_at, ?) WHERE id = ?", (until, row[0]))
            else:
                conn.execute(
                    "INSERT INTO ip_blocks (ip, reason, source, expires_at) VALUES (?, ?, ?, ?)",
                    (clean, reason[:200], source, until),
                )
    logger.warning("IP engellendi: %s (%s, bitiş %s)", clean, source, until)
    return {"success": True, "message": "IP engellendi.", "ip": clean, "expires_at": until}


def _unblock_row(row_id: int, ip: str, why: str) -> bool:
    try:
        _remove_rule(ip)
    except (OSError, subprocess.SubprocessError):
        logger.exception("Engel kaldırılamadı: %s", ip)
        return False
    with database.get_connection() as conn:
        conn.execute(
            "UPDATE ip_blocks SET removed_at = datetime('now','localtime'), removed_reason = ? WHERE id = ?",
            (why, row_id),
        )
    return True


def unblock(block_id: int) -> dict[str, Any]:
    with _lock:
        with database.get_connection() as conn:
            row = conn.execute(
                "SELECT id, ip FROM ip_blocks WHERE id = ? AND removed_at IS NULL", (block_id,)
            ).fetchone()
        if not row:
            return {"success": False, "message": "Aktif engel bulunamadı."}
        tool = _tool(row["ip"])
        if not compat.find_cmd(tool):
            return {"success": False, "message": f"{tool} bulunamadı."}
        if not _unblock_row(row["id"], row["ip"], "manual"):
            return {"success": False, "message": "Güvenlik duvarı kuralı kaldırılamadı."}
    logger.warning("Engel kaldırıldı: %s", row["ip"])
    return {"success": True, "message": "Engel kaldırıldı."}


def list_active() -> list[dict[str, Any]]:
    with database.get_connection() as conn:
        rows = conn.execute(
            "SELECT id, ip, reason, source, created_at, expires_at FROM ip_blocks "
            "WHERE removed_at IS NULL ORDER BY created_at DESC"
        ).fetchall()
    return [dict(r) for r in rows]


def expire() -> int:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    n = 0
    with _lock:
        with database.get_connection() as conn:
            rows = conn.execute(
                "SELECT id, ip FROM ip_blocks WHERE removed_at IS NULL AND expires_at <= ?", (now,)
            ).fetchall()
        for row in rows:
            if _unblock_row(row["id"], row["ip"], "expired"):
                n += 1
    if n:
        logger.info("Süresi dolan %d engel kaldırıldı.", n)
    return n


def _listed_ips(tool: str) -> set[str]:
    res = subprocess.run(
        [tool, "-w", "5", "-S", "INPUT"], executable=compat.need_cmd(tool), capture_output=True, text=True, timeout=15
    )
    found: set[str] = set()
    for line in res.stdout.splitlines():
        parts = line.split()
        if COMMENT not in parts or "-s" not in parts:
            continue
        try:
            found.add(str(ipaddress.ip_interface(parts[parts.index("-s") + 1]).ip))
        except (ValueError, IndexError):
            continue
    return found


def sync() -> None:
    expire()
    active = {b["ip"] for b in list_active()}
    with _lock:
        for ip in active:
            try:
                _add_rule(ip)
            except (OSError, subprocess.SubprocessError):
                logger.exception("Engel geri yüklenemedi: %s", ip)
        for tool in ("iptables", "ip6tables"):
            try:
                orphans = _listed_ips(tool) - active
            except (OSError, subprocess.SubprocessError):
                logger.warning("%s kuralları okunamadı, eşitleme atlandı.", tool)
                continue
            for ip in orphans:
                try:
                    _remove_rule(ip)
                except (OSError, subprocess.SubprocessError):
                    logger.exception("Sahipsiz kural silinemedi: %s", ip)
                logger.info("DB'de olmayan engel kuralı silindi: %s", ip)
