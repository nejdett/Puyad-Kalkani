from __future__ import annotations

import json
import logging
import os
import platform
import re
import socket
import subprocess
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

logger = logging.getLogger(__name__)

try:
    from light_agent import security
except ImportError:
    import security  # type: ignore[no-redef]

_TCP_STATES: dict[str, str] = {"01": "ESTAB", "0A": "LISTEN"}


def _run_cmd(cmd: list[str], timeout: int = 5) -> str:
    try:
        r = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return r.stdout.strip()
    except Exception:
        return ""


def get_uptime_seconds() -> float:
    try:
        with open("/proc/uptime", "r", encoding="utf-8") as f:
            parts = f.readline().split()
            if parts:
                return float(parts[0])
    except Exception:
        pass
    return 0.0


def format_uptime(seconds: float) -> str:
    secs = int(seconds)
    days, rem = divmod(secs, 86400)
    hours, rem = divmod(rem, 3600)
    mins, _ = divmod(rem, 60)
    parts: list[str] = []
    if days > 0:
        parts.append(f"{days} gün")
    if hours > 0 or days > 0:
        parts.append(f"{hours} saat")
    parts.append(f"{mins} dk")
    return " ".join(parts)


def get_os_info() -> dict[str, str]:
    info = {
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "distribution": platform.system(),
    }
    if os.path.exists("/etc/os-release"):
        try:
            with open("/etc/os-release", "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if line.startswith("PRETTY_NAME="):
                        val = line.split("=", 1)[1].strip().strip('"')
                        if val:
                            info["distribution"] = val
                            break
        except Exception:
            pass
    return info


def get_memory_info() -> dict[str, Any]:
    mem: dict[str, Any] = {"total_mb": 0.0, "available_mb": 0.0, "used_mb": 0.0, "percent": 0.0}
    if os.path.exists("/proc/meminfo"):
        try:
            total_kb = 0
            avail_kb = 0
            with open("/proc/meminfo", "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        total_kb = int(line.split()[1])
                    elif line.startswith("MemAvailable:"):
                        avail_kb = int(line.split()[1])
            if total_kb > 0:
                used_kb = total_kb - avail_kb
                mem["total_mb"] = round(total_kb / 1024, 1)
                mem["available_mb"] = round(avail_kb / 1024, 1)
                mem["used_mb"] = round(used_kb / 1024, 1)
                mem["percent"] = round((used_kb / total_kb) * 100, 1)
        except Exception:
            pass
    return mem


def get_system_info() -> dict[str, Any]:
    uptime = get_uptime_seconds()
    os_info = get_os_info()
    mem = get_memory_info()

    load_avg: list[float] = [0.0, 0.0, 0.0]
    if hasattr(os, "getloadavg"):
        try:
            load_avg = list(os.getloadavg())
        except Exception:
            pass

    return {
        "hostname": socket.gethostname(),
        "os": os_info["distribution"],
        "kernel": os_info["release"],
        "arch": os_info["machine"],
        "cpu_count": os.cpu_count() or 1,
        "load_avg": load_avg,
        "uptime_seconds": int(uptime),
        "uptime_human": format_uptime(uptime),
        "memory": mem,
    }


def _split_host_port(addr: str) -> tuple[str, str]:
    addr = addr.strip()
    if not addr or addr == "*":
        return "", ""
    if addr.startswith("["):
        end = addr.find("]")
        if end != -1:
            ip = addr[1:end]
            rest = addr[end + 1 :].lstrip(":")
            return ip, rest if rest != "*" else ""
    if ":" not in addr:
        return addr, ""
    idx = addr.rfind(":")
    ip = addr[:idx]
    port = addr[idx + 1 :]
    return (ip if ip != "*" else "0.0.0.0"), (port if port != "*" else "")  # nosec B104 bind değil


def _parse_proc_net() -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for path, proto in [("/proc/net/tcp", "tcp"), ("/proc/net/udp", "udp")]:
        if not os.path.exists(path):
            continue
        try:
            with open(path, "r", encoding="utf-8") as f:
                lines = f.readlines()
            for line in lines[1:]:
                parts = line.strip().split()
                if len(parts) < 4:
                    continue
                local_hex, local_port_hex = parts[1].split(":")
                rem_hex, rem_port_hex = parts[2].split(":")
                state_hex = parts[3]

                try:
                    local_ip = ".".join(str(int(local_hex[i:i+2], 16)) for i in (6, 4, 2, 0))
                    peer_ip = ".".join(str(int(rem_hex[i:i+2], 16)) for i in (6, 4, 2, 0))
                    lport = str(int(local_port_hex, 16))
                    pport = str(int(rem_port_hex, 16))
                except Exception:
                    continue

                results.append({
                    "proto": proto,
                    "state": _TCP_STATES.get(state_hex, state_hex),
                    "local_ip": local_ip,
                    "local_port": lport,
                    "peer_ip": peer_ip,
                    "peer_port": pport if pport != "0" else "",
                    "process": "",
                })
        except Exception:
            pass
    return results


def get_active_connections() -> dict[str, Any]:
    raw = _run_cmd(["ss", "-tunap"], timeout=4)
    connections: list[dict[str, Any]] = []

    if raw:
        lines = raw.splitlines()
        for line in lines[1:]:
            line = line.strip()
            if not line:
                continue
            parts = re.split(r"\s+", line, maxsplit=6)
            if len(parts) < 6:
                continue
            proto = parts[0]
            state = parts[1]
            local_raw = parts[4]
            peer_raw = parts[5]
            proc = ""
            if len(parts) >= 7:
                m = re.search(r'\("([^"]+)"', parts[6])
                if m:
                    proc = m.group(1)
            lip, lport = _split_host_port(local_raw)
            pip, pport = _split_host_port(peer_raw)
            connections.append({
                "proto": proto,
                "state": state,
                "local_ip": lip,
                "local_port": lport,
                "peer_ip": pip,
                "peer_port": pport,
                "process": proc,
            })
    else:
        connections = _parse_proc_net()

    established = [c for c in connections if c["state"] in ("ESTAB", "ESTABLISHED")]
    listening = [c for c in connections if c["state"] == "LISTEN"]

    return {
        "total": len(connections),
        "established_count": len(established),
        "listening_count": len(listening),
        "connections": connections,
    }


def _rule_result(rule: dict[str, Any], status: str, detail: str) -> dict[str, Any]:
    return {
        "id": rule.get("id", "unknown"),
        "name": rule.get("name", rule.get("id", "")),
        "category": rule.get("category", "Genel"),
        "severity": rule.get("severity", "medium"),
        "description": rule.get("description", ""),
        "status": status,
        "detail": detail,
        "output": detail,
    }


def check_rule(rule: dict[str, Any], timeout: int = 15) -> dict[str, Any]:
    check_cmd = rule.get("check_command", "")
    if not check_cmd:
        return {
            "id": rule.get("id", "unknown"),
            "name": rule.get("name", ""),
            "category": rule.get("category", "Genel"),
            "severity": rule.get("severity", "medium"),
            "description": rule.get("description", ""),
            "status": "warning",
            "detail": "check_command tanımlı değil",
            "output": "check_command tanımlı değil",
        }
    try:
        r = subprocess.run(
            ["/bin/bash", "-c", check_cmd],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        stdout = r.stdout.strip()
        stderr = r.stderr.strip()
        last_line = stdout.splitlines()[-1].strip() if stdout else ""
        status = "ok" if last_line == "OK" else "warning"
        detail = stdout or stderr or ("Uygun" if status == "ok" else "Kural sağlanamadı")
    except subprocess.TimeoutExpired:
        status = "warning"
        detail = "Komut zaman aşımına uğradı."
    except Exception:
        logger.exception("Kontrol komutu çalıştırılamadı: %s", rule.get("id"))
        status = "warning"
        detail = "Kontrol komutu çalıştırılamadı."

    return _rule_result(rule, status, detail)


def audit_rules(rules: list[dict[str, Any]], max_workers: int = 8) -> dict[str, Any]:
    if not rules:
        return {
            "summary": {"total": 0, "warnings": 0, "ok": 0, "score": 100},
            "results": [],
        }

    workers = min(max_workers, max(1, len(rules)))
    results: list[dict[str, Any]] = [{} for _ in rules]

    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_idx = {executor.submit(check_rule, rule): i for i, rule in enumerate(rules)}
        for future in as_completed(future_to_idx):
            idx = future_to_idx[future]
            try:
                results[idx] = future.result()
            except Exception:
                logger.exception("Kural denetimi tamamlanamadı: %s", rules[idx].get("id"))
                results[idx] = _rule_result(rules[idx], "warning", "Kural denetimi ajanda tamamlanamadı.")

    total = len(results)
    ok_count = sum(1 for c in results if c.get("status") == "ok")
    warnings = total - ok_count
    score = int((ok_count / total) * 100) if total > 0 else 0

    return {
        "summary": {
            "total": total,
            "warnings": warnings,
            "ok": ok_count,
            "score": score,
        },
        "results": results,
    }


def fetch_rules_from_controller(
    controller_url: str, secret: str = "", token: str = "", fingerprint: str = ""
) -> list[dict[str, Any]]:
    if not controller_url:
        print("[Uyarı] Controller URL tanımlı değil, kurallar çekilemez.", file=sys.stderr)
        return []
    base = controller_url.rstrip("/")
    url = f"{base}/api/rules"
    headers: dict[str, str] = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    elif secret:
        headers.update(security.build_headers(secret, "GET", "/api/rules"))
    else:
        print("[Uyarı] Ne token ne de secret tanımlı — /api/rules kimlik doğrulaması başarısız olabilir.", file=sys.stderr)

    try:
        req = urllib.request.Request(url, headers=headers)
        with security.controller_open(req, fingerprint, timeout=15) as resp:
            raw = resp.read().decode("utf-8")
            data = json.loads(raw)
            rules = data.get("rules", [])
            if isinstance(rules, list):
                return [r for r in rules if isinstance(r, dict)]
            print(f"[Hata] /api/rules yanıtı beklenmedik formatta: {raw[:200]}", file=sys.stderr)
    except security.ControllerPinError as e:
        print(f"[Hata] Controller'a güvenli bağlantı kurulamadı ({url}): {e}", file=sys.stderr)
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8", errors="ignore")[:300]
        except Exception:
            pass
        print(f"[Hata] Controller'dan kural çekilemedi — HTTP {e.code}: {body}", file=sys.stderr)
    except urllib.error.URLError as e:
        print(f"[Hata] Controller'a bağlanılamadı ({url}): {e.reason}", file=sys.stderr)
    except Exception as e:
        print(f"[Hata] fetch_rules_from_controller beklenmedik hata: {e}", file=sys.stderr)
    return []


def run_basic_audit(
    controller_url: str = "", secret: str = "", token: str = "", fingerprint: str = ""
) -> dict[str, Any]:
    if controller_url:
        rules = fetch_rules_from_controller(controller_url, secret=secret, token=token, fingerprint=fingerprint)
        if rules:
            return audit_rules(rules)
        print(
            "[Uyarı] Controller'dan kural çekilemedi veya kural listesi boş — tarama yapılamıyor.",
            file=sys.stderr,
        )
    else:
        print("[Uyarı] Controller URL ayarlı değil — tarama için controller yapılandırılmalı.", file=sys.stderr)

    return {
        "summary": {
            "total": 0,
            "warnings": 0,
            "ok": 0,
            "score": 0,
        },
        "results": [],
        "error": "Controller'dan kural çekilemedi. config.json içinde 'controller' ve 'secret' alanlarını kontrol edin.",
    }
