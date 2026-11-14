from __future__ import annotations

import re
from typing import Any

import compat
import config
import database
import httpx
from compat import run_shell as _run

_SS_COMMAND: str = "ss -tunap 2>/dev/null"

_geoip_cache: dict[str, dict[str, Any]] = {}
CACHE_MAX: int = 500


def _cache_put(ip_address: str, result: dict[str, Any]) -> None:
    if len(_geoip_cache) >= CACHE_MAX:
        for k in list(_geoip_cache.keys())[: CACHE_MAX // 5]:
            _geoip_cache.pop(k, None)
    _geoip_cache[ip_address] = result


def _split_host_port(addr: str) -> tuple[str, str]:
    addr = addr.strip()
    if not addr or addr == "*":
        return "", ""

    if addr.startswith("["):
        end = addr.find("]")
        if end != -1:
            ip = addr[1:end]
            if "%" in ip:
                ip = ip[:ip.find("%")]
            rest = addr[end + 1 :]
            if "%" in rest:
                pct = rest.find("%")
                colon_after = rest.find(":", pct)
                if colon_after != -1:
                    rest = rest[colon_after:]
                else:
                    rest = ""
            port = rest.lstrip(":")
            if port == "*":
                port = ""
            return ip, port

    if "%" in addr:
        pct = addr.find("%")
        colon_after = addr.find(":", pct)
        if colon_after != -1:
            addr = addr[:pct] + addr[colon_after:]
        else:
            addr = addr[:pct]

    if ":" not in addr:
        return addr, ""
    idx = addr.rfind(":")
    ip = addr[:idx]
    port = addr[idx + 1 :]
    if port == "*":
        port = ""
    if ip == "*":
        ip = "0.0.0.0"  # nosec B104 bind değil
    return ip, port


def _parse_ss_output(raw: str) -> list[dict[str, Any]]:
    connections: list[dict[str, Any]] = []
    lines = raw.splitlines()
    if not lines:
        return connections
    for line in lines[1:]:
        line = line.strip()
        if not line:
            continue
        m = re.match(r"^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)", line)
        if not m:
            continue
        proto = m.group(1)
        state = m.group(2)
        local_raw = m.group(5)
        peer_raw = m.group(6)

        process = ""
        pm = re.search(r'\("([^"]+)"', line)
        if pm:
            process = pm.group(1)

        local_ip, local_port = _split_host_port(local_raw)
        peer_ip, peer_port = _split_host_port(peer_raw)

        connections.append({
            "proto": proto,
            "state": state,
            "local_ip": local_ip,
            "local_port": local_port,
            "peer_ip": peer_ip,
            "peer_port": peer_port,
            "process": process,
        })
    return connections


_host_geo_cache: dict[str, Any] | None = None


def _geoip_enabled() -> bool:
    # Kapalıyken hiçbir IP ip-api.com'a (yurt dışı üçüncü taraf) gönderilmez
    return bool(config.load_config().get("NETWORK_GEOIP_ENABLED", True))


_LOCAL_GEO: dict[str, Any] = {
    "country": "Yerel",
    "country_code": "LAN",
    "city": "Yerel Ağ",
    "lat": 39.9334,
    "lon": 32.8597,
}


def _get_host_geo() -> dict[str, Any]:
    global _host_geo_cache
    if _host_geo_cache is not None:
        return _host_geo_cache
    if not _geoip_enabled():
        return dict(_LOCAL_GEO)
    try:
        resp = httpx.get("https://ip-api.com/json/?fields=status,country,countryCode,city,lat,lon", timeout=3.0)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success" and data.get("lat") and data.get("lon"):
                _host_geo_cache = {
                    "country": data.get("country", "Yerel"),
                    "country_code": data.get("countryCode", "LAN"),
                    "city": data.get("city", "Yerel"),
                    "lat": float(data.get("lat", 39.9334)),
                    "lon": float(data.get("lon", 32.8597)),
                }
                return _host_geo_cache
    except Exception:
        pass
    _host_geo_cache = dict(_LOCAL_GEO)
    return _host_geo_cache


class PuyadNetworkMapper:

    @staticmethod
    def _fetch_geoip(ip_address: str, url: str) -> dict[str, Any] | None:
        url = url.replace("http://", "https://")
        try:
            resp: httpx.Response = httpx.get(url, timeout=5.0)
            if resp.status_code != 200:
                return None
            data: dict[str, Any] = resp.json()
            if data.get("status") != "success":
                return None
            result: dict[str, Any] = {
                "ip": ip_address,
                "country": data.get("country", "Bilinmiyor"),
                "country_code": data.get("countryCode", ""),
                "city": data.get("city", "Bilinmiyor"),
                "lat": data.get("lat", 0),
                "lon": data.get("lon", 0),
                "org": data.get("org", ""),
                "isp": data.get("isp", ""),
                "is_private": False,
            }
            _cache_put(ip_address, result)
            return result
        except (httpx.RequestError, ValueError, KeyError):
            return None

    @staticmethod
    def get_geoip_data(ip_address: str) -> dict[str, Any]:
        if ip_address in _geoip_cache:
            return _geoip_cache[ip_address]

        if _is_private(ip_address):
            host = _get_host_geo()
            seed = sum(ord(c) for c in ip_address)
            jitter_lat = ((seed % 17) - 8) * 0.015
            jitter_lon = (((seed * 7) % 17) - 8) * 0.015
            result: dict[str, Any] = {
                "ip": ip_address,
                "country": "Yerel",
                "city": f"Yerel Ağ ({host.get('city', 'Ağ')})",
                "country_code": host.get("country_code", "LAN"),
                "lat": round(host["lat"] + jitter_lat, 4),
                "lon": round(host["lon"] + jitter_lon, 4),
                "org": "Private Network",
                "is_private": True,
            }
            _cache_put(ip_address, result)
            return result

        if not _geoip_enabled():
            return {
                "ip": ip_address, "country": "Bilinmiyor", "city": "Bilinmiyor",
                "lat": 0, "lon": 0, "org": "", "is_private": False,
            }

        primary_url = (
            f"http://ip-api.com/json/{ip_address}"
            "?fields=status,country,countryCode,city,lat,lon,org,isp"
        )
        cached = PuyadNetworkMapper._fetch_geoip(ip_address, primary_url)
        if cached is not None:
            return cached
        cached = PuyadNetworkMapper._fetch_geoip(ip_address, f"http://ip-api.com/json/{ip_address}")
        if cached is not None:
            return cached

        return {
            "ip": ip_address, "country": "Bilinmiyor", "city": "Bilinmiyor",
            "lat": 0, "lon": 0, "org": "", "is_private": False,
        }

    @staticmethod
    def get_active_connections_map() -> dict[str, Any]:
        if not compat.IS_LINUX:
            return {
                "nodes": [{"id": "server", "label": "Sunucu", "type": "server", "ip": "127.0.0.1"}],
                "edges": [],
                "total_connections": 0,
                "warning": compat.unsupported("Ağ haritası"),
            }
        raw: str = _run(_SS_COMMAND)
        connections: list[dict[str, Any]] = _parse_ss_output(raw)

        listening: list[dict[str, Any]] = [c for c in connections if c["state"] == "LISTEN"]
        established: list[dict[str, Any]] = [c for c in connections if c["state"] == "ESTAB"]

        nodes: list[dict[str, Any]] = []
        edges: list[dict[str, Any]] = []

        nodes.append({"id": "server", "label": "Sunucu", "type": "server", "ip": "127.0.0.1"})

        seen_port_ids: set[str] = set()

        def add_port(c: dict[str, Any], process: str) -> None:
            port_id = f"port_{c['local_port']}"
            if not c["local_port"] or port_id in seen_port_ids:
                return
            seen_port_ids.add(port_id)
            nodes.append({
                "id": port_id,
                "label": f":{c['local_port']}",
                "type": "port",
                "ip": c["local_ip"],
                "port": c["local_port"],
                "process": process,
            })
            edges.append({"from": "server", "to": port_id, "label": process})

        for c in listening:
            add_port(c, c["process"])
        if not seen_port_ids:
            for c in established:
                add_port(c, "")

        seen_peers: set[str] = set()
        for c in established:
            if not c["peer_ip"] or c["peer_ip"] in seen_peers:
                continue
            seen_peers.add(c["peer_ip"])
            node_id: str = f"client_{c['peer_ip']}"
            nodes.append({
                "id": node_id,
                "label": c["peer_ip"],
                "type": "client",
                "ip": c["peer_ip"],
                "port": c["peer_port"],
            })
            port_id = f"port_{c['local_port']}" if c["local_port"] else "server"
            if port_id != "server" and port_id not in seen_port_ids:
                port_id = "server"
            edges.append({"from": port_id, "to": node_id, "label": c["peer_port"]})

        return {"nodes": nodes, "edges": edges, "total_connections": len(connections)}

    @staticmethod
    def get_attack_origins() -> list[dict[str, Any]]:
        attacks: list[dict[str, Any]] = []

        try:
            with database.get_connection() as conn:
                hits = conn.execute(
                    "SELECT src_ip, port, service, created_at FROM honeypot_hits ORDER BY created_at DESC LIMIT 100"
                ).fetchall()
                for h in hits:
                    h_dict: dict[str, Any] = dict(h)
                    src_ip = (h_dict.get("src_ip") or "").strip()
                    if src_ip:
                        attacks.append(_attack_entry(src_ip, "HoneyPot", h_dict.get("created_at") or "", {
                            "port": h_dict.get("port"),
                            "service": h_dict.get("service") or "unknown",
                        }))
        except Exception:
            pass

        try:
            with database.get_connection() as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS bruteforce_log (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        src_ip TEXT NOT NULL,
                        attempts INTEGER DEFAULT 0,
                        created_at DATETIME DEFAULT (datetime('now','localtime'))
                    )
                """)
                bf = conn.execute(
                    "SELECT src_ip, attempts, created_at FROM bruteforce_log ORDER BY created_at DESC LIMIT 50"
                ).fetchall()
                for b in bf:
                    b_dict: dict[str, Any] = dict(b)
                    src_ip = (b_dict.get("src_ip") or "").strip()
                    if src_ip:
                        attacks.append(_attack_entry(src_ip, "BruteForce", b_dict.get("created_at") or "", {
                            "attempts": b_dict.get("attempts", 1),
                        }))
        except Exception:
            pass

        return attacks


def _attack_entry(src_ip: str, kind: str, date: str, extra: dict[str, Any]) -> dict[str, Any]:
    geo = PuyadNetworkMapper.get_geoip_data(src_ip)
    return {
        "ip": src_ip,
        "type": kind,
        **extra,
        "date": date,
        "lat": geo.get("lat", 0),
        "lon": geo.get("lon", 0),
        "country": geo.get("country", "Bilinmiyor"),
        "country_code": geo.get("country_code", ""),
        "city": geo.get("city", "Bilinmiyor"),
        "is_private": geo.get("is_private", False),
    }


def _is_private(ip: str) -> bool:
    if not ip:
        return True
    if ip in ("0.0.0.0", "::", "*", "0:0:0:0:0:0:0:0"):  # nosec B104 bind değil
        return True
    if ip == "::1" or ip.startswith("fe80:"):
        return True
    if ip.startswith("::ffff:"):
        ip = ip[7:]
    parts: list[str] = ip.split(".")
    if len(parts) != 4:
        return True
    try:
        first: int = int(parts[0])
        second: int = int(parts[1])
    except ValueError:
        return True
    if first == 10:
        return True
    if first == 172 and 16 <= second <= 31:
        return True
    if first == 192 and second == 168:
        return True
    if first == 127:
        return True
    if first == 169 and second == 254:
        return True
    if first == 0:
        return True
    return False
