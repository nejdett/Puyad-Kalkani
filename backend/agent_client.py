from __future__ import annotations

import ipaddress
import json
import logging
import socket
from pathlib import Path
from typing import Any

import agent_auth
import config
import database
import httpx
import tlsutil

logger = logging.getLogger(__name__)

AUTH_REJECTED_MESSAGE: str = (
    "Ajan kimlik doğrulamasını reddetti. Sunucu token'ını ya da ajan sırrını kontrol edin. "
    "Ajan eski sürümse dosyalarını güncelleyip yeniden başlatın."
)
AGENT_ID_MISSING_MESSAGE: str = (
    "Ajan kimliği henüz bilinmiyor. Ajanın controller adresiyle çalıştığından ve heartbeat "
    "gönderdiğinden emin olun."
)
CERT_NOT_APPROVED_MESSAGE: str = (
    "Ajanın TLS sertifikası onaylanmadı. Ajanı panelden alınan kurulum komutuyla güncelleyin, "
    "ardından Sunucular sayfasında parmak izini karşılaştırıp onaylayın."
)



def is_blocked_address(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_loopback or ip.is_link_local or ip.is_unspecified


class PuyadAgentClient:
    def __init__(
        self, server_ip: str, server_port: int = 8000, token: str = "", agent_id: str = "", cert_pem: str = ""
    ) -> None:
        cfg: dict[str, Any] = config.load_config()
        self.server_ip: str = server_ip
        self.server_port: int = server_port
        self.base_url: str = f"https://{server_ip}:{server_port}"
        self.timeout: float = 15.0
        self._token: str = token.strip() if token else ""
        self._secret: str = str(cfg.get("AGENT_SHARED_SECRET", "")).strip()
        self._agent_id: str = agent_id.strip() if agent_id else ""
        self._cert_pem: str = cert_pem.strip() if cert_pem else ""

    def _headers(self, method: str, path: str, body: bytes = b"") -> dict[str, str]:
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        # Kimlik bilinmiyorsa imzasız gider, ajan 401 döner — imza hedefsiz atılamaz
        elif self._secret and self._agent_id:
            headers.update(agent_auth.build_agent_headers(self._secret, method, path, body, self._agent_id))
        return headers

    def _agent_id_missing(self) -> bool:
        return bool(self._secret) and not self._token and not self._agent_id

    def _request(
        self, method: str, path: str, content: bytes | None, timeout: float, headers: dict[str, str] | None = None
    ) -> httpx.Response:
        # Eklerken yapılan kontrol yetmez — DNS rebinding ile sonraki isteklerde iç adrese gidilebilir
        try:
            infos = socket.getaddrinfo(self.server_ip, self.server_port, type=socket.SOCK_STREAM)
        except (socket.gaierror, UnicodeError) as e:
            raise httpx.ConnectError("Hostname çözümlenemedi") from e
        addresses = [ipaddress.ip_address(str(info[4][0]).split("%")[0]) for info in infos]
        if any(is_blocked_address(a) for a in addresses):
            logger.warning("%s engellenen bir adrese çözümlendi, istek gönderilmedi.", self.server_ip)
            raise httpx.ConnectError("Engellenen adres")
        ip = addresses[0]
        target = f"[{ip}]" if ip.version == 6 else str(ip)
        host = f"[{self.server_ip}]" if ":" in self.server_ip else self.server_ip
        hdrs = dict(headers if headers is not None else self._headers(method, path, content or b""))
        hdrs["Host"] = f"{host}:{self.server_port}"
        ctx = tlsutil.pinned_client_context(self._cert_pem)
        with httpx.Client(verify=ctx, timeout=timeout) as client:
            return client.request(
                method,
                f"https://{target}:{self.server_port}{path}",
                headers=hdrs,
                content=content,
                extensions={"sni_hostname": self.server_ip},
            )

    def check_agent_status(self) -> dict[str, Any]:
        if not self._cert_pem:
            return {"online": False, "error": CERT_NOT_APPROVED_MESSAGE}
        try:
            resp: httpx.Response = self._request("GET", "/api/health", None, 4.0)
            if resp.status_code == 200:
                return {"online": True, "data": resp.json()}
            return {"online": False, "error": f"HTTP {resp.status_code}"}
        except httpx.ConnectError:
            return {"online": False, "error": "Bağlantı kurulamadı"}
        except httpx.TimeoutException:
            return {"online": False, "error": "Zaman aşımı"}
        except Exception as e:
            logger.warning("Ajan durumu alınamadı %s: %s", self.base_url, e)
            return {"online": False, "error": "Ajan durumu alınamadı"}

    def _push_update_to_agent(self) -> bool:
        agent_dir = Path(__file__).resolve().parent.parent / "light_agent"
        for filename in ["agent.py", "collector.py", "security.py"]:
            fpath = agent_dir / filename
            if not fpath.exists():
                continue
            content = fpath.read_bytes()
            push_path = f"/api/update/{filename}"
            hdrs = self._headers("POST", push_path, content)
            hdrs["Content-Type"] = "text/plain; charset=utf-8"
            try:
                resp = self._request("POST", push_path, content, 15.0, hdrs)
                if resp.status_code not in (200, 201):
                    return False
            except Exception:
                return False
        return True

    def trigger_remote_scan(self, rules: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        if not self._cert_pem:
            return {"success": False, "error": CERT_NOT_APPROVED_MESSAGE}
        if self._agent_id_missing():
            return {"success": False, "error": AGENT_ID_MISSING_MESSAGE}
        path = "/api/scan"
        if rules is not None:
            method = "POST"
            payload_bytes: bytes | None = json.dumps({"rules": rules}, ensure_ascii=False).encode("utf-8")
        else:
            method = "GET"
            payload_bytes = None

        def attempt() -> httpx.Response:
            resp = self._request(method, path, payload_bytes, 120.0)
            if method == "POST" and resp.status_code in (404, 405):
                # Eski agent sürümü — önce güncellemeyi dene, olmazsa kurallarsız GET
                if self._push_update_to_agent():
                    resp = self._request("POST", path, payload_bytes, 120.0)
                if resp.status_code in (404, 405):
                    resp = self._request("GET", path, None, 120.0)
            return resp

        try:
            resp = attempt()
            if resp.status_code == 401:
                return {"success": False, "error": AUTH_REJECTED_MESSAGE}
            if resp.status_code == 200:
                return {"success": True, "data": resp.json()}
            return {"success": False, "error": f"HTTP {resp.status_code}"}
        except Exception as e:
            logger.warning("Uzak tarama başarısız %s: %s", self.base_url, e)
            return {"success": False, "error": "Ajana ulaşılamadı ya da yanıtı işlenemedi."}

    def trigger_remote_fix(self, rule_id: str, fix_command: str = "") -> dict[str, Any]:
        if not self._cert_pem:
            return {"success": False, "error": CERT_NOT_APPROVED_MESSAGE}
        if self._agent_id_missing():
            return {"success": False, "error": AGENT_ID_MISSING_MESSAGE}
        path = f"/api/fix/{rule_id}"
        body_str = json.dumps({"fix_command": fix_command}, ensure_ascii=False) if fix_command else "{}"
        payload_bytes = body_str.encode("utf-8")
        try:
            resp = self._request("POST", path, payload_bytes, 60.0)
            if resp.status_code == 401:
                return {"success": False, "error": AUTH_REJECTED_MESSAGE}
            if resp.status_code == 200:
                return {"success": True, "data": resp.json()}
            return {"success": False, "error": f"HTTP {resp.status_code}"}
        except Exception as e:
            logger.warning("Uzak düzeltme başarısız %s: %s", self.base_url, e)
            return {"success": False, "error": "Ajana ulaşılamadı ya da yanıtı işlenemedi."}


def approved_cert_pem(srv: dict[str, Any]) -> str:
    if srv.get("agent_cert_status") != "approved":
        return ""
    return str(srv.get("agent_cert_pem") or "")


def probe_all_servers() -> list[dict[str, Any]]:
    with database.get_connection() as conn:
        servers = conn.execute("SELECT * FROM servers").fetchall()

    results: list[dict[str, Any]] = []
    for srv in servers:
        srv_dict: dict[str, Any] = dict(srv)
        server_id = srv_dict["id"]
        # Yerel sunucu bu süreç — bu kod çalışıyorsa ayakta, ağ isteği gereksiz
        if server_id == 1:
            new_status = "online"
        else:
            client = PuyadAgentClient(
                srv_dict["ip_address"],
                srv_dict["port"],
                token=srv_dict.get("token") or "",
                agent_id=srv_dict.get("agent_id") or "",
                cert_pem=approved_cert_pem(srv_dict),
            )
            new_status = "online" if client.check_agent_status()["online"] else "offline"

        with database.get_connection() as conn:
            conn.execute(
                "UPDATE servers SET status = ? WHERE id = ?",
                (new_status, server_id),
            )

        results.append({
            "id": server_id,
            "name": srv_dict["name"],
            "ip_address": srv_dict["ip_address"],
            "port": srv_dict["port"],
            "status": new_status,
            "last_score": srv_dict.get("last_score", 0) or 0,
        })

    return results
