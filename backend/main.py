from __future__ import annotations

import ipaddress
import logging
import os
import re
import socket
import subprocess
import uuid
from collections.abc import AsyncGenerator, Awaitable, Callable, Iterator
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Literal, cast

import agent_auth
import agent_client
import auth
import backup_manager
import compat
import config
import cve_analyzer
import database
import engine
import firewall
import forensic_manager
import honeypot
import httpx
import jobs
import log_monitor
import network_mapper
import pdf_reporter
import remediation_engine
import scheduler
import telegram_manager
import tlsutil
from fastapi import Depends, FastAPI, HTTPException, Query, Request, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.security import HTTPAuthorizationCredentials
from schemas import (
    AgentHeartbeatModel,
    CertApproveModel,
    ChangePasswordModel,
    ConfigUpdateModel,
    CveBatchFixModel,
    CveFixModel,
    FixModel,
    ForensicTriggerModel,
    HoneypotModel,
    JobStartModel,
    LoginModel,
    RateLimitUpdateModel,
    RuleModel,
    ScanPostModel,
    SchedulerConfigModel,
    ServerModel,
    ServerUpdateModel,
    SnapshotCreateModel,
    TelegramTestModel,
)
from starlette.concurrency import run_in_threadpool
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from throttle import _get_forwarded_ip, _sanitize_log_field, limiter, rate_limit_middleware

os.umask(0o077)

logger = logging.getLogger(__name__)
_REQUEST_ID_RE: re.Pattern[str] = re.compile(r"[A-Za-z0-9-]{1,64}")
MAX_BODY_BYTES: int = 1024 * 1024
_HOST_HEADER_RE: re.Pattern[str] = re.compile(r"(?:[A-Za-z0-9.-]{1,253}|\[[0-9A-Fa-f:.]{2,45}\])(?::\d{1,5})?")

IS_DEV = os.getenv("ENV", "production").lower() in ("development", "dev")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    from migrate import migrate

    migrate()
    jobs.fail_unfinished()
    auth.ensure_credentials()
    if compat.IS_LINUX:
        try:
            firewall.sync()
        except Exception:
            logger.exception("Engel listesi iptables ile eşitlenemedi")
    scheduler.start_scheduler()
    honeypot.restore_from_config()
    telegram_manager.PuyadTelegramManager.start_polling()
    yield
    scheduler.shutdown_scheduler()


app = FastAPI(
    title="Puyad Kalkanı API",
    version="1.0.0",
    docs_url="/docs" if IS_DEV else None,
    redoc_url=None,
    openapi_url="/openapi.json" if IS_DEV else None,
    lifespan=lifespan,
)


_BODY_TOO_LARGE: str = "İstek gövdesi çok büyük."


# FastAPI gövde okurken HTTPException dışındaki hataları 400'e çeviriyor — 413 kalsın diye HTTPException
class _BodyTooLarge(HTTPException):

    def __init__(self) -> None:
        super().__init__(status_code=413, detail=_BODY_TOO_LARGE)


class BodySizeLimitMiddleware:

    def __init__(self, app: ASGIApp, max_bytes: int = MAX_BODY_BYTES) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        declared = dict(scope["headers"]).get(b"content-length", b"")
        if declared.isdigit() and int(declared) > self.max_bytes:
            await JSONResponse({"detail": _BODY_TOO_LARGE}, status_code=413)(scope, receive, send)
            return

        # Content-Length yok ya da yalan olabilir — asıl sınır okunan bayt
        received = 0
        started = False

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    raise _BodyTooLarge()
            return message

        async def tracked_send(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracked_send)
        except _BodyTooLarge:
            if not started:
                await JSONResponse({"detail": _BODY_TOO_LARGE}, status_code=413)(scope, receive, send)


app.add_middleware(BodySizeLimitMiddleware)


_env_origins = os.getenv("ALLOWED_ORIGINS", "")
_extra_origins = [o.strip() for o in _env_origins.split(",") if o.strip()]

CORS_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
] + _extra_origins

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Puyad-Timestamp", "X-Puyad-Nonce", "X-Puyad-Signature"],
)

rate_limit_middleware(app)


@app.middleware("http")
async def security_headers(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'"
    return response


@app.middleware("http")
async def request_id_middleware(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
    rid = request.headers.get("X-Request-ID", "")
    if not _REQUEST_ID_RE.fullmatch(rid):
        rid = uuid.uuid4().hex[:12]
    request.state.request_id = rid
    response = await call_next(request)
    response.headers["X-Request-ID"] = rid
    return response


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    if isinstance(exc, HTTPException):
        raise exc
    rid = getattr(request.state, "request_id", uuid.uuid4().hex[:8])
    logger.exception("Yakalanmamış hata ref=%s yol=%s", rid, request.url.path, exc_info=exc)
    return JSONResponse(status_code=500, content={"detail": f"Internal error (ref: {rid})"})


@contextmanager
def _system_change() -> Iterator[None]:
    # Beklemek yerine reddet — iki rollback ya da fix+rollback sırayla da çalışsa tutarsız sonuç verir
    if not backup_manager.SYSTEM_CHANGE_LOCK.acquire(blocking=False):
        raise HTTPException(status_code=409, detail="Başka bir sistem değişikliği sürüyor, bitince tekrar deneyin.")
    try:
        yield
    finally:
        backup_manager.SYSTEM_CHANGE_LOCK.release()


def _require_linux(feature: str) -> None:
    if not compat.IS_LINUX:
        raise HTTPException(status_code=501, detail=compat.unsupported(feature))


def _mask_secret(value: object) -> str:
    s = str(value) if value else ""
    return ("*" * 8 + s[-4:] if len(s) > 4 else "****") if s else ""


def _masked_server(row: Any) -> dict[str, object]:
    srv = dict(row)
    srv["token"] = _mask_secret(srv.get("token"))
    pem = srv.pop("agent_cert_pem", "") or ""
    srv["agent_cert_fingerprint"] = _cert_fingerprint(pem)
    srv["agent_cert_status"] = srv.get("agent_cert_status") or ""
    return srv


def _cert_fingerprint(pem: str) -> str:
    if not pem:
        return ""
    try:
        return tlsutil.fingerprint(pem)
    except ValueError:
        return ""


def _masked_config() -> dict[str, object]:
    cfg = config.load_config()
    masked: dict[str, object] = {}
    for k, v in cfg.items():
        if k in ("AGENT_SHARED_SECRET", "TELEGRAM_BOT_TOKEN"):
            masked[k] = _mask_secret(v)
        else:
            masked[k] = v
    return masked


async def _require_user_or_agent(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Security(auth._bearer),
) -> str:
    has_sig = request.headers.get("x-puyad-signature")
    has_ts = request.headers.get("x-puyad-timestamp")
    has_nonce = request.headers.get("x-puyad-nonce")
    if request.headers.get("x-puyad-key"):
        raise HTTPException(
            status_code=401,
            detail="X-Puyad-Key artık kabul edilmiyor. İstemciyi güncelleyin (HMAC gerekli).",
        )
    if has_sig or has_ts or has_nonce:
        cfg = config.load_config()
        secret: str = str(cfg.get("AGENT_SHARED_SECRET", ""))
        if agent_auth.is_weak_secret(secret):
            raise HTTPException(status_code=500, detail="Ajan sırrı yapılandırılmamış.")
        await agent_auth.verify_agent_request(request, secret)
        return "agent"
    return await run_in_threadpool(auth.get_current_user, credentials)


def _run_local_scan(server_id: int = 1) -> dict[str, object]:
    try:
        results = engine.scan_all()
    except Exception as e:
        rid = uuid.uuid4().hex[:8]
        logger.exception("Tarama başarısız ref=%s", rid, exc_info=e)
        raise HTTPException(status_code=500, detail=f"Tarama hatası (ref: {rid})") from e
    if not results:
        return {"summary": {"total": 0, "warnings": 0, "ok": 0, "score": 0}, "results": []}
    total = len(results)
    ok = sum(1 for r in results if r["status"] == "ok")
    scan_id = remediation_engine.save_scan_to_history(results, server_id=server_id)
    summary: dict[str, object] = {
        "total": total,
        "warnings": sum(1 for r in results if r["status"] == "warning"),
        "ok": ok,
        "score": int(ok / total * 100),
        "scan_id": scan_id,
    }
    database.update_server_score(server_id, int(cast(int, summary["score"])))
    return {"summary": summary, "results": results}


def _get_agent_client(server_id: int) -> agent_client.PuyadAgentClient:
    with database.get_connection() as conn:
        srv = conn.execute("SELECT * FROM servers WHERE id = ?", (server_id,)).fetchone()
    if not srv:
        raise HTTPException(status_code=404, detail="Sunucu bulunamadı.")
    return agent_client.PuyadAgentClient(
        srv["ip_address"],
        srv["port"],
        token=srv["token"] or "",
        agent_id=srv["agent_id"] or "",
        cert_pem=agent_client.approved_cert_pem(dict(srv)),
    )


def _is_masked(value: object) -> bool:
    s = str(value)
    return "*" in s or "•" in s


def _run_remote_scan(server_id: int) -> dict[str, object]:
    client = _get_agent_client(server_id)
    ignored = set(engine.load_ignored())
    active_rules = [r for r in engine.load_rules() if r.get("id") not in ignored]
    remote_result = client.trigger_remote_scan(rules=active_rules)
    if not remote_result["success"]:
        raise HTTPException(status_code=502, detail=remote_result.get("error", "Uzak tarama başarısız"))
    data = remote_result["data"]
    if not isinstance(data, dict):
        raise HTTPException(status_code=502, detail="Uzak sunucudan geçersiz yanıt.")
    results = data.get("results", [])
    summary = data.get("summary", {})
    if not isinstance(summary, dict):
        summary = {}
    if results:
        scan_id = remediation_engine.save_scan_to_history(results, server_id=server_id)
        summary["scan_id"] = scan_id
    score = summary.get("score", 0)
    try:
        score_int = int(score)
    except (TypeError, ValueError):
        score_int = 0
    score_int = max(0, min(100, score_int))
    database.update_server_score(server_id, score_int)
    return {"summary": summary, "results": results}


def _require_admin(current_user: str = Depends(auth.get_current_user)) -> str:
    # Rol modeli yok, tek kullanıcı — kullanıcı adı değiştirilmişse sabit "admin" herkesi dışarıda bırakıyordu
    if current_user != auth._load_credentials()["username"]:
        raise HTTPException(status_code=403, detail="Yetki yok (admin gerekli).")
    return current_user


@app.get("/api/config")
def get_config(current_user: str = Depends(auth.get_current_user)) -> dict[str, object]:
    return _masked_config()


@app.patch("/api/config")
def update_cfg(body: ConfigUpdateModel, current_user: str = Depends(_require_admin)) -> dict[str, object]:
    updates = {k: v for k, v in body.model_dump().items() if v is not None and k in config.DEFAULTS}

    # Arayüz maskeli değeri geri gönderiyor, gerçek sırrın üzerine yazılmasın
    for key in ("TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID", "AGENT_SHARED_SECRET"):
        if key in updates:
            val = str(updates[key]).strip()
            if not val or _is_masked(val):
                updates.pop(key)

    res = config.update_config(updates)
    try:
        telegram_manager.PuyadTelegramManager.start_polling()
    except Exception:
        pass
    return res


@app.get("/api/config/agent-secret")
def get_agent_secret(current_user: str = Depends(_require_admin)) -> dict[str, object]:
    cfg = config.load_config()
    return {"secret": cfg.get("AGENT_SHARED_SECRET", "")}


@app.post("/api/config/generate-agent-secret")
def generate_agent_secret(current_user: str = Depends(_require_admin)) -> dict[str, object]:
    import secrets
    return {"secret": secrets.token_hex(32)}


@app.get("/api/servers")
def list_servers(current_user: str = Depends(auth.get_current_user)) -> dict[str, object]:
    with database.get_connection() as conn:
        servers = conn.execute("SELECT * FROM servers ORDER BY id").fetchall()
        return {"servers": [_masked_server(s) for s in servers]}


@app.post("/api/servers")
def add_server(body: ServerModel, current_user: str = Depends(auth.get_current_user)) -> dict[str, object]:
    try:
        addresses = [ipaddress.ip_address(body.ip_address)]
    except ValueError:
        if not body.ip_address or len(body.ip_address) > 253 or any(c in body.ip_address for c in " \t\n\r;|&$`'\""):
            raise HTTPException(status_code=422, detail="Geçersiz IP/hostname.")
        try:
            infos = socket.getaddrinfo(body.ip_address, None)
        except (socket.gaierror, UnicodeError) as e:
            raise HTTPException(status_code=422, detail="Hostname çözümlenemedi.") from e
        addresses = [ipaddress.ip_address(str(info[4][0]).split("%")[0]) for info in infos]
    # özel ağlar (10/8, 172.16/12, 192.168/16) serbest, ajanlar zaten iç ağda
    if any(agent_client.is_blocked_address(a) for a in addresses):
        raise HTTPException(
            status_code=422,
            detail="Bu adres sunucu olarak eklenemez (loopback, link-local ya da 0.0.0.0).",
        )
    srv_token = (body.token or "").strip()
    srv_port = body.port if body.port is not None else 8000
    client = agent_client.PuyadAgentClient(body.ip_address, srv_port, token=srv_token)
    status_info = client.check_agent_status()
    initial_status = "online" if status_info.get("online") else "offline"
    with database.get_connection() as conn:
        try:
            conn.execute(
                "INSERT INTO servers (name, ip_address, port, status, token) VALUES (?, ?, ?, ?, ?)",
                (body.name, body.ip_address, srv_port, initial_status, srv_token),
            )
        except Exception as e:
            logger.warning("Sunucu eklenemedi: %s", e)
            raise HTTPException(status_code=400, detail="Sunucu eklenemedi (isim/IP çakışması olabilir).") from e
        return {"success": True, "message": "Sunucu eklendi.", "status": initial_status}


@app.patch("/api/servers/{server_id}")
def update_server(server_id: int, body: ServerUpdateModel, current_user: str = Depends(auth.get_current_user)) -> dict[str, object]:
    if server_id == 1 and (body.port is not None or body.name is not None):
        raise HTTPException(status_code=400, detail="Yerel sunucu düzenlenemez.")
    with database.get_connection() as conn:
        srv = conn.execute("SELECT * FROM servers WHERE id = ?", (server_id,)).fetchone()
        if not srv:
            raise HTTPException(status_code=404, detail="Sunucu bulunamadı.")
        if body.name is not None and body.name.strip():
            conn.execute("UPDATE servers SET name = ? WHERE id = ?", (body.name.strip(), server_id))
        if body.port is not None and 1 <= body.port <= 65535:
            conn.execute("UPDATE servers SET port = ? WHERE id = ?", (body.port, server_id))
        new_token = (body.token or "").strip()
        # Liste maskeli token döndürüyor — geri gelirse gerçek token'ın üstüne yazılmasın
        if _is_masked(new_token):
            new_token = ""
        if body.clear_token:
            if new_token:
                raise HTTPException(status_code=400, detail="Token aynı istekte hem değiştirilip hem kaldırılamaz.")
            conn.execute("UPDATE servers SET token = '' WHERE id = ?", (server_id,))
        elif new_token:
            conn.execute("UPDATE servers SET token = ? WHERE id = ?", (new_token, server_id))
        return {"success": True, "message": "Sunucu güncellendi."}


@app.delete("/api/servers/{server_id}")
def delete_server(server_id: int, current_user: str = Depends(auth.get_current_user)) -> dict[str, object]:
    if server_id == 1:
        raise HTTPException(status_code=400, detail="Yerel sunucu silinemez.")
    with database.get_connection() as conn:
        result = conn.execute("DELETE FROM servers WHERE id = ?", (server_id,))
        if result.rowcount == 0:
            raise HTTPException(status_code=404, detail="Sunucu bulunamadı.")
        return {"success": True, "message": "Sunucu silindi."}


@app.get("/api/servers/{server_id}/last-scan")
def get_server_last_scan(
    server_id: int,
    current_user: str = Depends(auth.get_current_user),
) -> dict[str, object]:
    with database.get_connection() as conn:
        srv = conn.execute("SELECT * FROM servers WHERE id = ?", (server_id,)).fetchone()
        if not srv:
            raise HTTPException(status_code=404, detail="Sunucu bulunamadı.")
        scan = conn.execute(
            """SELECT id, total, warnings, ok_count, score, created_at
               FROM scan_history WHERE server_id = ?
               ORDER BY id DESC LIMIT 1""",
            (server_id,),
        ).fetchone()
        if not scan:
            return {"has_scan": False, "server": _masked_server(srv), "summary": None, "results": []}
        scan_id = scan["id"]
        results = conn.execute(
            """SELECT rule_id as id, rule_name as name, status, output as detail
               FROM scan_results WHERE scan_id = ?""",
            (scan_id,),
        ).fetchall()
        return {
            "has_scan": True,
            "server": _masked_server(srv),
            "summary": dict(scan),
            "results": [dict(r) for r in results],
        }


@app.get("/api/servers/probe-all")
def probe_all(current_user: str = Depends(auth.get_current_user)) -> dict[str, object]:
    return {"results": agent_client.probe_all_servers()}


@app.post("/api/servers/heartbeat")
def server_heartbeat(
    request: Request,
    body: AgentHeartbeatModel = AgentHeartbeatModel(),
    current_user: str = Depends(_require_user_or_agent),
) -> dict[str, object]:
    fwd = _get_forwarded_ip(request)
    ip = fwd if fwd is not None else (request.client.host if request.client else "")
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="Geçersiz istemci adresi.")
    if agent_client.is_blocked_address(addr):
        raise HTTPException(
            status_code=422,
            detail="Bu adres sunucu olarak eklenemez (loopback, link-local ya da 0.0.0.0).",
        )
    # Gövdedeki IP'ye güvenilmez — sır sahibi başka bir sunucunun kaydını ezebilirdi
    if body.ip_address and body.ip_address.strip() != ip:
        logger.warning(
            "Heartbeat gövdesindeki IP yok sayıldı: gövde=%s istemci=%s",
            _sanitize_log_field(body.ip_address, 64),
            ip,
        )
    port = body.port if body.port and 1 <= body.port <= 65535 else 8000
    score = body.score if body.score is not None and 0 <= body.score <= 100 else None

    cert_pem = (body.cert_pem or "").strip()
    if cert_pem and not _cert_fingerprint(cert_pem):
        raise HTTPException(status_code=422, detail="Geçersiz ajan sertifikası.")

    with database.get_connection() as conn:
        srv = conn.execute("SELECT * FROM servers WHERE ip_address = ? AND port = ?", (ip, port)).fetchone()
        if srv:
            server_id = srv["id"]
            stored_pem = srv["agent_cert_pem"] or ""
            # Onaylı sertifika yalnızca panelden sıfırlanarak değişir — yoksa ilk heartbeat'i atan sabitlenirdi
            if cert_pem and stored_pem != cert_pem:
                if srv["agent_cert_status"] == "approved":
                    logger.warning("Heartbeat sertifikası onaylı sertifikayla uyuşmuyor: server_id=%s istemci=%s", server_id, ip)
                    raise HTTPException(
                        status_code=409,
                        detail="Ajan sertifikası değişti. Panelden sertifikayı sıfırlayıp yeniden onaylayın.",
                    )
                conn.execute(
                    "UPDATE servers SET agent_cert_pem = ?, agent_cert_status = 'pending' WHERE id = ?",
                    (cert_pem, server_id),
                )
            if body.agent_id:
                conn.execute("UPDATE servers SET agent_id = ? WHERE id = ?", (body.agent_id, server_id))
            if score is not None:
                conn.execute("UPDATE servers SET status = 'online', last_score = ? WHERE id = ?", (score, server_id))
            else:
                conn.execute("UPDATE servers SET status = 'online' WHERE id = ?", (server_id,))
        else:
            name = body.hostname.strip() if body.hostname else f"Sunucu-{ip}"
            init_score = score if score is not None else 0
            conn.execute(
                "INSERT INTO servers (name, ip_address, port, status, last_score, token, agent_id, "
                "agent_cert_pem, agent_cert_status) VALUES (?, ?, ?, 'online', ?, '', ?, ?, ?)",
                (name, ip, port, init_score, body.agent_id, cert_pem, "pending" if cert_pem else ""),
            )
    return {"success": True, "message": "Heartbeat kaydedildi", "status": "online"}


@app.post("/api/servers/{server_id}/cert/approve")
def approve_server_cert(
    server_id: int, body: CertApproveModel, current_user: str = Depends(_require_admin)
) -> dict[str, object]:
    with database.get_connection() as conn:
        srv = conn.execute("SELECT * FROM servers WHERE id = ?", (server_id,)).fetchone()
        if not srv:
            raise HTTPException(status_code=404, detail="Sunucu bulunamadı.")
        current = _cert_fingerprint(srv["agent_cert_pem"] or "")
        if not current:
            raise HTTPException(status_code=400, detail="Onay bekleyen sertifika yok.")
        # Ekranda görülen iz ile onay arasında sertifika değişmiş olabilir
        if current != body.fingerprint:
            raise HTTPException(status_code=409, detail="Parmak izi güncel sertifikayla uyuşmuyor, sayfayı yenileyin.")
        conn.execute("UPDATE servers SET agent_cert_status = 'approved' WHERE id = ?", (server_id,))
    return {"success": True, "message": "Ajan sertifikası onaylandı."}


@app.delete("/api/servers/{server_id}/cert")
def reset_server_cert(server_id: int, current_user: str = Depends(_require_admin)) -> dict[str, object]:
    with database.get_connection() as conn:
        result = conn.execute(
            "UPDATE servers SET agent_cert_pem = '', agent_cert_status = '' WHERE id = ?", (server_id,)
        )
        if result.rowcount == 0:
            raise HTTPException(status_code=404, detail="Sunucu bulunamadı.")
    return {"success": True, "message": "Ajan sertifikası sıfırlandı, sonraki heartbeat'te yeniden onay istenecek."}


def _controller_pins() -> tuple[str, str]:
    try:
        return tlsutil.controller_pins()
    except (tlsutil.TLSSetupError, OSError, ValueError, subprocess.SubprocessError) as e:
        logger.warning("Controller sertifika pini alınamadı: %s", e)
        raise HTTPException(
            status_code=503, detail="Controller TLS sertifikası okunamadı. Backend'i serve.py ile başlatın."
        ) from e


def _install_command(host: str, pin: str) -> str:
    return (
        f"curl -sSf -k --pinnedpubkey '{pin}' https://{host}/api/agent/update.sh -o update.sh"
        " && bash update.sh"
    )


@app.get("/api/agent/install-command")
def get_agent_install_command(
    host: str = Query(..., max_length=260), current_user: str = Depends(auth.get_current_user)
) -> dict[str, object]:
    if not _HOST_HEADER_RE.fullmatch(host):
        raise HTTPException(status_code=422, detail="Geçersiz controller adresi.")
    pin, fp = _controller_pins()
    return {"command": _install_command(host, pin), "pin": pin, "fingerprint": fp, "host": host}


_UPDATE_SCRIPT: str = r"""#!/bin/bash
set -euo pipefail
BASE="https://__HOST__"
PIN="__PIN__"
FP="__FP__"
dl() {
    curl -sSf -k --pinnedpubkey "$PIN" "$BASE/api/agent/$1" -o "$1.new"
}
echo "[+] Puyad Kalkanı Light Agent güncelleniyor..."
for f in agent.py collector.py security.py; do dl "$f"; done
for f in agent.py collector.py security.py; do mv -f "$f.new" "$f"; done
NEW_CONFIG=0
if [ ! -f config.json ]; then
    dl config.json.example
    mv -f config.json.example.new config.json
    NEW_CONFIG=1
fi
python3 - "$BASE" "$FP" <<'PY'
import json, os, sys, tempfile
base, fp = sys.argv[1], sys.argv[2]
with open("config.json", encoding="utf-8") as f:
    data = json.load(f)
data["controller"] = base
data["controller_fingerprint"] = fp
fd, tmp = tempfile.mkstemp(dir=".", prefix=".config.", suffix=".tmp")
with os.fdopen(fd, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2, ensure_ascii=False)
os.chmod(tmp, 0o600)
os.replace(tmp, "config.json")
PY
rm -f rules.json
if [ "$NEW_CONFIG" = 1 ]; then
    echo "[+] config.json oluşturuldu. 'secret' alanını doldurup 'python3 agent.py start' çalıştırın."
    exit 0
fi
echo "[+] Dosyalar güncellendi. Ajan yeniden başlatılıyor..."
python3 agent.py stop 2>/dev/null || true
pkill -f "python.*agent\.py" 2>/dev/null || true
sleep 1
python3 agent.py start
python3 agent.py status || true
echo "[+] Puyad Light Agent güncellendi. Paneldeki parmak iziyle yukarıdaki ajan parmak izini karşılaştırıp onaylayın."
"""


@app.get("/api/agent/update.sh")
def get_agent_update_script(request: Request) -> Response:
    host = request.headers.get("host") or "127.0.0.1:8000"
    # Host betiğe gömülüyor — shell'in yorumlayacağı karakterler girmesin
    if not _HOST_HEADER_RE.fullmatch(host):
        raise HTTPException(status_code=400, detail="Geçersiz Host başlığı.")
    pin, fp = _controller_pins()
    script = _UPDATE_SCRIPT.replace("__HOST__", host).replace("__PIN__", pin).replace("__FP__", fp)
    return Response(content=script, media_type="text/x-shellscript")


@app.get("/api/agent/{filename}")
def get_agent_file(filename: str) -> FileResponse:
    allowed = {"agent.py", "collector.py", "security.py", "config.json.example"}
    if filename not in allowed:
        raise HTTPException(status_code=404, detail="Dosya bulunamadı.")
    file_path = Path(__file__).resolve().parent.parent / "light_agent" / filename
    if not file_path.is_file():
        raise HTTPException(status_code=404, detail="Dosya bulunamadı.")
    return FileResponse(file_path, media_type="text/plain", filename=filename)


def _dispatch_scan(server_id: int) -> dict[str, object]:
    if server_id == 1:
        _require_linux("Yerel tarama")
        return _run_local_scan(server_id=1)
    return _run_remote_scan(server_id)


@app.post("/api/scan")
def scan_post(request: Request, body: ScanPostModel, current_user: str = Depends(_require_user_or_agent)) -> dict[str, object]:
    sid = body.server_id if body.server_id is not None else 1
    return _dispatch_scan(sid)


@app.get("/api/scan")
def scan_get(request: Request, server_id: int = Query(1, ge=1, le=100000), current_user: str = Depends(_require_user_or_agent)) -> dict[str, object]:
    return _dispatch_scan(server_id)


def _cve_job(force: bool) -> dict[str, Any]:
    result = cve_analyzer.run_cve_scan(server_id=1, force=force)
    if result.get("supported") is False:
        return result
    if not result["success"]:
        raise HTTPException(status_code=500, detail=result["message"])
    return result


@app.post("/api/jobs")
def start_job(body: JobStartModel, current_user: str = Depends(auth.get_current_user)) -> dict[str, object]:
    if body.kind == "cve":
        if body.server_id != 1:
            raise HTTPException(status_code=400, detail="CVE taraması yalnızca yerel sunucuda yapılabilir.")
        _require_linux("CVE tarama")
        job, started = jobs.start("cve", 1, lambda: _cve_job(body.force))
    else:
        if body.server_id == 1:
            _require_linux("Yerel tarama")
        else:
            _get_agent_client(body.server_id)
        job, started = jobs.start("scan", body.server_id, lambda: _dispatch_scan(body.server_id))
    return {"job": job, "started": started}


@app.get("/api/jobs/current")
def current_job(
    kind: Literal["scan", "cve"] = Query("scan"),
    current_user: str = Depends(auth.get_current_user),
) -> dict[str, object]:
    return {"job": jobs.current(kind)}


@app.get("/api/jobs/{job_id}")
def get_job(job_id: int, current_user: str = Depends(auth.get_current_user)) -> dict[str, object]:
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="İş bulunamadı.")
    return {"job": job}


@app.get("/api/scan/{rule_id}")
def scan_single(
    rule_id: str,
    server_id: int = Query(1, ge=1, le=100000),
    current_user: str = Depends(auth.get_current_user),
) -> dict[str, object]:
    rule = next((r for r in engine.load_rules() if r.get("id") == rule_id), None)
    if not rule:
        raise HTTPException(status_code=404, detail=f"'{rule_id}' ID'li kural bulunamadı.")
    if server_id == 1:
        return engine.check_rule(rule)
    client = _get_agent_client(server_id)
    remote_res = client.trigger_remote_scan(rules=[rule])
    if not remote_res["success"]:
        raise HTTPException(status_code=502, detail=str(remote_res.get("error", "Uzak tarama başarısız")))
    data = remote_res.get("data", {})
    results = data.get("results", []) if isinstance(data, dict) else []
    if results and isinstance(results[0], dict):
        return cast(dict[str, object], results[0])
    return {"id": rule_id, "name": rule.get("name", ""), "status": "warning", "output": "Sonuç alınamadı"}


@app.post("/api/fix/{rule_id}")
def fix(request: Request, rule_id: str, body: FixModel = FixModel(), current_user: str = Depends(_require_user_or_agent)) -> dict[str, object]:
    sid = body.server_id if body.server_id is not None else 1
    if sid == 1:
        with _system_change():
            result = remediation_engine.fix_with_snapshot(
                rule_id=rule_id,
                auto_snapshot=body.auto_snapshot if body.auto_snapshot is not None else True,
            )
        if not result["success"]:
            raise HTTPException(status_code=400, detail=result["message"])
        return result
    client = _get_agent_client(sid)
    rule = next((r for r in engine.load_rules() if r.get("id") == rule_id), None)
    fix_cmd = rule.get("fix_command", "") if rule else ""
    remote_result = client.trigger_remote_fix(rule_id, fix_command=fix_cmd)
    if not remote_result["success"]:
        raise HTTPException(status_code=502, detail=str(remote_result.get("error", "Uzak düzeltme başarısız")))
    return cast(dict[str, object], remote_result["data"])


@app.post("/api/ignore/{rule_id}")
def ignore(rule_id: str, current_user: str = Depends(auth.get_current_user)) -> dict[str, object]:
    result = engine.ignore_rule(rule_id)
    if not result["success"]:
        raise HTTPException(status_code=404, detail=result["message"])
    return result


@app.delete("/api/ignore/{rule_id}")
def unignore(rule_id: str, current_user: str = Depends(auth.get_current_user)) -> dict[str, object]:
    result = engine.unignore_rule(rule_id)
    if not result.get("success", True):
        raise HTTPException(status_code=404, detail=result.get("message", "Kural bulunamadı."))
    return dict(result)


@app.get("/api/ignored")
def get_ignored(current_user: str = Depends(auth.get_current_user)) -> dict[str, object]:
    return {"ignored": engine.load_ignored()}


@app.get("/api/rules")
def get_rules(current_user: str = Depends(_require_user_or_agent)) -> dict[str, object]:
    rules = engine.load_rules()
    return {"rules": rules, "total": len(rules)}


@app.post("/api/rules")
def add_rule(rule: RuleModel, current_user: str = Depends(_require_admin)) -> dict[str, object]:
    result = engine.add_rule(rule.model_dump())
    if not result["success"]:
        raise HTTPException(status_code=409, detail=result["message"])
    return result


@app.put("/api/rules/{rule_id}")
def update_rule(rule_id: str, body: RuleModel, current_user: str = Depends(_require_admin)) -> dict[str, object]:
    result = engine.update_rule(rule_id, body.model_dump())
    if not result["success"]:
        raise HTTPException(status_code=404, detail=result["message"])
    return result


@app.delete("/api/rules/{rule_id}")
def delete_rule(rule_id: str, current_user: str = Depends(_require_admin)) -> dict[str, object]:
    result = engine.delete_rule(rule_id)
    if not result["success"]:
        raise HTTPException(status_code=404, detail=result["message"])
    return result


@app.get("/api/snapshots")
def list_snapshots(current_user: str = Depends(auth.get_current_user)) -> dict[str, object]:
    return {"snapshots": backup_manager.list_snapshots()}


@app.post("/api/snapshots")
def create_snapshot(body: SnapshotCreateModel, current_user: str = Depends(auth.get_current_user)) -> dict[str, object]:
    _require_linux("Snapshot alma")
    try:
        with _system_change():
            result = backup_manager.create_snapshot(label=body.label or "")
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Snapshot oluşturulamadı", exc_info=e)
        raise HTTPException(status_code=500, detail="Snapshot alınamadı.") from e
    if not result.get("success"):
        raise HTTPException(status_code=500, detail=str(result.get("message", "Snapshot alınamadı.")))
    return cast(dict[str, object], result)


@app.post("/api/snapshots/{snapshot_id}/rollback")
def rollback(snapshot_id: str, current_user: str = Depends(_require_admin)) -> dict[str, object]:
    _require_linux("Geri yükleme")
    if not snapshot_id or ".." in snapshot_id or "/" in snapshot_id or "\\" in snapshot_id:
        raise HTTPException(status_code=400, detail="Geçersiz snapshot ID.")
    with _system_change():
        result = backup_manager.rollback_snapshot(snapshot_id)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=str(result.get("message", "Geri yükleme başarısız.")))
    return result


@app.delete("/api/snapshots/{snapshot_id}")
def delete_snapshot(snapshot_id: str, current_user: str = Depends(_require_admin)) -> dict[str, object]:
    if not snapshot_id or any(c in snapshot_id for c in ("/", "\\", "..", "\x00")):
        raise HTTPException(status_code=400, detail="Geçersiz snapshot ID.")
    result = backup_manager.delete_snapshot(snapshot_id)
    if not result["success"]:
        raise HTTPException(status_code=404, detail=result["message"])
    return result


@app.get("/api/history/fixes")
def fix_history(limit: int = Query(50, ge=1, le=200), current_user: str = Depends(auth.get_current_user)) -> dict[str, object]:
    return {"history": remediation_engine.get_fix_history(limit)}


@app.get("/api/history/scans")
def scan_history(limit: int = Query(20, ge=1, le=200), current_user: str = Depends(auth.get_current_user)) -> dict[str, object]:
    return {"history": remediation_engine.get_scan_history(limit)}


@app.get("/api/history/trend")
def score_trend(current_user: str = Depends(auth.get_current_user)) -> dict[str, object]:
    return {"trend": remediation_engine.get_score_trend()}


@app.get("/api/logs/tail")
def log_tail(lines: int = Query(100, ge=1, le=1000), current_user: str = Depends(auth.get_current_user)) -> dict[str, object]:
    return {"logs": log_monitor.get_log_tail(lines)}


@app.post("/api/logs/stream-ticket")
def log_stream_ticket(current_user: str = Depends(auth.get_current_user)) -> dict[str, object]:
    return {"ticket": auth.create_stream_ticket(current_user), "expires_in": auth.STREAM_TICKET_TTL}


# EventSource başlık gönderemiyor — oturum token'ı yerine tek kullanımlık bilet
@app.get("/api/logs/stream")
async def log_stream(request: Request, lines_back: int = Query(50, ge=1, le=1000), ticket: str | None = None) -> StreamingResponse:
    auth_header: str | None = request.headers.get("authorization")
    if auth_header and auth_header.lower().startswith("bearer "):
        user = auth.verify_token(auth_header.split(None, 1)[1].strip())
    else:
        user = auth.consume_stream_ticket(ticket) if ticket else None
    if not user:
        raise HTTPException(status_code=401, detail="Canlı log için geçerli bilet gerekli.")

    async def safe_stream() -> AsyncGenerator[str, None]:
        try:
            async for chunk in log_monitor.tail_log_stream(lines_back):
                yield chunk
        except Exception as e:
            logger.warning("Canlı log akışı kesildi: %s", e)
            yield "data: Akış hatası|LEVEL:error\n\n"

    return StreamingResponse(
        safe_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/api/logs/active")
def active_log(current_user: str = Depends(auth.get_current_user)) -> dict[str, object]:
    try:
        source = log_monitor.get_log_source()
        return {"path": source["path"], "type": source["type"], "available": source["type"] != "none"}
    except Exception as e:
        logger.warning("Aktif log kaynağı sorgulanamadı: %s", e)
        return {"path": None, "type": "none", "available": False, "error": "Kaynak sorgulanamadı"}


@app.get("/api/network/topology")
def network_topology(current_user: str = Depends(auth.get_current_user)) -> dict[str, object]:
    _require_linux("Ağ haritası")
    return network_mapper.PuyadNetworkMapper.get_active_connections_map()


@app.get("/api/network/attacks")
def network_attacks(current_user: str = Depends(auth.get_current_user)) -> dict[str, object]:
    return {"attacks": network_mapper.PuyadNetworkMapper.get_attack_origins()}


@app.get("/api/network/geoip/{ip_address}")
def network_geoip(ip_address: str, current_user: str = Depends(auth.get_current_user)) -> dict[str, object]:
    import ipaddress

    try:
        ipaddress.ip_address(ip_address)
    except ValueError:
        raise HTTPException(status_code=422, detail="Geçersiz IP adresi.")
    return network_mapper.PuyadNetworkMapper.get_geoip_data(ip_address)


@app.post("/api/forensic/trigger")
def forensic_trigger(body: ForensicTriggerModel, current_user: str = Depends(auth.get_current_user)) -> dict[str, object]:
    _require_linux("Adli kanıt toplama")
    evidence = forensic_manager.PuyadForensicManager.collect_evidence(
        trigger_reason=body.trigger_reason or "Manual Trigger",
        server_id=body.server_id or 1,
    )
    return {"success": True, "message": "Adli kanıt toplandı.", "evidence": evidence}


@app.get("/api/forensic/history")
def forensic_history(server_id: int | None = Query(None, ge=1), limit: int = Query(50, ge=1, le=200), current_user: str = Depends(auth.get_current_user)) -> dict[str, object]:
    return {"history": forensic_manager.PuyadForensicManager.get_history(server_id=server_id, limit=limit)}


@app.get("/api/forensic/evidence/{evidence_id}")
def forensic_evidence(evidence_id: int, current_user: str = Depends(auth.get_current_user)) -> dict[str, object]:
    evidence = forensic_manager.PuyadForensicManager.get_evidence(evidence_id)
    if not evidence:
        raise HTTPException(status_code=404, detail="Adli kanıt bulunamadı.")
    return evidence


@app.delete("/api/forensic/evidence/{evidence_id}")
def forensic_delete(evidence_id: int, current_user: str = Depends(_require_admin)) -> dict[str, object]:
    result = forensic_manager.PuyadForensicManager.delete_evidence(evidence_id)
    if not result["success"]:
        raise HTTPException(status_code=404, detail=result["message"])
    return result


@app.post("/api/telegram/test")
def telegram_test(body: TelegramTestModel, current_user: str = Depends(_require_admin)) -> dict[str, object]:
    cfg = config.load_config()
    token = body.bot_token
    if not token or _is_masked(token):
        token = cfg.get("TELEGRAM_BOT_TOKEN", "")
    chat_id = body.chat_id
    if not chat_id or _is_masked(chat_id):
        chat_id = cfg.get("TELEGRAM_CHAT_ID", "")

    token = str(token).strip() if token else ""
    chat_id = str(chat_id).strip() if chat_id else ""

    if not token or not chat_id:
        raise HTTPException(status_code=400, detail="Bot Token ve Chat ID gerekli.")
    if not re.match(r"^\d{5,}:[A-Za-z0-9_-]{20,}$", token):
        raise HTTPException(status_code=400, detail="Geçersiz bot token formatı.")
    if not re.match(r"^-?\d{4,}$", chat_id):
        raise HTTPException(status_code=400, detail="Geçersiz chat ID formatı.")
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    try:
        resp = httpx.post(
            url,
            json={"chat_id": chat_id, "text": "Puyad Kalkanı test mesajı. Bağlantı başarılı."},
            timeout=10,
        )
        if resp.status_code == 200:
            return {"success": True, "message": "Test mesajı gönderildi."}
        try:
            tg_error = resp.json()
            err_desc = tg_error.get("description", resp.text[:500])
            err_code = tg_error.get("error_code", resp.status_code)
        except Exception:
            err_desc = resp.text[:500]
            err_code = resp.status_code
        error_map = {
            400: f"Geçersiz istek: {err_desc}",
            401: f"Geçersiz token: {err_desc}",
            403: f"Bot engellendi veya yetkisi yok: {err_desc}",
            404: f"Chat bulunamadı: {err_desc}",
        }
        detail = error_map.get(err_code, f"Telegram API hatası ({err_code}): {err_desc}")
        raise HTTPException(status_code=400, detail=detail)
    except HTTPException:
        raise
    except httpx.ConnectError:
        raise HTTPException(status_code=502, detail="Telegram API'ye bağlanılamadı. İnternet bağlantınızı kontrol edin.")
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Telegram API zaman aşımına uğradı. Tekrar deneyin.")
    except Exception as e:
        logger.exception("Telegram test mesajında beklenmeyen hata", exc_info=e)
        raise HTTPException(status_code=500, detail="Beklenmeyen hata.") from e


@app.get("/api/telegram/pending")
def telegram_pending(current_user: str = Depends(auth.get_current_user)) -> dict[str, object]:
    return {"pending": telegram_manager.PuyadTelegramManager.get_pending_actions()}


@app.post("/api/telegram/approve/{approval_token}")
def telegram_approve(approval_token: str, current_user: str = Depends(_require_admin)) -> dict[str, object]:
    with _system_change():
        result = telegram_manager.PuyadTelegramManager.approve_action(approval_token)
    if not result["success"]:
        raise HTTPException(status_code=400, detail=result["error"])
    return result


@app.post("/api/telegram/reject/{approval_token}")
def telegram_reject(approval_token: str, current_user: str = Depends(auth.get_current_user)) -> dict[str, object]:
    result = telegram_manager.PuyadTelegramManager.reject_action(approval_token)
    if not result["success"]:
        raise HTTPException(status_code=400, detail=result["error"])
    return result


@app.get("/api/cve/scan")
def cve_scan(server_id: int = Query(1, ge=1), use_osv: bool = True, force: bool = Query(False), current_user: str = Depends(auth.get_current_user)) -> dict[str, object]:
    _require_linux("CVE tarama")
    result = cve_analyzer.run_cve_scan(server_id=server_id, force=force)
    if result.get("supported") is False:
        return result
    if not result["success"]:
        raise HTTPException(status_code=500, detail=result["message"])
    return result


@app.get("/api/cve/support")
def cve_support(current_user: str = Depends(auth.get_current_user)) -> dict[str, object]:
    if not compat.IS_LINUX:
        return {"supported": False, "message": cve_analyzer.UNSUPPORTED_MESSAGE}
    distro = cve_analyzer.detect_distro()
    return {"supported": distro["supported"], "message": distro["message"] if not distro["supported"] else "", "distro": distro["name"]}


@app.get("/api/cve/history")
def cve_history(server_id: int | None = Query(None, ge=1), limit: int = Query(20, ge=1, le=200), current_user: str = Depends(auth.get_current_user)) -> dict[str, object]:
    return {"history": cve_analyzer.get_scan_history(server_id=server_id, limit=limit)}


@app.get("/api/cve/history/{scan_id}")
def cve_history_detail(scan_id: int, current_user: str = Depends(auth.get_current_user)) -> dict[str, object]:
    detail = cve_analyzer.get_scan_detail(scan_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Tarama bulunamadı.")
    return detail


@app.post("/api/cve/fix")
def cve_fix(body: CveFixModel, current_user: str = Depends(auth.get_current_user)) -> dict[str, object]:
    _require_linux("CVE düzeltme")
    server_id = body.server_id or 1
    with _system_change():
        result = cve_analyzer.fix_cve_package(body.package, server_id=server_id)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("message", "Düzeltme başarısız."))
    return result


@app.post("/api/cve/fix-batch")
def cve_fix_batch(body: CveBatchFixModel, current_user: str = Depends(auth.get_current_user)) -> dict[str, object]:
    _require_linux("CVE toplu düzeltme")
    server_id = body.server_id or 1
    with _system_change():
        result = cve_analyzer.fix_cve_batch(body.packages, server_id=server_id)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("message", "Toplu düzeltme başarısız."))
    return result


@app.post("/api/cve/apt-update")
def cve_apt_update(current_user: str = Depends(_require_admin)) -> dict[str, object]:
    _require_linux("Paket listesi güncelleme")
    with _system_change():
        result = cve_analyzer.update_apt_lists()
    if not result.get("success"):
        raise HTTPException(status_code=500, detail=result.get("message", "Paket listeleri güncellenemedi."))
    return result


@app.get("/api/cve/fix-history")
def cve_fix_history(server_id: int | None = Query(None, ge=1), limit: int = Query(50, ge=1, le=200), current_user: str = Depends(auth.get_current_user)) -> dict[str, object]:
    return {"history": cve_analyzer.get_cve_fix_history(server_id=server_id, limit=limit)}


@app.get("/api/health")
def health() -> dict[str, object]:
    return {"status": "ok", "version": "1.0.0"}


@app.get("/api/admin/rate-limit/config")
def get_rate_limit_config(current_user: str = Depends(_require_admin)) -> dict[str, object]:
    return limiter.get_current_rules()


@app.patch("/api/admin/rate-limit/config")
def update_rate_limit_config(
    body: RateLimitUpdateModel,
    current_user: str = Depends(_require_admin),
) -> dict[str, object]:
    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    if updates:
        updates = {k: v for k, v in updates.items() if k in config.DEFAULTS}
        config.update_config(updates)
    new_rules = limiter.reload_from_config()
    return {"success": True, "message": "Rate limit ayarları güncellendi.", "config": new_rules}


@app.get("/api/admin/rate-limit/stats")
def rate_limit_stats(current_user: str = Depends(_require_admin)) -> dict[str, object]:
    return {"stats": limiter.get_stats()}


@app.post("/api/admin/rate-limit/reset")
def rate_limit_reset(
    client_ip: str | None = None,
    current_user: str = Depends(_require_admin),
) -> dict[str, object]:
    limiter.reset(client_ip)
    msg = f"{client_ip} sıfırlandı." if client_ip else "Tüm IP'ler sıfırlandı."
    return {"success": True, "message": msg}


@app.get("/api/admin/rate-limit/logs")
def get_rate_limit_logs(
    limit: int = Query(100, ge=1, le=1000),
    event: str | None = None,
    ip: str | None = None,
    current_user: str = Depends(_require_admin),
) -> dict[str, object]:
    logs = limiter.logger.get_logs(limit=limit, event_filter=event, ip_filter=ip)
    return {"logs": logs, "total": len(logs)}


@app.get("/api/admin/rate-limit/logs/text")
def get_rate_limit_text_logs(
    lines: int = Query(50, ge=1, le=1000),
    current_user: str = Depends(_require_admin),
) -> dict[str, object]:
    logs = limiter.logger.get_text_logs(lines=lines)
    return {"logs": logs, "total": len(logs)}


@app.get("/api/admin/rate-limit/logs/stats")
def get_rate_limit_log_stats(
    current_user: str = Depends(_require_admin),
) -> dict[str, object]:
    return limiter.logger.get_stats()


@app.delete("/api/admin/rate-limit/logs")
def clear_rate_limit_logs(
    current_user: str = Depends(_require_admin),
) -> dict[str, object]:
    limiter.logger.clear_logs()
    return {"success": True, "message": "Loglar temizlendi."}


@app.get("/api/report/pdf")
def download_pdf(scan_id: int | None = Query(None, ge=1), current_user: str = Depends(auth.get_current_user)) -> Response:
    try:
        pdf_bytes = pdf_reporter.generate_report(scan_id=scan_id)
        filename = f"puyad-kalkani-{datetime.now().strftime('%Y%m%d-%H%M')}.pdf"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except Exception as e:
        logger.exception("PDF rapor üretilemedi", exc_info=e)
        raise HTTPException(status_code=500, detail="PDF rapor üretilemedi.") from e


@app.get("/api/scheduler/config")
def get_scheduler_config(current_user: str = Depends(auth.get_current_user)) -> dict[str, object]:
    return scheduler.load_config()


@app.post("/api/scheduler/config")
def set_scheduler_config(body: SchedulerConfigModel, current_user: str = Depends(_require_admin)) -> dict[str, object]:
    allowed_intervals = {"daily", "weekly", "monthly"}
    allowed_days = {"mon", "tue", "wed", "thu", "fri", "sat", "sun"}
    interval = body.interval or "weekly"
    if interval not in allowed_intervals:
        raise HTTPException(status_code=422, detail="Geçersiz interval (daily/weekly/monthly).")
    day = body.day_of_week or "mon"
    if interval == "weekly" and day not in allowed_days:
        raise HTTPException(status_code=422, detail="Geçersiz gün.")
    hour = body.hour if body.hour is not None else 3
    minute = body.minute if body.minute is not None else 0
    if not (0 <= hour <= 23 and 0 <= minute <= 59):
        raise HTTPException(status_code=422, detail="Saat 0-23, dakika 0-59 aralığında olmalı.")
    return scheduler.update_schedule(
        enabled=body.enabled,
        interval=interval,
        day_of_week=day,
        hour=hour,
        minute=minute,
    )


@app.post("/api/scheduler/run-now")
def run_scan_now(current_user: str = Depends(_require_admin)) -> dict[str, object]:
    return scheduler.run_now()


@app.get("/api/scheduler/alerts")
def get_alerts(current_user: str = Depends(auth.get_current_user)) -> dict[str, object]:
    return {"alerts": scheduler.get_alerts(), "unread_count": scheduler.get_unread_count()}


@app.post("/api/scheduler/alerts/read")
def mark_read(current_user: str = Depends(auth.get_current_user)) -> dict[str, object]:
    scheduler.mark_alerts_read()
    return {"success": True}


@app.post("/api/auth/login")
def login(request: Request, body: LoginModel) -> dict[str, object]:
    res = auth.login(body.username, body.password)
    # Honeypot otomatik engeli paneli kullanan adresi kilitlemesin
    fwd = _get_forwarded_ip(request)
    firewall.record_login(fwd or (request.client.host if request.client else ""))
    return res


@app.post("/api/auth/change-password")
def change_password(body: ChangePasswordModel, current_user: str = Depends(auth.get_current_user)) -> dict[str, object]:
    if body.username != current_user:
        raise HTTPException(status_code=403, detail="Yalnızca kendi parolanızı değiştirebilirsiniz.")
    return auth.change_password(body.username, body.old_password, body.new_password)


@app.post("/api/auth/logout")
def logout(
    request: Request,
    current_user: str = Depends(auth.get_current_user),
) -> dict[str, object]:
    auth_header = request.headers.get("authorization")
    if auth_header and auth_header.lower().startswith("bearer "):
        token = auth_header.split(None, 1)[1].strip()
        auth.revoke_token(token)
    return {"success": True, "message": "Başarıyla çıkış yapıldı."}


@app.get("/api/auth/me")
def me(current_user: str = Depends(auth.get_current_user)) -> dict[str, object]:
    return {"username": current_user}


@app.get("/api/honeypot/active")
def honeypot_list(current_user: str = Depends(auth.get_current_user)) -> dict[str, object]:
    return {"pots": honeypot.list_active()}


@app.get("/api/honeypot/check-port/{port}")
def honeypot_check_port(port: int, current_user: str = Depends(auth.get_current_user)) -> dict[str, object]:
    _require_linux("Honeypot port kontrolü")
    if not 1 <= port <= 65535:
        raise HTTPException(status_code=400, detail="Geçersiz port numarası (1-65535).")
    return honeypot.check_port_status(port)


@app.post("/api/honeypot/start")
def honeypot_start(body: HoneypotModel, current_user: str = Depends(_require_admin)) -> dict[str, object]:
    _require_linux("Honeypot başlatma")
    if not 1 <= body.port <= 65535:
        raise HTTPException(status_code=400, detail="Geçersiz port numarası (1-65535).")
    if body.service and not re.match(r"^(ftp|telnet|ssh|http|smtp|custom)$", body.service):
        raise HTTPException(status_code=422, detail="Geçersiz servis türü.")
    result = honeypot.start_honeypot(body.port, body.service or "custom", body.label or "")
    if not result["success"]:
        raise HTTPException(status_code=400, detail=result["message"])
    return result


@app.delete("/api/honeypot/stop/{port}")
def honeypot_stop(port: int, current_user: str = Depends(_require_admin)) -> dict[str, object]:
    _require_linux("Honeypot durdurma")
    result = honeypot.stop_honeypot(port)
    if not result["success"]:
        raise HTTPException(status_code=404, detail=result["message"])
    return result


@app.get("/api/honeypot/blocks")
def honeypot_blocks(current_user: str = Depends(_require_admin)) -> dict[str, object]:
    return {"blocks": firewall.list_active()}


@app.delete("/api/honeypot/blocks/{block_id}")
def honeypot_unblock(block_id: int, current_user: str = Depends(_require_admin)) -> dict[str, object]:
    _require_linux("Engel kaldırma")
    if not any(b["id"] == block_id for b in firewall.list_active()):
        raise HTTPException(status_code=404, detail="Aktif engel bulunamadı.")
    with _system_change():
        result = firewall.unblock(block_id)
    if not result["success"]:
        raise HTTPException(status_code=500, detail=result["message"])
    return result


@app.get("/api/honeypot/hits")
def honeypot_hits(
    limit: int = Query(100, ge=1, le=1000),
    since_id: int = Query(0, ge=0),
    current_user: str = Depends(auth.get_current_user),
) -> dict[str, object]:
    if since_id > 0:
        return {"hits": honeypot.get_hits_since(since_id, limit)}
    return {"hits": honeypot.get_hits(limit)}
