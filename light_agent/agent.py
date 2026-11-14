from __future__ import annotations

import argparse
import json
import logging
import os
import secrets
import signal
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, cast

_AGENT_DIR = Path(__file__).resolve().parent
if str(_AGENT_DIR) not in sys.path:
    sys.path.insert(0, str(_AGENT_DIR))

try:
    from light_agent import collector, security
except ImportError:
    import collector  # type: ignore[no-redef]
    import security  # type: ignore[no-redef]

logger = logging.getLogger(__name__)

MAX_BODY_BYTES: int = 1024 * 1024
_CONFIG_FIELDS: dict[str, Callable[[Any], Any]] = {
    "host": str,
    "port": int,
    "secret": str,
    "token": str,
    "controller": lambda v: str(v).rstrip("/"),
    "controller_fingerprint": lambda v: str(v).strip().lower(),
    "interval": int,
    "pid_file": str,
    "log_file": str,
    "cert_file": str,
    "key_file": str,
}


def _persist_agent_id(cpath: Path, agent_id: str) -> None:
    data: dict[str, Any] = {}
    if cpath.exists():
        with open(cpath, "r", encoding="utf-8") as f:
            loaded = json.load(f)
        if not isinstance(loaded, dict):
            raise ValueError("config.json bir JSON nesnesi değil")
        data = loaded
    data["agent_id"] = agent_id
    fd, tmp = tempfile.mkstemp(dir=str(cpath.parent), prefix=".config.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        os.chmod(tmp, 0o600)
        os.replace(tmp, str(cpath))
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _json_body(body: str) -> Any:
    try:
        return json.loads(body) if body else {}
    except Exception:
        return {}


class AgentConfig:
    def __init__(
        self,
        host: str = "0.0.0.0",  # nosec B104 controller bağlanıyor
        port: int = 8000,
        secret: str = "",
        token: str = "",
        controller: str = "",
        interval: int = 60,
        pid_file: str = "",
        log_file: str = "",
        agent_id: str = "",
        controller_fingerprint: str = "",
        cert_file: str = "",
        key_file: str = "",
    ) -> None:
        self.host: str = host
        self.port: int = port
        self.secret: str = secret
        self.token: str = token
        self.controller: str = controller.rstrip("/") if controller else ""
        self.interval: int = max(5, interval)
        self.pid_file: str = pid_file or str(_AGENT_DIR / "agent.pid")
        self.log_file: str = log_file or str(_AGENT_DIR / "agent.log")
        self.agent_id: str = agent_id
        self.controller_fingerprint: str = controller_fingerprint.strip().lower()
        self.cert_file: str = cert_file or str(_AGENT_DIR / "agent.crt")
        self.key_file: str = key_file or str(_AGENT_DIR / "agent.key")

    @classmethod
    def load(cls, config_path: str | None = None) -> AgentConfig:
        cfg = cls()
        cpath = Path(config_path) if config_path else (_AGENT_DIR / "config.json")
        if cpath.exists():
            try:
                with open(cpath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        for key, convert in _CONFIG_FIELDS.items():
                            if key in data:
                                setattr(cfg, key, convert(data[key]))
                        cfg.agent_id = str(data.get("agent_id", "")).strip()
            except Exception as e:
                print(f"[Uyarı] config.json okunamadı: {e}", file=sys.stderr)

        # İmzalar bu kimliğe bağlı — her açılışta değişirse controller'ın kaydı bayatlar
        if not security.AGENT_ID_RE.fullmatch(cfg.agent_id):
            if cfg.agent_id:
                print("[Uyarı] config.json'daki agent_id geçersiz, yenisi üretiliyor.", file=sys.stderr)
            cfg.agent_id = secrets.token_hex(16)
            try:
                _persist_agent_id(cpath, cfg.agent_id)
            except Exception as e:
                print(f"[Uyarı] agent_id config.json'a yazılamadı, bu oturumluk kullanılacak: {e}", file=sys.stderr)

        env_secret = os.environ.get("PUYAD_AGENT_SECRET")
        if env_secret:
            cfg.secret = env_secret
        env_token = os.environ.get("PUYAD_AGENT_TOKEN")
        if env_token:
            cfg.token = env_token
        env_port = os.environ.get("PUYAD_AGENT_PORT")
        if env_port:
            try:
                cfg.port = int(env_port)
            except ValueError:
                pass
        env_controller = os.environ.get("PUYAD_CONTROLLER_URL")
        if env_controller:
            cfg.controller = env_controller.rstrip("/")

        return cfg


class PuyadAgentHandler(BaseHTTPRequestHandler):
    server_version = "Puyad-Light-Agent/1.0"
    sys_version = ""
    # TLS el sıkışması işçi thread'inde — yarım kalan bağlantılar thread tutmasın
    timeout = 30

    @property
    def agent_server(self) -> PuyadAgentServer:
        return cast(PuyadAgentServer, self.server)

    def log_message(self, format: str, *args: Any) -> None:
        pass

    def _send_json(self, status_code: int, data: dict[str, Any]) -> None:
        payload = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _check_auth(self, body: bytes = b"") -> bool:
        cfg = self.agent_server.agent_config
        headers_dict = {k: v for k, v in self.headers.items()}
        ok, reason = security.verify_request(
            headers=headers_dict,
            method=self.command,
            path=self.path,
            body=body,
            secret=cfg.secret,
            token=cfg.token,
            agent_id=cfg.agent_id,
        )
        if not ok:
            self._send_json(401, {"detail": reason or "Yetkilendirme hatası."})
            return False
        return True

    def do_GET(self) -> None:
        clean_path = self.path.split("?")[0].rstrip("/") or "/"

        if clean_path in ("/api/health", "/"):
            cfg = self.agent_server.agent_config
            if not self._check_auth():
                return

            sys_info = collector.get_system_info()
            conn_info = collector.get_active_connections()
            response_data = {
                "status": "ok",
                "version": "1.0.0-light",
                "mode": "light_agent",
                "hostname": sys_info["hostname"],
                "os": sys_info["os"],
                "kernel": sys_info["kernel"],
                "uptime": sys_info["uptime_seconds"],
                "uptime_human": sys_info["uptime_human"],
                "active_connections": conn_info["total"],
                "established_connections": conn_info["established_count"],
            }
            self._send_json(200, response_data)
            return

        if not self._check_auth():
            return

        if clean_path == "/api/status":
            sys_info = collector.get_system_info()
            conn_info = collector.get_active_connections()
            self._send_json(200, {
                "status": "ok",
                "system": sys_info,
                "connections_summary": {
                    "total": conn_info["total"],
                    "established": conn_info["established_count"],
                    "listening": conn_info["listening_count"],
                },
            })
            return

        if clean_path in ("/api/network/connections", "/api/network/topology", "/api/network"):
            conn_info = collector.get_active_connections()
            self._send_json(200, conn_info)
            return

        if clean_path == "/api/scan":
            cfg = self.agent_server.agent_config
            audit_result = collector.run_basic_audit(
                controller_url=cfg.controller,
                secret=cfg.secret,
                token=cfg.token,
                fingerprint=cfg.controller_fingerprint,
            )
            self._send_json(200, audit_result)
            return

        self._send_json(404, {"detail": "Sayfa bulunamadı."})

    def do_POST(self) -> None:
        try:
            content_len = int(self.headers.get("Content-Length", 0))
        except ValueError:
            content_len = -1
        if content_len < 0:
            self._send_json(400, {"detail": "Geçersiz Content-Length."})
            return
        # İmza gövdenin hash'ini içeriyor, okumadan doğrulanamıyor — en azından boyut sınırlı
        if content_len > MAX_BODY_BYTES:
            self._send_json(413, {"detail": "İstek gövdesi çok büyük."})
            return
        raw_body = self.rfile.read(content_len) if content_len > 0 else b""

        if not self._check_auth(raw_body):
            return
        body = raw_body.decode("utf-8", errors="ignore")

        clean_path = self.path.split("?")[0].rstrip("/")

        if clean_path == "/api/scan":
            data = _json_body(body)
            rules = data.get("rules") if isinstance(data, dict) else None
            if isinstance(rules, list) and rules:
                valid_rules = [r for r in rules if isinstance(r, dict)]
                audit_result = collector.audit_rules(valid_rules)
            else:
                cfg = self.agent_server.agent_config
                audit_result = collector.run_basic_audit(
                    controller_url=cfg.controller,
                    secret=cfg.secret,
                    token=cfg.token,
                    fingerprint=cfg.controller_fingerprint,
                )
            self._send_json(200, audit_result)
            return

        if clean_path.startswith("/api/fix/"):
            rule_id = clean_path.split("/")[-1]
            data = _json_body(body)
            fix_cmd = data.get("fix_command", "") if isinstance(data, dict) else ""

            if not fix_cmd:
                self._send_json(400, {
                    "success": False,
                    "message": f"'{rule_id}' için merkezden düzeltme komutu (fix_command) sağlanmalıdır.",
                    "rule_id": rule_id,
                })
                return

            try:
                proc = subprocess.run(
                    ["/bin/bash", "-c", fix_cmd],
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
                success = (proc.returncode == 0)
                out = proc.stdout.strip() or proc.stderr.strip()
                msg = "Düzeltme başarıyla uygulandı." if success else f"Düzeltme hatası (kod: {proc.returncode})"
                self._send_json(200, {
                    "success": success,
                    "message": msg,
                    "output": out,
                    "rule_id": rule_id,
                })
            except subprocess.TimeoutExpired:
                self._send_json(200, {
                    "success": False,
                    "message": "Düzeltme komutu zaman aşımına uğradı (60s).",
                    "output": "TIMEOUT",
                    "rule_id": rule_id,
                })
            except Exception:
                logger.exception("Düzeltme komutu çalıştırılamadı: %s", rule_id)
                self._send_json(200, {
                    "success": False,
                    "message": "Düzeltme komutu çalıştırılamadı.",
                    "output": "",
                    "rule_id": rule_id,
                })
            return

        if clean_path == "/api/heartbeat":
            sent = self.agent_server.send_heartbeat()
            self._send_json(200, {
                "success": sent,
                "message": "Heartbeat gönderildi." if sent else "Heartbeat başarısız veya controller tanımlı değil.",
            })
            return

        if clean_path.startswith("/api/update/"):
            filename = clean_path.split("/")[-1]
            allowed = {"agent.py", "collector.py", "security.py"}
            if filename not in allowed:
                self._send_json(400, {"success": False, "message": "İzin verilmeyen dosya."})
                return
            target = _AGENT_DIR / filename
            try:
                target.write_bytes(raw_body)
                self._send_json(200, {"success": True, "message": f"{filename} güncellendi."})
            except Exception:
                logger.exception("Güncelleme dosyası yazılamadı: %s", filename)
                self._send_json(500, {"success": False, "message": f"{filename} güncellemesi diske yazılamadı."})
            return

        self._send_json(404, {"detail": "Sayfa bulunamadı."})


class PuyadAgentServer(ThreadingHTTPServer):
    def __init__(self, agent_config: AgentConfig) -> None:
        self.agent_config: AgentConfig = agent_config
        self._stop_event: threading.Event = threading.Event()
        self._hb_thread: threading.Thread | None = None
        super().__init__((agent_config.host, agent_config.port), PuyadAgentHandler)
        try:
            ctx = security.server_context(Path(agent_config.cert_file), Path(agent_config.key_file))
            # El sıkışması accept() içinde olursa yavaş bir istemci tüm sunucuyu bekletir
            self.socket = ctx.wrap_socket(self.socket, server_side=True, do_handshake_on_connect=False)
        except BaseException:
            self.server_close()
            raise

    def handle_error(self, request: Any, client_address: Any) -> None:
        exc = sys.exc_info()[1]
        if isinstance(exc, (ssl.SSLError, ConnectionError, TimeoutError)):
            print(f"[Uyarı] {client_address[0]} bağlantısı kapandı: {exc}", file=sys.stderr)
            return
        super().handle_error(request, client_address)

    def start_heartbeat_loop(self) -> None:
        if not self.agent_config.controller:
            return

        def _loop() -> None:
            while not self._stop_event.is_set():
                try:
                    self.send_heartbeat()
                except Exception:
                    pass
                self._stop_event.wait(self.agent_config.interval)

        self._hb_thread = threading.Thread(target=_loop, daemon=True)
        self._hb_thread.start()

    def send_heartbeat(self) -> bool:
        ctrl = self.agent_config.controller
        if not ctrl:
            return False

        sys_info = collector.get_system_info()
        conn_info = collector.get_active_connections()

        try:
            cert_pem = Path(self.agent_config.cert_file).read_text(encoding="utf-8")
        except OSError:
            cert_pem = ""
        payload = {
            "hostname": sys_info["hostname"],
            "agent_id": self.agent_config.agent_id,
            "port": self.agent_config.port,
            "status": "online",
            "active_connections": conn_info["total"],
            "cert_pem": cert_pem,
        }
        body_str = json.dumps(payload)
        path = "/api/servers/heartbeat"
        url = f"{ctrl}{path}"

        headers = {"Content-Type": "application/json"}
        if self.agent_config.token:
            headers["Authorization"] = f"Bearer {self.agent_config.token}"
        elif self.agent_config.secret:
            sig_headers = security.build_headers(self.agent_config.secret, "POST", path, body_str)
            headers.update(sig_headers)

        req = urllib.request.Request(
            url,
            data=body_str.encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            with security.controller_open(req, self.agent_config.controller_fingerprint, timeout=10) as resp:
                status_code: int = int(resp.status)
                return status_code == 200
        except security.ControllerPinError as e:
            print(f"[Hata] Heartbeat gönderilmedi: {e}", file=sys.stderr)
            return False
        except urllib.error.HTTPError as e:
            if e.code == 409:
                print("[Hata] Controller bu ajanın sertifikasını tanımıyor, panelden sıfırlanıp onaylanmalı.", file=sys.stderr)
            return False
        except Exception:
            return False

    def shutdown_cleanly(self) -> None:
        self._stop_event.set()
        self.shutdown()


def run_server(cfg: AgentConfig) -> None:
    server = PuyadAgentServer(cfg)
    server.start_heartbeat_loop()

    def _sig_handler(signum: int, frame: Any) -> None:
        pid_file = Path(cfg.pid_file)
        if pid_file.exists():
            try:
                pid_file.unlink()
            except Exception:
                pass
        threading.Thread(target=server.shutdown_cleanly, daemon=True).start()

    signal.signal(signal.SIGTERM, _sig_handler)
    signal.signal(signal.SIGINT, _sig_handler)

    print(f"Puyad Kalkanı Light Agent dinleniyor: https://{cfg.host}:{cfg.port}")
    if cfg.controller:
        print(f"Controller bağlantısı: {cfg.controller} (her {cfg.interval} sn heartbeat)")
    if cfg.secret:
        print("HMAC SHA-256 kimlik doğrulaması: AKTİF")
    if cfg.token:
        print("Bearer Token doğrulaması: AKTİF")

    try:
        server.serve_forever()
    finally:
        server.server_close()
        pid_file = Path(cfg.pid_file)
        if pid_file.exists():
            try:
                pid_file.unlink()
            except Exception:
                pass


def is_process_running(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _restrict_file_modes(paths: list[Path]) -> None:
    # umask yalnızca yeni dosyaları etkiliyor — eski sürümün 0666 bıraktığı dosyalar burada düzelir
    for path in paths:
        try:
            if path.is_file() and not path.is_symlink():
                os.chmod(path, 0o600)
        except OSError as e:
            print(f"[Uyarı] {path} izni daraltılamadı: {e}", file=sys.stderr)


def cmd_start(cfg: AgentConfig) -> None:
    pid_path = Path(cfg.pid_file)
    _restrict_file_modes([Path(cfg.log_file), pid_path])
    if pid_path.exists():
        try:
            old_pid = int(pid_path.read_text().strip())
            if is_process_running(old_pid):
                print(f"[Bilgi] Light Agent zaten çalışıyor (PID: {old_pid}).")
                return
        except Exception:
            pass
        try:
            pid_path.unlink()
        except Exception:
            pass

    log_path = Path(cfg.log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError as e:
        print(f"[Hata] Fork 1 başarısız: {e}", file=sys.stderr)
        sys.exit(1)

    os.setsid()
    os.umask(0o077)

    try:
        pid2 = os.fork()
        if pid2 > 0:
            sys.exit(0)
    except OSError as e:
        print(f"[Hata] Fork 2 başarısız: {e}", file=sys.stderr)
        sys.exit(1)

    sys.stdout.flush()
    sys.stderr.flush()

    log_fd = open(str(log_path), "a+", encoding="utf-8")
    os.dup2(log_fd.fileno(), sys.stdout.fileno())
    os.dup2(log_fd.fileno(), sys.stderr.fileno())

    pid_path.write_text(str(os.getpid()))
    run_server(cfg)


def cmd_stop(cfg: AgentConfig) -> None:
    pid_path = Path(cfg.pid_file)
    if not pid_path.exists():
        print("[Bilgi] PID dosyası bulunamadı, Light Agent çalışmıyor olabilir.")
        return

    try:
        pid = int(pid_path.read_text().strip())
    except Exception:
        print("[Hata] PID dosyası geçersiz.", file=sys.stderr)
        pid_path.unlink(missing_ok=True)
        return

    if not is_process_running(pid):
        print(f"[Bilgi] PID {pid} çalışmıyor.")
        pid_path.unlink(missing_ok=True)
        return

    print(f"Light Agent durduruluyor (PID: {pid})...")
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError as e:
        print(f"[Hata] Sinyal gönderilemedi: {e}", file=sys.stderr)
        return

    for _ in range(30):
        if not is_process_running(pid):
            break
        time.sleep(0.1)

    if is_process_running(pid):
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass

    pid_path.unlink(missing_ok=True)
    print("Light Agent başarıyla durduruldu.")


def cmd_status(cfg: AgentConfig) -> None:
    pid_path = Path(cfg.pid_file)
    if not pid_path.exists():
        print("Durum: DURDURULDU (PID dosyası yok)")
        return

    try:
        pid = int(pid_path.read_text().strip())
    except Exception:
        print("Durum: DURDURULDU (Bozuk PID dosyası)")
        return

    if not is_process_running(pid):
        print(f"Durum: DURDURULDU (PID {pid} aktif değil)")
        return

    test_url = f"https://127.0.0.1:{cfg.port}/api/health"
    req = urllib.request.Request(test_url)
    if cfg.token:
        req.add_header("Authorization", f"Bearer {cfg.token}")
    elif cfg.secret:
        headers = security.build_headers(cfg.secret, "GET", "/api/health", target=cfg.agent_id)
        for k, v in headers.items():
            req.add_header(k, v)

    http_ok = False
    details = ""
    try:
        cert_pem = Path(cfg.cert_file).read_text(encoding="utf-8")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.load_verify_locations(cadata=cert_pem)
        with urllib.request.urlopen(req, timeout=3, context=ctx) as resp:  # nosec B310 sabit https adresi
            if resp.status == 200:
                http_ok = True
                details = resp.read().decode("utf-8", errors="ignore")
    except Exception as e:
        details = str(e)

    print(f"Durum: ÇALIŞIYOR (PID: {pid})")
    print(f"Port: {cfg.port}")
    print(f"HTTPS Yanıtı: {'OK (200)' if http_ok else 'Bağlantı hatası: ' + details}")
    print_agent_fingerprint(cfg)


def print_agent_fingerprint(cfg: AgentConfig) -> None:
    try:
        fp = security.cert_fingerprint(Path(cfg.cert_file).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        print(f"Ajan sertifikası okunamadı: {e}")
        return
    print(f"Ajan parmak izi (SHA-256): {fp}")


def prepare_tls(cfg: AgentConfig) -> str:
    if cfg.controller:
        problem = security.controller_problem(cfg.controller, cfg.controller_fingerprint)
        if problem:
            return f"{problem} {security.CONTROLLER_SETUP_HELP}"
    try:
        security.ensure_cert(Path(cfg.cert_file), Path(cfg.key_file))
        security.cert_fingerprint(Path(cfg.cert_file).read_text(encoding="utf-8"))
    except (security.TLSSetupError, OSError, ValueError) as e:
        return str(e)
    return ""


def main() -> None:
    parser = argparse.ArgumentParser(description="Puyad Kalkanı Light Agent")
    parser.add_argument("action", nargs="?", default="run", choices=["run", "start", "stop", "restart", "status"], help="İşlem türü")
    parser.add_argument("--port", type=int, help="Dinlenecek port (varsayılan: 8000)")
    parser.add_argument("--host", type=str, help="Dinlenecek IP (varsayılan: 0.0.0.0)")
    parser.add_argument("--secret", type=str, help="HMAC SHA-256 güvenlik sırrı")
    parser.add_argument("--token", type=str, help="Özel Bearer token")
    parser.add_argument("--controller", type=str, help="Puyad Kalkanı Kontrolcü URL (örn: https://192.168.1.100:8000)")
    parser.add_argument("--controller-fingerprint", type=str, help="Controller sertifikasının SHA-256 parmak izi")
    parser.add_argument("--interval", type=int, help="Heartbeat gönderme aralığı (saniye)")
    parser.add_argument("--cert-file", type=str, help="Ajan TLS sertifikası (varsayılan: agent.crt)")
    parser.add_argument("--key-file", type=str, help="Ajan TLS anahtarı (varsayılan: agent.key)")
    parser.add_argument("--config", type=str, help="Yapılandırma JSON dosyası yolu")
    parser.add_argument("--pid-file", type=str, help="PID dosya yolu")
    parser.add_argument("--log-file", type=str, help="Log dosya yolu")
    parser.add_argument("-d", "--daemon", action="store_true", help="Arka planda çalıştır (start ile eşdeğer)")

    args = parser.parse_args()
    cfg = AgentConfig.load(args.config)

    for name in _CONFIG_FIELDS:
        value = getattr(args, name)
        if value:
            setattr(cfg, name, value)

    action = args.action
    if args.daemon and action == "run":
        action = "start"

    problem = security.credential_problem(cfg.secret, cfg.token)
    if action in ("run", "start", "restart") and problem:
        print(f"[Hata] {problem} Ajan başlatılmadı.\n{security.WEAK_SECRET_HELP}", file=sys.stderr)
        sys.exit(1)
    # Daemon'a geçmeden önce — hata log dosyasına değil terminale düşsün
    if action in ("run", "start", "restart"):
        tls_problem = prepare_tls(cfg)
        if tls_problem:
            print(f"[Hata] {tls_problem} Ajan başlatılmadı.", file=sys.stderr)
            sys.exit(1)
        print_agent_fingerprint(cfg)
        sys.stdout.flush()

    if action == "start":
        cmd_start(cfg)
    elif action == "stop":
        cmd_stop(cfg)
    elif action == "restart":
        cmd_stop(cfg)
        time.sleep(0.5)
        cmd_start(cfg)
    elif action == "status":
        cmd_status(cfg)
    else:
        run_server(cfg)


if __name__ == "__main__":
    main()
