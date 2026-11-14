from __future__ import annotations

import json
import os
import secrets
import tempfile
import threading
from pathlib import Path
from typing import Any, cast

from fileutil import atomic_write_json

CONFIG_FILE: Path = Path(__file__).parent.parent / "config.json"
_update_lock: threading.Lock = threading.Lock()

DEFAULTS: dict[str, Any] = {
    "RUN_MODE": "standalone",
    "AGENT_SHARED_SECRET": "",
    "TELEGRAM_ENABLED": False,
    "TELEGRAM_BOT_TOKEN": "",
    "TELEGRAM_CHAT_ID": "",
    "TELEGRAM_ALLOWED_USER_ID": "",
    "RETENTION_HONEYPOT_DAYS": 30,
    "RETENTION_BRUTEFORCE_DAYS": 90,
    "RETENTION_FORENSIC_DAYS": 90,
    "RETENTION_RATE_LIMIT_DAYS": 90,
    "NETWORK_GEOIP_ENABLED": True,
    "HONEYPOT_BLOCK_HOURS": 24,
    "HONEYPOT_WHITELIST": "",
    "HONEYPOT_AUTOBLOCK_ENABLED": False,
    "HONEYPOT_AUTOBLOCK_COUNT": 5,
    "HONEYPOT_AUTOBLOCK_MINUTES": 15,
    "RATE_LIMIT_ENABLED": True,
    "RATE_LIMIT_AUTH_MAX": 5,
    "RATE_LIMIT_AUTH_WINDOW": 60,
    "RATE_LIMIT_AUTH_BLOCK": 300,
    "RATE_LIMIT_API_MAX": 120,
    "RATE_LIMIT_API_WINDOW": 60,
    "RATE_LIMIT_API_BLOCK": 300,
    "RATE_LIMIT_HEAVY_MAX": 20,
    "RATE_LIMIT_HEAVY_WINDOW": 60,
    "RATE_LIMIT_HEAVY_BLOCK": 300,
    "RATE_LIMIT_EXPORT_MAX": 10,
    "RATE_LIMIT_EXPORT_WINDOW": 60,
    "RATE_LIMIT_EXPORT_BLOCK": 300,
    "RATE_LIMIT_TELEGRAM_MAX": 10,
    "RATE_LIMIT_TELEGRAM_WINDOW": 60,
    "RATE_LIMIT_TELEGRAM_BLOCK": 600,
}


def save_config(cfg: dict[str, Any]) -> None:
    try:
        atomic_write_json(CONFIG_FILE, cfg)
    except OSError:
        pass


def _coerce_env_value(raw: str, default_val: Any) -> Any:
    if isinstance(default_val, bool):
        return raw.lower() in ("true", "1", "yes")
    if isinstance(default_val, int):
        try:
            return int(raw)
        except ValueError:
            return default_val
    return raw


def _apply_env_overrides(cfg: dict[str, Any]) -> None:
    for key in DEFAULTS:
        # .env.example kopyalanınca boş kalan anahtarlar config.json'ı ezmesin
        env_val = os.environ.get(f"PUYAD_{key}")
        if env_val:
            cfg[key] = _coerce_env_value(env_val, DEFAULTS[key])


def _create_config_file(cfg: dict[str, Any]) -> bool:
    fd, tmp = tempfile.mkstemp(dir=str(CONFIG_FILE.parent), prefix=f".{CONFIG_FILE.name}.tmp.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
        os.chmod(tmp, 0o600)
        # link var olan dosyanın üzerine yazmaz — aynı anda iki üretimde ilki kazanır
        os.link(tmp, str(CONFIG_FILE))
        return True
    except FileExistsError:
        return True
    except OSError:
        return False
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def load_config() -> dict[str, Any]:
    file_cfg: dict[str, Any] | None = None
    if CONFIG_FILE.is_file():
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                data: Any = json.load(f)
                if isinstance(data, dict):
                    file_cfg = cast(dict[str, Any], data)
        except (json.JSONDecodeError, OSError):
            file_cfg = None

    if file_cfg is not None:
        for k, v in DEFAULTS.items():
            file_cfg.setdefault(k, v)
        _apply_env_overrides(file_cfg)
        return file_cfg

    env_cfg: dict[str, Any] = DEFAULTS.copy()
    if not env_cfg.get("AGENT_SHARED_SECRET"):
        env_cfg["AGENT_SHARED_SECRET"] = secrets.token_hex(32)
    # Bozuk dosyanın üzerine yazılmaz, yalnızca hiç yoksa kalıcı oluşturulur
    if not CONFIG_FILE.exists() and _create_config_file(env_cfg):
        return load_config()
    _apply_env_overrides(env_cfg)
    return env_cfg


def update_config(updates: dict[str, Any]) -> dict[str, Any]:
    with _update_lock:
        cfg = load_config()
        filtered = {k: v for k, v in updates.items() if k in DEFAULTS and v is not None}
        cfg.update(filtered)
        save_config(cfg)
    return cfg
