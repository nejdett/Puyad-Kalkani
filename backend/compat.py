from __future__ import annotations

import os
import platform
import shutil
import subprocess
from typing import Any

SYSTEM: str = platform.system()
IS_LINUX: bool = SYSTEM == "Linux"
IS_WINDOWS: bool = SYSTEM == "Windows"
IS_MAC: bool = SYSTEM == "Darwin"
# sudo/systemd dışında başlatılınca PATH'te sbin olmayabiliyor
SBIN_DIRS: tuple[str, ...] = ("/usr/local/sbin", "/usr/sbin", "/sbin")


class CommandNotFound(FileNotFoundError):
    pass


def find_cmd(name: str) -> str | None:
    return shutil.which(name) or shutil.which(name, path=os.pathsep.join(SBIN_DIRS))


def need_cmd(name: str) -> str:
    path = find_cmd(name)
    if not path:
        raise CommandNotFound(f"{name} bulunamadı.")
    return path


def shell_env() -> dict[str, str]:
    env = dict(os.environ)
    parts = [p for p in env.get("PATH", "").split(os.pathsep) if p]
    env["PATH"] = os.pathsep.join(parts + [d for d in SBIN_DIRS if d not in parts])
    return env


def unsupported(feature: str) -> str:
    return f"{feature} yalnızca Linux sistemlerde destekleniyor. Mevcut sistem: {SYSTEM}"


def linux_only_response(feature: str) -> dict[str, Any]:
    return {"success": False, "message": unsupported(feature)}


def run_shell(cmd: str, timeout: int = 10) -> str:
    try:
        r = subprocess.run(
            ["/bin/bash", "-c", cmd], shell=False, capture_output=True, text=True, timeout=timeout, env=shell_env()
        )
        return r.stdout.strip()
    except Exception:
        return ""
