from __future__ import annotations

import asyncio
import glob
import logging
import os
import subprocess
import time
from collections import deque
from collections.abc import AsyncGenerator
from pathlib import Path
from typing import Any

import compat

logger = logging.getLogger(__name__)

LOG_CANDIDATES: list[str] = [
    "/var/log/auth.log",
    "/var/log/secure",
    "/var/log/syslog",
    "/var/log/messages",
    "/var/log/kern.log",
]

CRITICAL_KEYWORDS: list[str] = [
    "Failed password",
    "Invalid user",
    "authentication failure",
    "BREAK-IN ATTEMPT",
    "sudo:",
    "ROOT LOGIN",
    "session opened for user root",
    "Accepted password",
    "Accepted publickey",
    "Connection closed",
    "error",
    "warning",
]

_CRITICAL_MARKERS: tuple[str, ...] = (
    "failed password", "invalid user", "authentication failure",
    "break-in attempt", "root login", "session opened for user root",
    "fatal", "critical",
)
_WARNING_MARKERS: tuple[str, ...] = (
    "sudo:", "accepted password", "accepted publickey",
    "error", "warning", "disconnect", "failed", "denied",
)


def get_active_log() -> str | None:
    if not compat.IS_LINUX:
        return None
    for path in LOG_CANDIDATES:
        p: Path = Path(path)
        try:
            if p.exists() and p.is_file() and os.access(str(p), os.R_OK):
                return path
        except Exception:
            continue
    return None


def _journald_available() -> bool:
    try:
        result: subprocess.CompletedProcess[str] = subprocess.run(
            ["journalctl", "--no-pager", "-n", "1"],
            executable=compat.need_cmd("journalctl"), capture_output=True, text=True, timeout=3,
        )
        return result.returncode == 0
    except Exception:
        return False


def get_log_source() -> dict[str, Any]:
    file_path: str | None = get_active_log()
    if file_path:
        return {"type": "file", "path": file_path}
    if _journald_available():
        return {"type": "journald", "path": "journalctl (systemd)"}
    try:
        log_files: list[str] = sorted(glob.glob("/var/log/*.log") + glob.glob("/var/log/syslog*"))
        for lf in log_files:
            if os.path.isfile(lf) and os.access(lf, os.R_OK):
                return {"type": "file", "path": lf}
    except Exception:
        pass
    return {"type": "none", "path": None}


def _classify_line(line: str) -> str:
    line_lower = line.lower()
    if any(kw in line_lower for kw in _CRITICAL_MARKERS):
        return "critical"
    if any(kw in line_lower for kw in _WARNING_MARKERS):
        return "warning"
    return "info"


def _read_last_lines(path: str, n: int) -> list[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return [line.rstrip("\n") for line in deque(f, maxlen=n)]
    except OSError:
        raise
    except Exception as e:
        raise OSError(str(e)) from e


def get_log_tail(lines: int = 100) -> list[dict[str, Any]]:
    lines = max(1, min(lines, 1000))
    source: dict[str, Any] = get_log_source()

    if source["type"] == "journald":
        return _journald_tail(lines)
    if source["type"] == "file":
        return _file_tail(source["path"], lines)
    return [{"line": "Log kaynağı bulunamadı. Sisteminizde rsyslog veya journald çalışmıyor — 'sudo systemctl status rsyslog' ile kontrol edin.", "level": "error"}]


def _file_tail(log_path: str, lines: int) -> list[dict[str, Any]]:
    try:
        raw = _read_last_lines(log_path, lines)
        filtered = [line for line in raw if line.strip()]
        if not filtered:
            return [{"line": f"{log_path} şu an boş — yakında yeni kayıtlar görünecek.", "level": "info"}]
        return [{"line": line, "level": _classify_line(line)} for line in filtered]
    except PermissionError:
        return [{"line": f"İzin hatası: {log_path} okunamıyor (uygulamayı adm grubuna ekleyin: sudo usermod -aG adm $USER)", "level": "error"}]
    except OSError:
        logger.exception("Log dosyası okunamadı: %s", log_path)
        return [{"line": "Log dosyası okunamadı.", "level": "error"}]
    except Exception:
        logger.exception("Log satırları işlenemedi: %s", log_path)
        return [{"line": "Log satırları işlenirken beklenmeyen bir hata oluştu.", "level": "error"}]


def _journalctl_last(lines: int) -> str:
    return subprocess.run(
        ["journalctl", "--no-pager", "-n", str(lines), "--output=short"],
        executable=compat.need_cmd("journalctl"), capture_output=True, text=True, timeout=10,
    ).stdout


def _journald_tail(lines: int) -> list[dict[str, Any]]:
    try:
        out = [line.rstrip() for line in _journalctl_last(lines).splitlines() if line.strip()]
        if not out:
            return [{"line": "journald boş — henüz kayıt yok.", "level": "info"}]
        return [{"line": line, "level": _classify_line(line)} for line in out]
    except Exception:
        logger.exception("journalctl çıktısı alınamadı")
        return [{"line": "journald kayıtları alınamadı.", "level": "error"}]


async def tail_log_stream(lines_back: int = 50) -> AsyncGenerator[str, None]:
    source: dict[str, Any] = get_log_source()

    yield f"data: Kaynak: {source['path'] or 'Bulunamadı'}|LEVEL:info\n\n"

    if source["type"] == "none":
        yield "data: Log kaynağı bulunamadı. 'sudo systemctl start rsyslog' veya 'sudo journalctl -f' ile kontrol edin.|LEVEL:error\n\n"
        return

    if source["type"] == "journald":
        async for chunk in _stream_journald(lines_back):
            yield chunk
    else:
        async for chunk in _stream_file(source["path"], lines_back):
            yield chunk


async def _stream_file(log_path: str, lines_back: int) -> AsyncGenerator[str, None]:
    try:
        initial = _read_last_lines(log_path, lines_back)
        for line in initial:
            clean: str = _sanitize_sse_line(line)
            if clean:
                yield f"data: {clean}|LEVEL:{_classify_line(clean)}\n\n"
    except PermissionError:
        yield f"data: İzin hatası: {log_path} okunamıyor|LEVEL:error\n\n"
        return
    except OSError:
        logger.exception("Canlı izleme için log açılamadı: %s", log_path)
        yield "data: Log dosyası canlı izleme için açılamadı.|LEVEL:error\n\n"
        return

    while True:
        try:
            last_inode: int | None
            last_size: int | None
            try:
                st = os.stat(log_path)
                last_inode = st.st_ino
                last_size = st.st_size
            except OSError:
                last_inode = None
                last_size = None

            with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(0, 2)
                empty_ticks = 0
                while True:
                    line = f.readline()
                    if line:
                        empty_ticks = 0
                        clean = _sanitize_sse_line(line)
                        if clean:
                            yield f"data: {clean}|LEVEL:{_classify_line(clean)}\n\n"
                    else:
                        empty_ticks += 1
                        if empty_ticks % 30 == 0:
                            yield ": keepalive\n\n"

                        try:
                            cur = os.stat(log_path)
                            rotated = (last_inode is not None and cur.st_ino != last_inode)
                            truncated = (last_size is not None and cur.st_size < last_size)
                            if rotated or truncated:
                                yield "data: --- log rotasyonu algılandı, yeniden bağlanılıyor ---|LEVEL:info\n\n"
                                break
                        except OSError:
                            await asyncio.sleep(1)
                            break

                        await asyncio.sleep(0.5)

        except PermissionError:
            yield f"data: İzin hatası: {log_path} okunamıyor|LEVEL:error\n\n"
            return
        except Exception as e:
            yield f"data: Akış hatası: {e!s}|LEVEL:error\n\n"
            return

        await asyncio.sleep(1)
        if not Path(log_path).exists():
            await asyncio.sleep(2)


def _sanitize_sse_line(s: str) -> str:
    s = s.replace("\r", "").replace("\n", " ")
    s = s.replace("|LEVEL:", " ")
    return s.strip()


async def _stream_journald(lines_back: int) -> AsyncGenerator[str, None]:
    proc: asyncio.subprocess.Process | None = None
    try:
        for line in _journalctl_last(lines_back).splitlines():
            clean: str = _sanitize_sse_line(line)
            if clean:
                yield f"data: {clean}|LEVEL:{_classify_line(clean)}\n\n"

        proc = await asyncio.create_subprocess_exec(
            compat.need_cmd("journalctl"), "-f", "--output=short", "--no-pager",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        last_yield = time.monotonic()
        while True:
            assert proc.stdout is not None
            try:
                raw: bytes | None = await asyncio.wait_for(proc.stdout.readline(), timeout=15.0)
            except asyncio.TimeoutError:
                yield ": keepalive\n\n"
                continue

            if not raw:
                break
            line_str: str = _sanitize_sse_line(raw.decode("utf-8", errors="replace"))
            if line_str:
                last_yield = time.monotonic()
                yield f"data: {line_str}|LEVEL:{_classify_line(line_str)}\n\n"
            elif time.monotonic() - last_yield > 15:
                yield ": keepalive\n\n"
                last_yield = time.monotonic()

    except compat.CommandNotFound as exc:
        logger.warning("journald akışı başlatılamadı: %s", exc)
        yield f"data: {exc}|LEVEL:error\n\n"
    except Exception:
        logger.exception("journald canlı akışı kesildi")
        yield "data: journald canlı akışı kesildi.|LEVEL:error\n\n"
    finally:
        if proc is not None:
            try:
                proc.terminate()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=3)
                except asyncio.TimeoutError:
                    proc.kill()
            except Exception:
                pass
