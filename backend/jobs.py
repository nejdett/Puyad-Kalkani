from __future__ import annotations

import json
import logging
import sqlite3
import threading
from collections.abc import Callable
from typing import Any

from fastapi import HTTPException

import database

logger = logging.getLogger(__name__)

KEEP_JOBS: int = 100
_lock = threading.Lock()


def _to_dict(row: sqlite3.Row) -> dict[str, Any]:
    job = dict(row)
    job["result"] = json.loads(job["result"]) if job["result"] else None
    return job


def start(kind: str, server_id: int, target: Callable[[], dict[str, Any]]) -> tuple[dict[str, Any], bool]:
    with _lock:
        with database.get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM scan_jobs WHERE kind = ? AND status IN ('pending', 'running') "
                "ORDER BY id DESC LIMIT 1",
                (kind,),
            ).fetchone()
            if row:
                return _to_dict(row), False
            conn.execute(
                "DELETE FROM scan_jobs WHERE status IN ('done', 'error') AND id NOT IN "
                "(SELECT id FROM scan_jobs ORDER BY id DESC LIMIT ?)",
                (KEEP_JOBS,),
            )
            job_id = conn.execute(
                "INSERT INTO scan_jobs (kind, server_id) VALUES (?, ?)", (kind, server_id)
            ).lastrowid
            assert job_id is not None
            row = conn.execute("SELECT * FROM scan_jobs WHERE id = ?", (job_id,)).fetchone()
        threading.Thread(target=_run, args=(job_id, target), daemon=True).start()
    return _to_dict(row), True


def _set(job_id: int, status: str, result: dict[str, Any] | None = None, error: str | None = None) -> None:
    with database.get_connection() as conn:
        conn.execute(
            "UPDATE scan_jobs SET status = ?, result = ?, error = ?, "
            "updated_at = datetime('now','localtime') WHERE id = ?",
            (status, json.dumps(result, ensure_ascii=False, default=str) if result is not None else None, error, job_id),
        )


def _run(job_id: int, target: Callable[[], dict[str, Any]]) -> None:
    try:
        _set(job_id, "running")
        result = target()
    except HTTPException as e:
        _set(job_id, "error", error=str(e.detail))
        return
    except Exception:
        logger.exception("Tarama işi durdu: id=%d", job_id)
        _set(job_id, "error", error="Tarama beklenmeyen bir hatayla durdu.")
        return
    try:
        _set(job_id, "done", result=result)
    except Exception:
        logger.exception("Tarama sonucu kaydedilemedi: id=%d", job_id)
        _set(job_id, "error", error="Tarama sonucu kaydedilemedi.")


def get(job_id: int) -> dict[str, Any] | None:
    with database.get_connection() as conn:
        row = conn.execute("SELECT * FROM scan_jobs WHERE id = ?", (job_id,)).fetchone()
    return _to_dict(row) if row else None


def current(kind: str) -> dict[str, Any] | None:
    with database.get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM scan_jobs WHERE kind = ? ORDER BY id DESC LIMIT 1", (kind,)
        ).fetchone()
    return _to_dict(row) if row else None


def fail_unfinished() -> int:
    with database.get_connection() as conn:
        n = conn.execute(
            "UPDATE scan_jobs SET status = 'error', error = ?, updated_at = datetime('now','localtime') "
            "WHERE status IN ('pending', 'running')",
            ("Sunucu yeniden başladı, tarama yarıda kaldı.",),
        ).rowcount
    if n:
        logger.warning("%d yarım tarama işi hata olarak işaretlendi.", n)
    return n
