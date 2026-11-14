from __future__ import annotations

import json
from datetime import datetime
from typing import Any

import compat
import database
from compat import run_shell as _run

_LINUX_COMMANDS: dict[str, str] = {
    "active_connections": "ss -tupn 2>/dev/null || netstat -tupn 2>/dev/null",
    "running_processes": "ps -eo pid,user,comm --sort=-%cpu | head -n 20",
    "logged_users": "who 2>/dev/null",
    "last_logins": "last -n 10 2>/dev/null",
    "listening_ports": "ss -tuln 2>/dev/null",
}


class PuyadForensicManager:

    @staticmethod
    def collect_evidence(trigger_reason: str, server_id: int = 1) -> dict[str, Any]:
        ts: str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if not compat.IS_LINUX:
            return {
                "timestamp": ts,
                "trigger_reason": trigger_reason,
                "server_id": server_id,
                "warning": compat.unsupported("Adli kanıt toplama"),
            }

        evidence: dict[str, Any] = {
            "timestamp": ts,
            "trigger_reason": trigger_reason,
            "server_id": server_id,
            **{key: _run(cmd) for key, cmd in _LINUX_COMMANDS.items()},
        }

        with database.get_connection() as conn:
            conn.execute(
                "INSERT INTO forensic_history (server_id, trigger_reason, evidence_json) VALUES (?, ?, ?)",
                (server_id, trigger_reason, json.dumps(evidence, ensure_ascii=False))
            )

        return evidence

    @staticmethod
    def get_history(server_id: int | None = None, limit: int = 50) -> list[dict[str, Any]]:
        with database.get_connection() as conn:
            if server_id:
                rows = conn.execute(
                    "SELECT id, server_id, trigger_reason, created_at FROM forensic_history "
                    "WHERE server_id = ? ORDER BY created_at DESC LIMIT ?",
                    (server_id, limit)
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT id, server_id, trigger_reason, created_at FROM forensic_history "
                    "ORDER BY created_at DESC LIMIT ?",
                    (limit,)
                ).fetchall()
        return [dict(r) for r in rows]

    @staticmethod
    def get_evidence(evidence_id: int) -> dict[str, Any] | None:
        with database.get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM forensic_history WHERE id = ?", (evidence_id,)
            ).fetchone()
        if not row:
            return None
        result: dict[str, Any] = dict(row)
        result["evidence_data"] = json.loads(result["evidence_json"])
        return result

    @staticmethod
    def delete_evidence(evidence_id: int) -> dict[str, Any]:
        with database.get_connection() as conn:
            result = conn.execute("DELETE FROM forensic_history WHERE id = ?", (evidence_id,))
            if result.rowcount == 0:
                return {"success": False, "message": "Kayıt bulunamadı."}
        return {"success": True, "message": "Adli kanıt kaydı silindi."}
