from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Generator

DB_FILE: Path = Path(__file__).parent / "history.db"


@contextmanager
def get_connection() -> Generator[sqlite3.Connection, None, None]:
    if not DB_FILE.exists():
        init_db()
    conn = sqlite3.connect(str(DB_FILE), timeout=10.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("PRAGMA synchronous=NORMAL")
    except sqlite3.Error:
        pass
    try:
        yield conn
        conn.commit()
    except Exception:
        try:
            conn.rollback()
        except sqlite3.Error:
            pass
        raise
    finally:
        try:
            conn.close()
        except sqlite3.Error:
            pass


def _get_raw_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_FILE), timeout=10.0)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def update_server_score(server_id: int, score: int) -> None:
    score = max(0, min(100, int(score)))
    with get_connection() as conn:
        conn.execute("UPDATE servers SET last_score = ? WHERE id = ?", (score, server_id))


def update_server_status(server_id: int, status: str, score: int | None = None) -> None:
    if score is not None:
        score = max(0, min(100, int(score)))
    with get_connection() as conn:
        if score is None:
            conn.execute("UPDATE servers SET status = ? WHERE id = ?", (status, server_id))
        else:
            conn.execute(
                "UPDATE servers SET status = ?, last_score = ? WHERE id = ?",
                (status, score, server_id),
            )


def update_server_token(server_id: int, token: str) -> None:
    with get_connection() as conn:
        conn.execute("UPDATE servers SET token = ? WHERE id = ?", (token, server_id))


def init_db() -> None:
    conn = _get_raw_connection()
    try:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS servers (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT    NOT NULL,
            ip_address  TEXT    NOT NULL,
            port        INTEGER DEFAULT 8000 CHECK(port BETWEEN 1 AND 65535),
            status      TEXT    DEFAULT 'offline',
            last_score  INTEGER DEFAULT 0 CHECK(last_score BETWEEN 0 AND 100),
            created_at  DATETIME DEFAULT (datetime('now','localtime'))
        );

        CREATE TABLE IF NOT EXISTS fix_history (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_id     TEXT    NOT NULL,
            rule_name   TEXT    NOT NULL,
            status      TEXT    NOT NULL,
            output      TEXT,
            snapshot_id TEXT,
            server_id   INTEGER DEFAULT 1,
            created_at  DATETIME DEFAULT (datetime('now','localtime'))
        );

        CREATE TABLE IF NOT EXISTS snapshots (
            id          TEXT    PRIMARY KEY,
            label       TEXT    NOT NULL,
            path        TEXT    NOT NULL,
            size_bytes  INTEGER DEFAULT 0,
            server_id   INTEGER DEFAULT 1,
            created_at  DATETIME DEFAULT (datetime('now','localtime'))
        );

        CREATE TABLE IF NOT EXISTS scan_history (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            total       INTEGER DEFAULT 0,
            warnings    INTEGER DEFAULT 0,
            ok_count    INTEGER DEFAULT 0,
            score       INTEGER DEFAULT 0,
            server_id   INTEGER DEFAULT 1,
            created_at  DATETIME DEFAULT (datetime('now','localtime'))
        );

        CREATE TABLE IF NOT EXISTS scan_results (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id     INTEGER NOT NULL REFERENCES scan_history(id),
            rule_id     TEXT    NOT NULL,
            rule_name   TEXT    NOT NULL,
            status      TEXT    NOT NULL,
            output      TEXT
        );

        CREATE TABLE IF NOT EXISTS forensic_history (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            server_id       INTEGER DEFAULT 1,
            trigger_reason  TEXT    NOT NULL,
            evidence_json   TEXT    NOT NULL,
            created_at      DATETIME DEFAULT (datetime('now','localtime'))
        );

        CREATE TABLE IF NOT EXISTS pending_actions (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            server_id       INTEGER DEFAULT 1,
            token           TEXT    UNIQUE NOT NULL,
            action_type     TEXT    NOT NULL,
            target_payload  TEXT,
            status          TEXT    DEFAULT 'pending',
            created_at      DATETIME DEFAULT (datetime('now','localtime'))
        );

        CREATE TABLE IF NOT EXISTS cve_scans (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            server_id           INTEGER DEFAULT 1,
            vulnerability_score INTEGER DEFAULT 0,
            critical_count      INTEGER DEFAULT 0,
            high_count          INTEGER DEFAULT 0,
            medium_count        INTEGER DEFAULT 0,
            low_count           INTEGER DEFAULT 0,
            scan_results        TEXT,
            created_at          DATETIME DEFAULT (datetime('now','localtime'))
        );

        CREATE TABLE IF NOT EXISTS scan_jobs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            kind        TEXT    NOT NULL,
            server_id   INTEGER NOT NULL,
            status      TEXT    NOT NULL DEFAULT 'pending',
            result      TEXT,
            error       TEXT,
            created_at  DATETIME DEFAULT (datetime('now','localtime')),
            updated_at  DATETIME DEFAULT (datetime('now','localtime'))
        );

        CREATE TABLE IF NOT EXISTS ip_blocks (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            ip              TEXT    NOT NULL,
            reason          TEXT,
            source          TEXT    NOT NULL,
            created_at      DATETIME DEFAULT (datetime('now','localtime')),
            expires_at      DATETIME NOT NULL,
            removed_at      DATETIME,
            removed_reason  TEXT
        );

        CREATE TABLE IF NOT EXISTS honeypot_hits (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            port       INTEGER NOT NULL,
            service    TEXT,
            src_ip     TEXT NOT NULL,
            src_port   INTEGER,
            data       TEXT,
            created_at DATETIME DEFAULT (datetime('now','localtime'))
        );

        CREATE TABLE IF NOT EXISTS bruteforce_log (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            src_ip     TEXT NOT NULL,
            attempts   INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT (datetime('now','localtime'))
        );

        CREATE TABLE IF NOT EXISTS cve_package_cache (
            pkg_name    TEXT    NOT NULL,
            pkg_version TEXT    NOT NULL,
            vulns_json  TEXT    NOT NULL,
            created_at  DATETIME DEFAULT (datetime('now','localtime')),
            PRIMARY KEY (pkg_name, pkg_version)
        );

        CREATE TABLE IF NOT EXISTS cve_vuln_details (
            vuln_id     TEXT    PRIMARY KEY,
            detail_json TEXT    NOT NULL,
            created_at  DATETIME DEFAULT (datetime('now','localtime'))
        );

        CREATE TABLE IF NOT EXISTS cve_fix_history (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            server_id   INTEGER DEFAULT 1,
            package     TEXT    NOT NULL,
            status      TEXT    NOT NULL,
            old_version TEXT,
            new_version TEXT,
            output      TEXT,
            created_at  DATETIME DEFAULT (datetime('now','localtime'))
        );
        """)
        conn.executescript("""
        CREATE INDEX IF NOT EXISTS idx_scan_results_scan_id ON scan_results(scan_id);
        CREATE INDEX IF NOT EXISTS idx_fix_history_server ON fix_history(server_id);
        CREATE INDEX IF NOT EXISTS idx_snapshots_server ON snapshots(server_id);
        CREATE INDEX IF NOT EXISTS idx_forensic_server ON forensic_history(server_id);
        CREATE INDEX IF NOT EXISTS idx_cve_scans_server ON cve_scans(server_id);
        CREATE INDEX IF NOT EXISTS idx_cve_fix_server ON cve_fix_history(server_id);
        CREATE INDEX IF NOT EXISTS idx_scan_jobs_kind ON scan_jobs(kind, status);
        CREATE INDEX IF NOT EXISTS idx_ip_blocks_active ON ip_blocks(removed_at, expires_at);
        """)

        existing = conn.execute("SELECT id FROM servers WHERE id = 1").fetchone()
        if not existing:
            conn.execute(
                "INSERT INTO servers (id, name, ip_address, port, status) VALUES (?, ?, ?, ?, ?)",
                (1, "Yerel Sunucu", "127.0.0.1", 8000, "online"),
            )
        cols = [c[1] for c in conn.execute("PRAGMA table_info(servers)").fetchall()]
        if "token" not in cols:
            conn.execute("ALTER TABLE servers ADD COLUMN token TEXT DEFAULT ''")
        if "agent_id" not in cols:
            conn.execute("ALTER TABLE servers ADD COLUMN agent_id TEXT")
        if "agent_cert_pem" not in cols:
            conn.execute("ALTER TABLE servers ADD COLUMN agent_cert_pem TEXT DEFAULT ''")
        if "agent_cert_status" not in cols:
            conn.execute("ALTER TABLE servers ADD COLUMN agent_cert_status TEXT DEFAULT ''")
        conn.commit()
    finally:
        try:
            conn.close()
        except sqlite3.Error:
            pass


def get_cached_package_vulns(pkg_name: str, pkg_version: str) -> list[dict[str, Any]] | None:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT vulns_json FROM cve_package_cache WHERE pkg_name = ? AND pkg_version = ?",
            (pkg_name, pkg_version),
        ).fetchone()
        if row:
            try:
                data: Any = json.loads(row[0])
                if isinstance(data, list):
                    return data
            except Exception:
                return None
    return None


def set_cached_package_vulns(pkg_name: str, pkg_version: str, vulns: list[dict[str, Any]]) -> None:
    vulns_json = json.dumps(vulns, ensure_ascii=False)
    with get_connection() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO cve_package_cache (pkg_name, pkg_version, vulns_json, created_at) "
            "VALUES (?, ?, ?, datetime('now','localtime'))",
            (pkg_name, pkg_version, vulns_json),
        )


def get_cached_vuln_detail(vuln_id: str) -> dict[str, Any] | None:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT detail_json FROM cve_vuln_details WHERE vuln_id = ?",
            (vuln_id,),
        ).fetchone()
        if row:
            try:
                data: Any = json.loads(row[0])
                if isinstance(data, dict):
                    return data
            except Exception:
                return None
    return None


def set_cached_vuln_detail(vuln_id: str, detail: dict[str, Any]) -> None:
    detail_json = json.dumps(detail, ensure_ascii=False)
    with get_connection() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO cve_vuln_details (vuln_id, detail_json, created_at) "
            "VALUES (?, ?, datetime('now','localtime'))",
            (vuln_id, detail_json),
        )


def clear_cve_caches() -> None:
    with get_connection() as conn:
        conn.execute("DELETE FROM cve_package_cache")
        conn.execute("DELETE FROM cve_vuln_details")
