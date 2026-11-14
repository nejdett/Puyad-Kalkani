from __future__ import annotations

import sqlite3
from pathlib import Path

DB_FILE: Path = Path(__file__).parent / "history.db"

_ALLOWED_TABLES: set[str] = {"servers", "fix_history", "snapshots", "scan_history", "scan_results", "forensic_history", "pending_actions", "cve_scans"}


def _validate_table(name: str) -> str:
    if name not in _ALLOWED_TABLES:
        raise ValueError(f"Geçersiz tablo adı: {name}")
    return name


def migrate() -> None:
    if not DB_FILE.exists():
        print("Veritabanı bulunamadı, init_db() zaten yeni şemayı oluşturur.")
        return

    conn: sqlite3.Connection = sqlite3.connect(str(DB_FILE), timeout=10.0)
    try:
        conn.execute("PRAGMA busy_timeout=5000")
        cursor: sqlite3.Cursor = conn.cursor()

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='servers'")
        if not cursor.fetchone():
            print("servers tablosu ekleniyor...")
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS servers (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    name        TEXT    NOT NULL,
                    ip_address  TEXT    NOT NULL,
                    port        INTEGER DEFAULT 8000 CHECK(port BETWEEN 1 AND 65535),
                    status      TEXT    DEFAULT 'offline',
                    last_score  INTEGER DEFAULT 0 CHECK(last_score BETWEEN 0 AND 100),
                    created_at  DATETIME DEFAULT (datetime('now','localtime'))
                )
            """)
            cursor.execute(
                "INSERT INTO servers (id, name, ip_address, port, status) VALUES (?, ?, ?, ?, ?)",
                (1, "Yerel Sunucu", "127.0.0.1", 8000, "online"),
            )
            print("servers tablosu oluşturuldu, localhost seed edildi.")
        else:
            print("servers tablosu zaten mevcut.")

        tables_to_update: list[str] = ["fix_history", "snapshots", "scan_history"]
        for table in tables_to_update:
            _validate_table(table)
            cursor.execute(f"PRAGMA table_info({table})")
            columns: list[str] = [col[1] for col in cursor.fetchall()]

            if "server_id" not in columns:
                print(f"{table} tablosuna server_id ekleniyor...")
                cursor.execute(f"ALTER TABLE {table} ADD COLUMN server_id INTEGER DEFAULT 1")
                print(f"{table} güncellendi.")
            else:
                print(f"{table} tablosunda server_id zaten mevcut.")

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='forensic_history'")
        if not cursor.fetchone():
            print("forensic_history tablosu ekleniyor...")
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS forensic_history (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    server_id       INTEGER DEFAULT 1,
                    trigger_reason  TEXT    NOT NULL,
                    evidence_json   TEXT    NOT NULL,
                    created_at      DATETIME DEFAULT (datetime('now','localtime'))
                )
            """)
            print("forensic_history tablosu oluşturuldu.")
        else:
            print("forensic_history tablosu zaten mevcut.")

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='pending_actions'")
        if not cursor.fetchone():
            print("pending_actions tablosu ekleniyor...")
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS pending_actions (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    server_id       INTEGER DEFAULT 1,
                    token           TEXT    UNIQUE NOT NULL,
                    action_type     TEXT    NOT NULL,
                    target_payload  TEXT,
                    status          TEXT    DEFAULT 'pending',
                    created_at      DATETIME DEFAULT (datetime('now','localtime'))
                )
            """)
            print("pending_actions tablosu oluşturuldu.")
        else:
            print("pending_actions tablosu zaten mevcut.")

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='cve_scans'")
        if not cursor.fetchone():
            print("cve_scans tablosu ekleniyor...")
            cursor.execute("""
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
                )
            """)
            print("cve_scans tablosu oluşturuldu.")
        else:
            print("cve_scans tablosu zaten mevcut.")

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_jobs (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                kind        TEXT    NOT NULL,
                server_id   INTEGER NOT NULL,
                status      TEXT    NOT NULL DEFAULT 'pending',
                result      TEXT,
                error       TEXT,
                created_at  DATETIME DEFAULT (datetime('now','localtime')),
                updated_at  DATETIME DEFAULT (datetime('now','localtime'))
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ip_blocks (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                ip              TEXT    NOT NULL,
                reason          TEXT,
                source          TEXT    NOT NULL,
                created_at      DATETIME DEFAULT (datetime('now','localtime')),
                expires_at      DATETIME NOT NULL,
                removed_at      DATETIME,
                removed_reason  TEXT
            )
        """)

        cursor.execute("SELECT name FROM sqlite_master WHERE type='trigger' AND name='prevent_delete_localhost'")
        if not cursor.fetchone():
            cursor.execute("""
                CREATE TRIGGER prevent_delete_localhost
                BEFORE DELETE ON servers
                WHEN OLD.id = 1
                BEGIN
                    SELECT RAISE(ABORT, 'Yerel sunucu (id=1) silinemez.');
                END
            """)
            print("localhost koruma trigger'ı eklendi.")

        for ddl in [
            "CREATE INDEX IF NOT EXISTS idx_scan_results_scan_id ON scan_results(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_fix_history_server ON fix_history(server_id)",
            "CREATE INDEX IF NOT EXISTS idx_snapshots_server ON snapshots(server_id)",
            "CREATE INDEX IF NOT EXISTS idx_forensic_server ON forensic_history(server_id)",
            "CREATE INDEX IF NOT EXISTS idx_cve_scans_server ON cve_scans(server_id)",
            "CREATE INDEX IF NOT EXISTS idx_scan_jobs_kind ON scan_jobs(kind, status)",
            "CREATE INDEX IF NOT EXISTS idx_ip_blocks_active ON ip_blocks(removed_at, expires_at)",
        ]:
            cursor.execute(ddl)

        conn.commit()
    finally:
        try:
            conn.close()
        except sqlite3.Error:
            pass
    print("Geçiş tamamlandı.")


if __name__ == "__main__":
    migrate()
