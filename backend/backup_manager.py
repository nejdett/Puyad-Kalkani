from __future__ import annotations

import logging
import os
import re
import shutil
import tarfile
import tempfile
import threading
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

import compat
import database

logger = logging.getLogger(__name__)

SNAPSHOT_DIR: Path = Path(__file__).parent / "snapshots"
# Fix, rollback, snapshot ve CVE düzeltmesi aynı anda /etc ve paketleri değiştirmesin
SYSTEM_CHANGE_LOCK: threading.Lock = threading.Lock()
SNAPSHOT_DIR.mkdir(exist_ok=True)

BACKUP_PATHS: list[str] = ["/etc"]


def _sanitize_label(label: str) -> str:
    if not label:
        return "manual"
    label = label.replace("..", "__")
    safe = re.sub(r"[^a-zA-Z0-9._-]", "_", label)[:40]
    return safe or "manual"


def create_snapshot(label: str = "") -> dict[str, Any]:
    if not compat.IS_LINUX:
        return {"success": False, "message": compat.unsupported("Snapshot alma")}
    snap_id: str = str(uuid.uuid4())
    timestamp: str = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_label: str = _sanitize_label(label)
    filename: str = f"{timestamp}_{safe_label}_{snap_id[:8]}.tar.gz"
    snap_path: Path = (SNAPSHOT_DIR / filename).resolve()
    if not str(snap_path).startswith(str(SNAPSHOT_DIR.resolve())):
        return {"success": False, "message": "Geçersiz etiket — dosya yolu engellendi."}
    if len(filename) > 200:
        return {"success": False, "message": "Dosya adı çok uzun."}

    tmp_path = snap_path.with_suffix(snap_path.suffix + ".tmp")
    skipped: list[str] = []
    try:
        with tarfile.open(str(tmp_path), "w:gz") as tar:
            for path in BACKUP_PATHS:
                p: Path = Path(path)
                if p.exists():
                    try:
                        tar.add(str(p), arcname=p.name)
                    except OSError:
                        logger.warning("Snapshot'a eklenemeyen yol: %s", p, exc_info=True)
                        skipped.append(f"{p} yedeğe eklenemedi.")

        tmp_path.replace(snap_path)
        size: int = snap_path.stat().st_size

        try:
            with database.get_connection() as conn:
                conn.execute(
                    "INSERT INTO snapshots (id, label, path, size_bytes) VALUES (?, ?, ?, ?)",
                    (snap_id, label or "Manuel Yedek", str(snap_path), size),
                )
        except Exception:
            logger.exception("Snapshot DB kaydı başarısız: %s", snap_id)
            try:
                snap_path.unlink(missing_ok=True)
            except OSError:
                pass
            return {"success": False, "message": "Snapshot veritabanına kaydedilemedi."}

        result: dict[str, Any] = {
            "success": True,
            "snapshot_id": snap_id,
            "path": str(snap_path),
            "label": label or "Manuel Yedek",
            "size_bytes": size,
            "created_at": datetime.now().isoformat(),
        }
        if skipped:
            result["warnings"] = skipped
        return result

    except Exception:
        logger.exception("Snapshot oluşturulamadı")
        for p in [tmp_path, snap_path]:
            try:
                if p.exists():
                    p.unlink()
            except OSError:
                pass
        return {"success": False, "message": "Snapshot oluşturulamadı."}


def list_snapshots() -> list[dict[str, Any]]:
    with database.get_connection() as conn:
        rows = conn.execute(
            "SELECT id, label, path, size_bytes, created_at FROM snapshots ORDER BY created_at DESC"
        ).fetchall()
    return [dict(r) for r in rows]


def delete_snapshot(snapshot_id: str) -> dict[str, Any]:
    if not snapshot_id or any(c in snapshot_id for c in ("/", "\\", "..", "\x00")):
        return {"success": False, "message": "Geçersiz snapshot ID."}
    with database.get_connection() as conn:
        row = conn.execute(
            "SELECT path FROM snapshots WHERE id = ?", (snapshot_id,)
        ).fetchone()
        if not row:
            return {"success": False, "message": "Snapshot bulunamadı."}
        snap_path: Path = Path(row["path"]).resolve()
        try:
            snap_path.relative_to(SNAPSHOT_DIR.resolve())
        except ValueError:
            return {"success": False, "message": "Snapshot yolu geçersiz — silme engellendi."}
        if snap_path.suffixes[-2:] != [".tar", ".gz"] and snap_path.suffix != ".gz":
            return {"success": False, "message": "Beklenmeyen dosya türü — silme engellendi."}
        if snap_path.exists():
            try:
                snap_path.unlink()
            except OSError:
                logger.exception("Snapshot dosyası silinemedi: %s", snapshot_id)
                return {"success": False, "message": "Snapshot dosyası silinemedi."}
        conn.execute("DELETE FROM snapshots WHERE id = ?", (snapshot_id,))
    return {"success": True, "message": "Snapshot silindi."}


def rollback_snapshot(snapshot_id: str) -> dict[str, Any]:
    if not compat.IS_LINUX:
        return {"success": False, "message": compat.unsupported("Geri yükleme")}
    if not snapshot_id or any(c in snapshot_id for c in ("/", "\\", "..")):
        return {"success": False, "message": "Geçersiz snapshot ID."}
    with database.get_connection() as conn:
        row = conn.execute(
            "SELECT path, label FROM snapshots WHERE id = ?", (snapshot_id,)
        ).fetchone()

    if not row:
        return {"success": False, "message": "Snapshot bulunamadı."}

    snap_path: Path = Path(row["path"])
    if not snap_path.exists():
        return {"success": False, "message": "Snapshot dosyası diskte bulunamadı."}

    pre_rollback: dict[str, Any] = create_snapshot(label="Rollback öncesi otomatik yedek")
    if not pre_rollback.get("success"):
        return {"success": False, "message": "Geri yükleme öncesi otomatik yedek alınamadı."}

    temp_dir: Path = Path(tempfile.mkdtemp(prefix=f"_restore_{snapshot_id[:8]}_", dir=str(SNAPSHOT_DIR)))
    quarantine_base = SNAPSHOT_DIR / f"_quarantine_{snapshot_id[:8]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    try:
        with tarfile.open(str(snap_path), "r:gz") as tar:
            for member in tar.getmembers():
                if member.issym() or member.islnk() or member.isdev():
                    continue
                member_path: str = member.name
                if member_path.startswith("/") or ".." in Path(member_path).parts:
                    continue
                try:
                    tar.extract(member, str(temp_dir), filter="data")
                except Exception:
                    continue

        extracted_etc: Path = temp_dir / "etc"
        if not extracted_etc.exists():
            shutil.rmtree(str(temp_dir), ignore_errors=True)
            return {"success": False, "message": "Snapshot içerisinde /etc dizini bulunamadı."}

        snapshot_files: set[str] = set()
        snapshot_dirs: set[str] = set()
        for item in extracted_etc.rglob("*"):
            try:
                rel: str = item.relative_to(extracted_etc).as_posix()
                if item.is_symlink() or item.is_file():
                    snapshot_files.add(rel)
                elif item.is_dir():
                    snapshot_dirs.add(rel)
            except Exception:
                continue

        live_etc: Path = Path("/etc")
        quarantined_count: int = 0
        quarantine_failed: int = 0
        quarantine_dir: Path | None = quarantine_base
        if live_etc.exists():
            live_files: list[Path] = []
            for p in live_etc.rglob("*"):
                try:
                    if p.is_symlink() or p.is_file():
                        live_files.append(p)
                except Exception:
                    continue
            if any(_relative_posix(live_item, live_etc) not in snapshot_files for live_item in live_files):
                quarantine_base.mkdir(parents=True, exist_ok=True)
            for live_item in live_files:
                live_rel = _relative_posix(live_item, live_etc)
                if live_rel is None or live_rel in snapshot_files:
                    continue
                dest_q: Path = quarantine_base / live_rel
                moved = False
                try:
                    dest_q.parent.mkdir(parents=True, exist_ok=True)
                    shutil.move(str(live_item), str(dest_q))
                    quarantined_count += 1
                    moved = True
                except Exception:
                    pass
                if not moved:
                    try:
                        if live_item.is_symlink():
                            link_target: str = os.readlink(str(live_item))
                            if link_target.startswith("/") or ".." in Path(link_target).parts:
                                quarantine_failed += 1
                                continue
                            dest_q.parent.mkdir(parents=True, exist_ok=True)
                            dest_q.symlink_to(link_target)
                            live_item.unlink()
                            quarantined_count += 1
                        else:
                            shutil.copy2(str(live_item), str(dest_q))
                            live_item.unlink()
                            quarantined_count += 1
                    except Exception:
                        quarantine_failed += 1
                        continue
            live_dirs: list[Path] = []
            for p in live_etc.rglob("*"):
                try:
                    if p.is_dir() and not p.is_symlink():
                        live_dirs.append(p)
                except Exception:
                    continue
            for d in sorted(live_dirs, key=lambda x: len(x.parts), reverse=True):
                rel_d = _relative_posix(d, live_etc)
                if rel_d is None or rel_d in snapshot_dirs:
                    continue
                try:
                    if not any(d.iterdir()):
                        d.rmdir()
                except Exception:
                    continue
            try:
                if not quarantine_base.exists():
                    quarantine_dir = None
                elif not any(quarantine_base.iterdir()):
                    quarantine_base.rmdir()
                    quarantine_dir = None
            except Exception:
                pass
            if quarantined_count == 0 and quarantine_dir is not None and not quarantine_dir.exists():
                quarantine_dir = None

        restored_count: int = 0
        failed_count: int = 0
        for item in extracted_etc.rglob("*"):
            try:
                item_str: str = str(item)
                target: Path = Path("/etc") / item.relative_to(extracted_etc)
                if item.is_symlink():
                    link_target = os.readlink(item_str)
                    if link_target.startswith("/") or ".." in Path(link_target).parts:
                        failed_count += 1
                        continue
                    try:
                        if target.is_symlink() or target.exists():
                            if target.is_dir() and not target.is_symlink():
                                shutil.rmtree(str(target), ignore_errors=True)
                            else:
                                target.unlink(missing_ok=True)
                    except Exception:
                        pass
                    try:
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.symlink_to(link_target)
                        restored_count += 1
                    except Exception:
                        failed_count += 1
                elif item.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                elif item.is_file():
                    target.parent.mkdir(parents=True, exist_ok=True)
                    if target.is_dir() and not target.is_symlink():
                        shutil.rmtree(str(target), ignore_errors=True)
                    shutil.copy2(item_str, str(target))
                    restored_count += 1
            except Exception:
                failed_count += 1
                continue

        shutil.rmtree(str(temp_dir), ignore_errors=True)

        quarantine_msg: str = ""
        quarantine_path_str: str = ""
        if quarantined_count > 0 and quarantine_dir is not None:
            quarantine_path_str = str(quarantine_dir)
            quarantine_msg = f" | {quarantined_count} yeni dosya karantinaya alındı ({quarantine_path_str})"
            if quarantine_failed > 0:
                quarantine_msg += f" ({quarantine_failed} karantinaya alınamadı)"
        elif quarantined_count == 0:
            quarantine_msg = " | Yeni dosya bulunmadı"

        scope_warn: str = " Not: Geri yükleme yalnızca /etc dizinini kapsar; /etc dışındaki dosyalar (örn. /usr/sbin/nginx) ayrıca temizlenmelidir."

        msg: str = f"'{row['label']}' başarıyla geri yüklendi. ({restored_count} dosya geri yüklendi{quarantine_msg})"
        if failed_count > 0:
            msg += f" ({failed_count} dosyaya erişilemedi)"
        msg += scope_warn

        result: dict[str, Any] = {
            "success": True,
            "message": msg,
            "pre_rollback_snapshot_id": pre_rollback["snapshot_id"],
            "restored": restored_count,
            "failed": failed_count,
            "quarantined": quarantined_count,
            "scope_warning": scope_warn.strip(),
        }
        if quarantine_path_str:
            result["quarantine_path"] = quarantine_path_str
        if quarantine_failed:
            result["quarantine_failed"] = quarantine_failed
        return result

    except Exception:
        logger.exception("Snapshot geri yüklenemedi: %s", snapshot_id)
        shutil.rmtree(str(temp_dir), ignore_errors=True)
        return {"success": False, "message": "Snapshot geri yüklenemedi."}


def _relative_posix(item: Path, base: Path) -> str | None:
    try:
        return item.relative_to(base).as_posix()
    except Exception:
        return None
