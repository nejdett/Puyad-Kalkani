from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, cast

import backup_manager
import config as app_config
import database
import engine
import firewall
from fileutil import atomic_write_json
import remediation_engine
import throttle
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

logger = logging.getLogger(__name__)

CONFIG_FILE: Path = Path(__file__).parent / "scheduler_config.json"
ALERT_FILE: Path = Path(__file__).parent / "scheduler_alerts.json"

CRITICAL_SCORE_THRESHOLD: int = 60

_scheduler: Any = BackgroundScheduler(timezone="Europe/Istanbul")
_lock: threading.Lock = threading.Lock()
_file_lock: threading.Lock = threading.Lock()
# Tarama sonu last_run yazımı aynı anda yapılan zamanlama değişikliğini ezmesin
_config_lock: threading.Lock = threading.Lock()


def _default_config() -> dict[str, Any]:
    return {
        "enabled": False,
        "interval": "weekly",
        "day_of_week": "mon",
        "hour": 3,
        "minute": 0,
        "last_run": None,
        "next_run": None,
    }


def load_config() -> dict[str, Any]:
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                data: Any = json.load(f)
                cfg: dict[str, Any] = data
                defaults: dict[str, Any] = _default_config()
                for k, v in defaults.items():
                    cfg.setdefault(k, v)
                return cfg
        except (json.JSONDecodeError, OSError) as exc:
            logger.debug("Zamanlayıcı yapılandırması okunamadı: %s", exc)
    return _default_config()


def save_config(cfg: dict[str, Any]) -> None:
    with _file_lock:
        try:
            atomic_write_json(CONFIG_FILE, cfg)
        except OSError as exc:
            logger.warning("Zamanlayıcı yapılandırması kaydedilemedi: %s", exc)


def get_alerts() -> list[dict[str, Any]]:
    if not ALERT_FILE.exists():
        return []
    try:
        with open(ALERT_FILE, "r", encoding="utf-8") as f:
            data: Any = json.load(f)
            return cast(list[dict[str, Any]], data)
    except (json.JSONDecodeError, OSError) as exc:
        logger.debug("Zamanlanmış tarama uyarıları okunamadı: %s", exc)
        return []


def add_alert(message: str, score: int) -> None:
    with _file_lock:
        alerts: list[dict[str, Any]] = get_alerts()
        alerts.insert(0, {
            "message": message,
            "score": score,
            "created_at": datetime.now().isoformat(),
            "read": False,
        })
        alerts = alerts[:20]
        try:
            atomic_write_json(ALERT_FILE, alerts)
        except OSError as exc:
            logger.warning("Uyarı kaydedilemedi: %s", exc)


def mark_alerts_read() -> None:
    with _file_lock:
        alerts: list[dict[str, Any]] = get_alerts()
        for a in alerts:
            a["read"] = True
        try:
            atomic_write_json(ALERT_FILE, alerts)
        except OSError as exc:
            logger.warning("Uyarılar okundu olarak işaretlenemedi: %s", exc)


def get_unread_count() -> int:
    return sum(1 for a in get_alerts() if not a.get("read", True))


def _run_scheduled_scan() -> None:
    if not _lock.acquire(blocking=False):
        logger.info("Zamanlanmış tarama atlandı, başka bir tarama sürüyor.")
        return
    try:
        logger.info("Zamanlanmış tarama başladı")
        results: list[dict[str, Any]] = engine.scan_all()
        remediation_engine.save_scan_to_history(results)

        total: int = len(results)
        ok_count: int = sum(1 for r in results if r["status"] == "ok")
        score: int = int(ok_count / total * 100) if total > 0 else 0

        with _config_lock:
            cfg: dict[str, Any] = load_config()
            cfg["last_run"] = datetime.now().isoformat()
            save_config(cfg)

        if score < CRITICAL_SCORE_THRESHOLD:
            warnings: int = total - ok_count
            add_alert(
                f"Tarama tamamlandı. Güvenlik skoru kritik: {score}/100. "
                f"{warnings} uyarı tespit edildi.",
                score,
            )
            logger.warning("Zamanlanmış tarama bitti, skor kritik: %d/100", score)
        else:
            logger.info("Zamanlanmış tarama bitti, skor: %d/100", score)

    except Exception as e:
        logger.error("Zamanlanmış tarama başarısız: %s", e)
        try:
            add_alert(f"Tarama başarısız: {e!s}", 0)
        except Exception:
            pass
    finally:
        _lock.release()


def _build_trigger(cfg: dict[str, Any]) -> Any:
    interval: str = str(cfg.get("interval", "weekly"))
    raw_hour: Any = cfg.get("hour", 3)
    raw_minute: Any = cfg.get("minute", 0)
    try:
        hour: int = int(raw_hour)
        minute: int = int(raw_minute)
    except (TypeError, ValueError):
        raise ValueError("Saat/dakika sayısal olmalı.")
    if not (0 <= hour <= 23):
        raise ValueError(f"Saat 0-23 aralığında olmalı, gelen: {hour}")
    if not (0 <= minute <= 59):
        raise ValueError(f"Dakika 0-59 aralığında olmalı, gelen: {minute}")

    if interval == "daily":
        return CronTrigger(hour=hour, minute=minute, timezone="Europe/Istanbul")
    elif interval == "monthly":
        return CronTrigger(day=1, hour=hour, minute=minute, timezone="Europe/Istanbul")
    elif interval == "weekly":
        day = str(cfg.get("day_of_week", "mon")).lower()
        if day not in ("mon", "tue", "wed", "thu", "fri", "sat", "sun"):
            raise ValueError(f"Geçersiz gün: {day}")
        return CronTrigger(day_of_week=day, hour=hour, minute=minute, timezone="Europe/Istanbul")
    else:
        raise ValueError(f"Geçersiz interval: {interval} (daily/weekly/monthly olmalı).")


# Tablo -> config anahtarı. Kişisel veri (IP, honeypot ham verisi) süresiz tutulmasın
STUCK_PROCESSING_MINUTES: int = 10

_RETENTION_TABLES: dict[str, str] = {
    "honeypot_hits": "RETENTION_HONEYPOT_DAYS",
    "bruteforce_log": "RETENTION_BRUTEFORCE_DAYS",
    "forensic_history": "RETENTION_FORENSIC_DAYS",
}


def _retention_days(cfg: dict[str, Any], key: str) -> int:
    try:
        return int(cfg.get(key, app_config.DEFAULTS[key]))
    except (TypeError, ValueError):
        logger.warning("%s geçersiz, varsayılan kullanılıyor.", key)
        return int(app_config.DEFAULTS[key])


def run_retention_cleanup() -> dict[str, int]:
    from telegram_manager import APPROVAL_TTL_HOURS

    cfg = app_config.load_config()
    removed: dict[str, int] = {}
    with database.get_connection() as conn:
        for table, key in _RETENTION_TABLES.items():
            days = _retention_days(cfg, key)
            # 0 ya da negatif — bu tablo için temizlik kapalı
            if days < 1:
                continue
            removed[table] = conn.execute(
                f"DELETE FROM {table} WHERE created_at < datetime('now', 'localtime', ?)",  # nosec B608 sabit tablo adı
                (f"-{days} days",),
            ).rowcount
        removed["pending_actions"] = conn.execute(
            "DELETE FROM pending_actions WHERE status != 'processing'"
            " AND created_at < datetime('now', 'localtime', ?)",
            (f"-{APPROVAL_TTL_HOURS} hours",),
        ).rowcount
        # Onay yalnızca TTL içinde alınabiliyor — created_at TTL+10 dk'dan eskiyse en az 10 dk'dır processing'de
        stuck = [
            r["id"] for r in conn.execute(
                "SELECT id FROM pending_actions WHERE status = 'processing'"
                " AND created_at < datetime('now', 'localtime', ?)",
                (f"-{APPROVAL_TTL_HOURS * 60 + STUCK_PROCESSING_MINUTES} minutes",),
            ).fetchall()
        ]
        if stuck:
            conn.executemany("UPDATE pending_actions SET status = 'failed' WHERE id = ?", [(i,) for i in stuck])
            logger.warning(
                "%d onay işlemi %d dakikadan uzun süredir işleniyordu, başarısız işaretlendi: id=%s",
                len(stuck), STUCK_PROCESSING_MINUTES, stuck,
            )
    days = _retention_days(cfg, "RETENTION_RATE_LIMIT_DAYS")
    if days >= 1:
        try:
            removed["rate_limit_logs"] = throttle.limiter.logger.purge_older_than(
                datetime.now() - timedelta(days=days)
            )
        except OSError as exc:
            logger.warning("Rate limit log temizliği başarısız: %s", exc)
    if any(removed.values()):
        logger.info("Saklama süresi temizliği: %s", removed)
    return removed


def _expire_blocks() -> None:
    if not backup_manager.SYSTEM_CHANGE_LOCK.acquire(blocking=False):
        return
    try:
        firewall.expire()
    finally:
        backup_manager.SYSTEM_CHANGE_LOCK.release()


def start_scheduler() -> None:
    if not _scheduler.running:
        _scheduler.start()

    _scheduler.add_job(_expire_blocks, trigger="interval", minutes=5, id="expire_blocks", replace_existing=True)

    # Günlük, açılışta da bir kez — sunucu 04:30'da kapalıysa temizlik atlanmasın
    _scheduler.add_job(
        run_retention_cleanup,
        trigger=CronTrigger(hour=4, minute=30),
        id="retention_cleanup",
        replace_existing=True,
        next_run_time=datetime.now(),
    )

    cfg: dict[str, Any] = load_config()
    if cfg.get("enabled"):
        try:
            _apply_schedule(cfg)
        except Exception as e:
            logger.warning("Açılışta tarama zamanlanamadı: %s", e)


def _apply_schedule(cfg: dict[str, Any]) -> None:
    try:
        _scheduler.remove_job("auto_scan")
    except Exception:
        pass

    if cfg.get("enabled"):
        trigger: CronTrigger = _build_trigger(cfg)
        job = _scheduler.add_job(
            _run_scheduled_scan,
            trigger=trigger,
            id="auto_scan",
            replace_existing=True,
        )
        cfg["next_run"] = job.next_run_time.isoformat() if job.next_run_time else None
        save_config(cfg)


def update_schedule(enabled: bool, interval: str = "weekly",
                    day_of_week: str = "mon", hour: int = 3, minute: int = 0) -> dict[str, Any]:
    if interval not in ("daily", "weekly", "monthly"):
        raise ValueError(f"Geçersiz interval: {interval}")
    if interval == "weekly" and day_of_week not in ("mon", "tue", "wed", "thu", "fri", "sat", "sun"):
        raise ValueError(f"Geçersiz gün: {day_of_week}")
    if not (0 <= hour <= 23 and 0 <= minute <= 59):
        raise ValueError("Saat/dakika aralık dışı.")

    with _config_lock:
        cfg: dict[str, Any] = load_config()
        cfg["enabled"] = enabled
        cfg["interval"] = interval
        cfg["day_of_week"] = day_of_week
        cfg["hour"] = hour
        cfg["minute"] = minute
        _apply_schedule(cfg)
    return cfg


def run_now() -> dict[str, Any]:
    if _lock.locked():
        return {"success": False, "message": "Zaten bir tarama çalışıyor."}
    threading.Thread(target=_run_scheduled_scan, daemon=True).start()
    return {"success": True, "message": "Tarama arka planda başlatıldı."}


def shutdown_scheduler() -> None:
    if _scheduler.running:
        _scheduler.shutdown(wait=False)
