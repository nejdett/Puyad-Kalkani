from __future__ import annotations

import json
import logging
import os
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
import config
import database
import network_mapper
import scheduler
import throttle


def _age(days: float) -> str:
    return f"-{days} days"


def _clear() -> None:
    with database.get_connection() as conn:
        for t in ("honeypot_hits", "bruteforce_log", "forensic_history", "pending_actions"):
            conn.execute(f"DELETE FROM {t}")


def _seed() -> None:
    _clear()
    with database.get_connection() as conn:
        for days in (10, 40, 100):
            ts = ("now", "localtime", _age(days))
            conn.execute(
                "INSERT INTO honeypot_hits (port, service, src_ip, created_at) VALUES (22, 'ssh', ?, datetime(?, ?, ?))",
                (f"203.0.113.{days}", *ts),
            )
            conn.execute(
                "INSERT INTO bruteforce_log (src_ip, attempts, created_at) VALUES (?, 5, datetime(?, ?, ?))",
                (f"203.0.113.{days}", *ts),
            )
            conn.execute(
                "INSERT INTO forensic_history (trigger_reason, evidence_json, created_at) VALUES (?, '{}', datetime(?, ?, ?))",
                (f"t{days}", *ts),
            )
        for token, status, age in (
            ("eski-onay", "approved", "-2 hours"), ("eski-red", "rejected", "-2 hours"),
            ("suresi-dolan", "pending", "-2 hours"), ("taze", "pending", "-10 minutes"),
            ("taze-onay", "approved", "-10 minutes"), ("isleniyor", "processing", "-2 hours"),
        ):
            conn.execute(
                "INSERT INTO pending_actions (token, action_type, target_payload, status, created_at)"
                " VALUES (?, 'block_ip', '{}', ?, datetime('now', 'localtime', ?))",
                (token, status, age),
            )


def _count(table: str) -> int:
    with database.get_connection() as conn:
        return int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])


def _tokens() -> set[str]:
    with database.get_connection() as conn:
        return {r["token"] for r in conn.execute("SELECT token FROM pending_actions").fetchall()}


def test_default_retention_periods() -> None:
    _seed()
    removed = scheduler.run_retention_cleanup()
    assert _count("honeypot_hits") == 1
    assert _count("bruteforce_log") == 2
    assert _count("forensic_history") == 2
    assert _tokens() == {"taze", "taze-onay", "isleniyor"}
    assert removed["honeypot_hits"] == 2
    assert removed["pending_actions"] == 3
    _clear()


def test_retention_configurable(monkeypatch: pytest.MonkeyPatch) -> None:
    _seed()
    config.update_config({"RETENTION_HONEYPOT_DAYS": 5, "RETENTION_FORENSIC_DAYS": 0, "RETENTION_BRUTEFORCE_DAYS": 50})
    scheduler.run_retention_cleanup()
    assert _count("honeypot_hits") == 0
    assert _count("forensic_history") == 3
    assert _count("bruteforce_log") == 2
    _clear()


def test_rate_limit_logs_purged() -> None:
    old = (datetime.now() - timedelta(days=100)).isoformat()
    new = (datetime.now() - timedelta(days=1)).isoformat()
    throttle.RATE_LIMIT_LOG_DIR.mkdir(parents=True, exist_ok=True)
    throttle.RATE_LIMIT_LOG_JSON.write_text(json.dumps([{"timestamp": old, "ip": "1.1.1.1"}, {"timestamp": new, "ip": "2.2.2.2"}]))
    throttle.RATE_LIMIT_LOG_FILE.write_text(f"[{old}] BLOCKED | IP: 1.1.1.1\n[{new}] BLOCKED | IP: 2.2.2.2\n")
    old_archive = throttle.RATE_LIMIT_LOG_DIR / "rate_limit.1000.log"
    new_archive = throttle.RATE_LIMIT_LOG_DIR / "rate_limit.2000.log"
    old_archive.write_text("x")
    new_archive.write_text("y")
    past = time.time() - 100 * 86400
    os.utime(old_archive, (past, past))

    removed = scheduler.run_retention_cleanup()

    assert [e["ip"] for e in json.loads(throttle.RATE_LIMIT_LOG_JSON.read_text())] == ["2.2.2.2"]
    assert throttle.RATE_LIMIT_LOG_FILE.read_text() == f"[{new}] BLOCKED | IP: 2.2.2.2\n"
    assert throttle.RATE_LIMIT_LOG_FILE.stat().st_mode & 0o777 == 0o600
    assert not old_archive.exists() and new_archive.exists()
    assert removed["rate_limit_logs"] == 3


def test_cleanup_job_registered_daily() -> None:
    fake = MagicMock(running=True)
    with patch.object(scheduler, "_scheduler", fake), patch.object(scheduler, "load_config", return_value={}):
        scheduler.start_scheduler()
    kwargs: dict[str, Any] = fake.add_job.call_args.kwargs
    assert fake.add_job.call_args.args[0] is scheduler.run_retention_cleanup
    assert kwargs["id"] == "retention_cleanup"
    assert str(kwargs["trigger"]).startswith("cron[")
    assert "hour='4'" in str(kwargs["trigger"])


@pytest.mark.parametrize("enabled,expected_calls", [(False, 0), (True, 1)])
def test_geoip_setting(enabled: bool, expected_calls: int, monkeypatch: pytest.MonkeyPatch) -> None:
    config.update_config({"NETWORK_GEOIP_ENABLED": enabled})
    monkeypatch.setattr(network_mapper, "_geoip_cache", {})
    monkeypatch.setattr(network_mapper, "_host_geo_cache", None)
    resp = MagicMock(status_code=200)
    resp.json.return_value = {"status": "success", "country": "X", "countryCode": "XX", "city": "Y", "lat": 1, "lon": 2}
    with patch.object(network_mapper.httpx, "get", return_value=resp) as get:
        result = network_mapper.PuyadNetworkMapper.get_geoip_data("8.8.8.8")
        network_mapper.PuyadNetworkMapper.get_geoip_data("192.168.1.5")
    public_calls = [c for c in get.call_args_list if "8.8.8.8" in str(c.args[0])]
    assert len(public_calls) == expected_calls
    if not enabled:
        assert get.call_count == 0
        assert result["country"] == "Bilinmiyor"


def test_geoip_enabled_by_default() -> None:
    assert config.DEFAULTS["NETWORK_GEOIP_ENABLED"] is True


def test_stuck_processing_marked_failed_not_deleted(caplog: pytest.LogCaptureFixture) -> None:
    _clear()
    with database.get_connection() as conn:
        for token, age in (("takili", "-71 minutes"), ("yeni-isleniyor", "-30 minutes")):
            conn.execute(
                "INSERT INTO pending_actions (token, action_type, target_payload, status, created_at)"
                " VALUES (?, 'block_ip', '{}', 'processing', datetime('now', 'localtime', ?))",
                (token, age),
            )
    with caplog.at_level(logging.WARNING, logger="scheduler"):
        scheduler.run_retention_cleanup()
    with database.get_connection() as conn:
        rows = {r["token"]: r["status"] for r in conn.execute("SELECT token, status FROM pending_actions")}
    assert rows == {"takili": "failed", "yeni-isleniyor": "processing"}
    assert "başarısız işaretlendi" in caplog.text
