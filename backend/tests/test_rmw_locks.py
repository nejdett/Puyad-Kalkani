from __future__ import annotations

import json
import sys
import threading
import time
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
import config
import cve_analyzer
import database
import engine
import scheduler
import telegram_manager

Mgr = telegram_manager.PuyadTelegramManager


def _slow_io(monkeypatch: pytest.MonkeyPatch, module: Any, name: str) -> None:
    # Okuma ile yazma arasını genişlet ki kilit yoksa yarış kesin görünsün
    real = getattr(module, name)

    def slow(*a: Any, **k: Any) -> Any:
        out = real(*a, **k)
        time.sleep(0.02)
        return out

    monkeypatch.setattr(module, name, slow)


def _run_parallel(fn: Any, args: list[Any]) -> None:
    threads = [threading.Thread(target=fn, args=(a,)) for a in args]
    for t in threads:
        t.start()
    for t in threads:
        t.join()


def test_parallel_rule_adds_all_kept(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(engine, "RULES_FILE", tmp_path / "rules.json")
    (tmp_path / "rules.json").write_text("[]")
    _slow_io(monkeypatch, engine, "load_rules")

    def add(i: int) -> None:
        engine.add_rule({
            "id": f"kural_{i}", "name": f"K{i}", "category": "c", "severity": "low",
            "check_command": "true", "fix_command": "true", "description": "d",
        })

    _run_parallel(add, list(range(8)))
    assert sorted(r["id"] for r in engine.load_rules()) == sorted(f"kural_{i}" for i in range(8))


def test_parallel_ignores_all_kept(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(engine, "RULES_FILE", tmp_path / "rules.json")
    (tmp_path / "rules.json").write_text(json.dumps([{"id": f"r{i}"} for i in range(6)]))
    _slow_io(monkeypatch, engine, "load_ignored")
    _run_parallel(engine.ignore_rule, [f"r{i}" for i in range(6)])
    assert sorted(engine.load_ignored()) == [f"r{i}" for i in range(6)]


def test_parallel_config_updates_all_kept(monkeypatch: pytest.MonkeyPatch) -> None:
    config.load_config()
    _slow_io(monkeypatch, config, "load_config")
    keys = ["TELEGRAM_CHAT_ID", "TELEGRAM_ALLOWED_USER_ID", "RUN_MODE"]
    _run_parallel(lambda k: config.update_config({k: f"deger-{k}"}), keys)
    cfg = json.loads(config.CONFIG_FILE.read_text())
    assert all(cfg[k] == f"deger-{k}" for k in keys)


def test_scan_last_run_does_not_overwrite_schedule_change(monkeypatch: pytest.MonkeyPatch) -> None:
    _slow_io(monkeypatch, scheduler, "load_config")
    monkeypatch.setattr(scheduler.engine, "scan_all", lambda: [{"status": "ok"}])
    monkeypatch.setattr(scheduler.remediation_engine, "save_scan_to_history", lambda r: None)
    monkeypatch.setattr(scheduler, "_apply_schedule", lambda cfg: scheduler.save_config(cfg))
    scan = threading.Thread(target=scheduler._run_scheduled_scan)
    scan.start()
    scheduler.update_schedule(True, "daily", hour=5, minute=7)
    scan.join()
    cfg = scheduler.load_config()
    assert (cfg["enabled"], cfg["hour"], cfg["minute"]) == (True, 5, 7)
    assert cfg.get("last_run")


def _insert_pending(token: str) -> None:
    with database.get_connection() as conn:
        conn.execute("DELETE FROM pending_actions WHERE token = ?", (token,))
        conn.execute(
            "INSERT INTO pending_actions (token, action_type, target_payload, status, created_at)"
            " VALUES (?, 'block_ip', ?, 'pending', datetime('now', 'localtime'))",
            (token, json.dumps({"ip": "203.0.113.7"})),
        )


def _status(token: str) -> str:
    with database.get_connection() as conn:
        return str(conn.execute("SELECT status FROM pending_actions WHERE token = ?", (token,)).fetchone()["status"])


def test_parallel_approvals_run_action_once() -> None:
    _insert_pending("tok-yaris")
    calls: list[str] = []

    def slow_action(action_type: str, payload: dict[str, Any]) -> str:
        calls.append(payload["ip"])
        time.sleep(0.05)
        return ""

    results: list[dict[str, Any]] = []
    with patch.object(Mgr, "_run_action", side_effect=slow_action):
        _run_parallel(lambda _: results.append(Mgr.approve_action("tok-yaris")), [0, 1, 2])
    assert calls == ["203.0.113.7"]
    assert sum(r["success"] for r in results) == 1
    assert _status("tok-yaris") == "approved"


def test_failed_action_returns_to_pending() -> None:
    _insert_pending("tok-hata")
    with patch.object(Mgr, "_run_action", return_value="iptables hatası: x"):
        assert Mgr.approve_action("tok-hata") == {"success": False, "error": "iptables hatası: x"}
    assert _status("tok-hata") == "pending"


def test_reject_after_approve_fails() -> None:
    _insert_pending("tok-sira")
    with patch.object(Mgr, "_run_action", return_value=""):
        assert Mgr.approve_action("tok-sira")["success"] is True
    assert Mgr.reject_action("tok-sira")["success"] is False
    assert _status("tok-sira") == "approved"


def test_apt_calls_serialized() -> None:
    active = [0]
    peak = [0]
    lock = threading.Lock()

    def fake_run(*_a: Any, **_k: Any) -> MagicMock:
        with lock:
            active[0] += 1
            peak[0] = max(peak[0], active[0])
        time.sleep(0.03)
        with lock:
            active[0] -= 1
        return MagicMock(returncode=0, stdout="ok", stderr="")

    with patch.object(cve_analyzer.subprocess, "run", side_effect=fake_run):
        _run_parallel(lambda p: cve_analyzer._apt_upgrade([p], 5, 5), ["a", "b", "c"])
    assert peak[0] == 1
