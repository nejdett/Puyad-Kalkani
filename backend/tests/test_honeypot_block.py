from __future__ import annotations

import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
import backup_manager
import config
import database
import firewall
import honeypot
import telegram_manager
from tests.test_firewall import FakeIptables

Mgr = telegram_manager.PuyadTelegramManager


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch) -> Iterator[dict[str, Any]]:
    fake = FakeIptables()
    monkeypatch.setattr(firewall.subprocess, "run", fake)
    monkeypatch.setattr(firewall, "_own_cache", (0.0, set()))
    monkeypatch.setattr(honeypot, "_should_run_forensic", lambda ip, now: False)
    monkeypatch.setattr(honeypot, "_log_hit", lambda *a, **k: None)
    honeypot._failed_attempts.clear()
    with database.get_connection() as conn:
        conn.execute("DELETE FROM ip_blocks")
    with patch.object(Mgr, "send_approval_notification") as approval, \
            patch.object(Mgr, "send_simple_message") as info:
        yield {"fw": fake, "approval": approval, "info": info}


def _hit(ip: str, n: int = 1) -> None:
    for _ in range(n):
        sock = MagicMock()
        sock.recv.return_value = b""
        honeypot._handle_connection(sock, (ip, 40000), 2222, "ssh")


def _autoblock(on: bool, count: int = 5, minutes: int = 15) -> None:
    config.update_config({
        "HONEYPOT_AUTOBLOCK_ENABLED": on,
        "HONEYPOT_AUTOBLOCK_COUNT": count,
        "HONEYPOT_AUTOBLOCK_MINUTES": minutes,
    })


def test_kapaliyken_onay_istenir(env: dict[str, Any]) -> None:
    _hit("203.0.113.70", 4)
    env["approval"].assert_not_called()
    _hit("203.0.113.70")
    assert env["approval"].call_count == 1
    assert env["fw"].blocked() == []
    env["info"].assert_not_called()


def test_acikken_otomatik_engel(env: dict[str, Any]) -> None:
    _autoblock(True, count=3)
    _hit("203.0.113.71", 2)
    assert env["fw"].blocked() == []
    _hit("203.0.113.71")
    assert env["fw"].blocked() == ["203.0.113.71"]
    blocks = firewall.list_active()
    assert blocks[0]["source"] == "auto"
    env["approval"].assert_not_called()
    assert env["info"].call_count == 1
    assert "203.0.113.71" in env["info"].call_args.args[0]


def test_otomatik_engel_beyaz_liste(env: dict[str, Any]) -> None:
    _autoblock(True, count=2)
    config.update_config({"HONEYPOT_WHITELIST": "203.0.113.0/24"})
    _hit("203.0.113.72", 3)
    assert env["fw"].blocked() == []
    env["approval"].assert_not_called()
    env["info"].assert_not_called()


def test_kapaliyken_korunan_ip_bildirilmez(env: dict[str, Any]) -> None:
    firewall.record_login("203.0.113.73")
    _hit("203.0.113.73", 5)
    env["approval"].assert_not_called()


def test_kilit_mesgulse_engel_yok(env: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    _autoblock(True, count=2)
    busy = MagicMock()
    busy.acquire.return_value = False
    monkeypatch.setattr(backup_manager, "SYSTEM_CHANGE_LOCK", busy)
    _hit("203.0.113.74", 2)
    assert env["fw"].blocked() == []
    env["info"].assert_not_called()


def test_esik_forensic_beklemesinden_bagimsiz(env: dict[str, Any]) -> None:
    _hit("203.0.113.75", 5)
    assert env["approval"].call_count == 1


def test_ayar_sinirlari() -> None:
    from fastapi.testclient import TestClient
    import auth
    import main
    from datetime import datetime
    auth._save_credentials({"username": "admin", "password_hash": auth._hash_password("parola-123"), "created_at": datetime.now().isoformat()})
    h = {"Authorization": f"Bearer {auth.create_token('admin')}"}
    c = TestClient(main.app)
    assert c.patch("/api/config", json={"HONEYPOT_AUTOBLOCK_COUNT": 1}, headers=h).status_code == 422
    assert c.patch("/api/config", json={"HONEYPOT_BLOCK_HOURS": 0}, headers=h).status_code == 422
    assert c.patch("/api/config", json={"HONEYPOT_AUTOBLOCK_ENABLED": True, "HONEYPOT_AUTOBLOCK_COUNT": 10}, headers=h).status_code == 200
    cfg = config.load_config()
    assert cfg["HONEYPOT_AUTOBLOCK_ENABLED"] is True
    assert cfg["HONEYPOT_AUTOBLOCK_COUNT"] == 10


def test_varsayilan_kapali() -> None:
    assert config.DEFAULTS["HONEYPOT_AUTOBLOCK_ENABLED"] is False
    assert config.load_config()["HONEYPOT_AUTOBLOCK_ENABLED"] is False


@pytest.fixture
def forensic_state(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(honeypot, "_last_forensic_by_ip", {})
    monkeypatch.setattr(honeypot, "_forensic_runs", [])


def test_forensic_ip_beklemesi(forensic_state: None) -> None:
    from datetime import datetime, timedelta
    t = datetime(2026, 11, 14, 12, 0)
    assert honeypot._should_run_forensic("203.0.113.80", t) is True
    assert honeypot._should_run_forensic("203.0.113.80", t + timedelta(minutes=9)) is False
    assert honeypot._should_run_forensic("203.0.113.80", t + timedelta(minutes=11)) is True


def test_forensic_saatlik_sinir(forensic_state: None) -> None:
    from datetime import datetime, timedelta
    t = datetime(2026, 11, 14, 12, 0)
    got = [honeypot._should_run_forensic(f"198.51.100.{i}", t + timedelta(minutes=i)) for i in range(10)]
    assert got == [True] * 6 + [False] * 4
    assert honeypot._should_run_forensic("198.51.100.50", t + timedelta(minutes=61)) is True


def test_sinirda_sadece_kayit(forensic_state: None, monkeypatch: pytest.MonkeyPatch) -> None:
    logged: list[str] = []
    monkeypatch.setattr(honeypot, "_log_hit", lambda port, service, ip, *a: logged.append(ip))
    monkeypatch.setattr(honeypot, "_FORENSIC_MAX_PER_HOUR", 2)
    honeypot._failed_attempts.clear()
    with patch.object(honeypot.forensic_manager.PuyadForensicManager, "collect_evidence") as collect, \
            patch.object(honeypot.threading, "Thread") as th:
        th.side_effect = lambda target, args, daemon: MagicMock(start=lambda: target(*args))
        for i in range(4):
            sock = MagicMock()
            sock.recv.return_value = b""
            honeypot._handle_connection(sock, (f"198.51.100.{60 + i}", 40000), 2222, "ssh")
    assert len(logged) == 4
    assert collect.call_count == 2
