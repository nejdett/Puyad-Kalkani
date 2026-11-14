from __future__ import annotations

import logging
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi import HTTPException

sys.path.insert(0, str(Path(__file__).parent.parent))
import auth
import telegram_manager

PASSWORD = "dogru-parola-123"


@pytest.fixture(autouse=True)
def clock(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    now = [1000.0]
    monkeypatch.setattr(auth, "_now", lambda: now[0])
    monkeypatch.setattr(auth.threading, "Timer", _FakeTimer)
    auth._save_credentials({"username": "admin", "password_hash": auth._hash_password(PASSWORD)})
    return now


class _FakeTimer:

    def __init__(self, interval: float, fn: object) -> None:
        self.interval = interval
        self.daemon = False

    def start(self) -> None:
        pass

    def cancel(self) -> None:
        pass


def _fail(n: int) -> None:
    for _ in range(n):
        with pytest.raises(HTTPException) as exc:
            auth.login("admin", "yanlis-parola")
        assert exc.value.status_code == 401


def _status(password: str = PASSWORD) -> int:
    try:
        auth.login("admin", password)
        return 200
    except HTTPException as e:
        return e.status_code


def test_ten_failures_lock_even_correct_password(clock: list[float]) -> None:
    _fail(10)
    assert _status() == 429
    clock[0] += auth.LOCKOUT_SECONDS - 1
    assert _status() == 429


def test_lock_expires_after_fifteen_minutes(clock: list[float]) -> None:
    _fail(10)
    clock[0] += auth.LOCKOUT_SECONDS
    assert _status() == 200


def test_attempts_during_lock_do_not_extend_it(clock: list[float]) -> None:
    _fail(10)
    for _ in range(20):
        clock[0] += 30
        assert _status("yanlis-parola") == 429
    clock[0] = 1000.0 + auth.LOCKOUT_SECONDS
    assert _status() == 200


def test_failures_outside_window_not_counted(clock: list[float]) -> None:
    _fail(9)
    clock[0] += auth.LOCKOUT_WINDOW_SECONDS
    _fail(9)
    assert _status() == 200


def test_success_resets_counter(clock: list[float]) -> None:
    _fail(9)
    assert _status() == 200
    _fail(9)
    assert _status() == 200


def test_unknown_username_counts(clock: list[float]) -> None:
    for _ in range(10):
        with pytest.raises(HTTPException):
            auth.login("baskasi", "x")
    assert _status() == 429


def test_unlock_logs_and_notifies(clock: list[float], caplog: pytest.LogCaptureFixture) -> None:
    _fail(10)
    with patch.object(telegram_manager.PuyadTelegramManager, "_is_enabled", return_value=True), \
         patch.object(telegram_manager.PuyadTelegramManager, "send_simple_message") as send, \
         caplog.at_level(logging.WARNING, logger="auth"):
        auth._on_lockout_expired()
        send.assert_not_called()
        clock[0] += auth.LOCKOUT_SECONDS
        auth._on_lockout_expired()
    send.assert_called_once()
    assert "kilidi kalktı" in send.call_args.args[0]
    assert any("kilidi kalktı" in r.getMessage() for r in caplog.records)
    assert _status() == 200


def test_unlock_survives_telegram_error(clock: list[float]) -> None:
    _fail(10)
    clock[0] += auth.LOCKOUT_SECONDS
    with patch.object(telegram_manager.PuyadTelegramManager, "_is_enabled", return_value=True), \
         patch.object(telegram_manager.PuyadTelegramManager, "send_simple_message", side_effect=RuntimeError("ağ")):
        auth._on_lockout_expired()
    assert _status() == 200


def test_lock_schedules_unlock_timer(clock: list[float]) -> None:
    _fail(10)
    assert auth._unlock_timer is not None
    assert auth._unlock_timer.interval == auth.LOCKOUT_SECONDS  # type: ignore[attr-defined]
