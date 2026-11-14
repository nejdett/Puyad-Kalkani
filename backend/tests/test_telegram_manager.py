from __future__ import annotations

import logging
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

import database
import telegram_manager

Mgr = telegram_manager.PuyadTelegramManager


def _insert(token: str, age_sql: str) -> None:
    with database.get_connection() as conn:
        conn.execute(
            "INSERT INTO pending_actions (token, action_type, target_payload, status, created_at)"
            " VALUES (?, 'note', '{}', 'pending', datetime('now', 'localtime', ?))",
            (token, age_sql),
        )


def test_fresh_token_approved() -> None:
    _insert("tok-fresh", "-10 minutes")
    assert Mgr.approve_action("tok-fresh")["success"] is True


def test_expired_token_rejected() -> None:
    _insert("tok-old", "-2 hours")
    assert Mgr.approve_action("tok-old")["success"] is False


def _poll_once(chat_id: int, from_id: int | None, allowed_user: str) -> MagicMock:
    callback: dict[str, Any] = {"id": "c", "data": "approve:tok-x", "message": {"message_id": 5, "chat": {"id": chat_id}}}
    if from_id is not None:
        callback["from"] = {"id": from_id}
    resp = MagicMock(status_code=200)
    resp.json.return_value = {"result": [{"update_id": 1, "callback_query": callback}]}

    def fake_get(*_a: Any, **_k: Any) -> MagicMock:
        telegram_manager._polling_active = False
        return resp

    with patch.object(Mgr, "_get_credentials", return_value=("bot", "123")), \
         patch.object(Mgr, "_is_enabled", return_value=True), \
         patch.object(telegram_manager.config, "load_config", return_value={"TELEGRAM_ALLOWED_USER_ID": allowed_user}), \
         patch.object(telegram_manager.httpx, "get", side_effect=fake_get), \
         patch.object(telegram_manager.httpx, "post"), \
         patch.object(Mgr, "approve_action") as approve:
        Mgr.poll_telegram_callbacks()
    return approve


def test_callback_from_other_chat_ignored() -> None:
    _poll_once(999, 42, "42").assert_not_called()


def test_callback_from_allowed_chat_and_user_accepted() -> None:
    _poll_once(123, 42, "42").assert_called_once_with("tok-x", msg_id=5, chat_id=123)


def test_callback_from_other_user_in_allowed_chat_ignored(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="telegram_manager"):
        _poll_once(123, 77, "42").assert_not_called()
    assert any("77" in r.getMessage() for r in caplog.records)


def test_callback_without_from_ignored_when_user_configured() -> None:
    _poll_once(123, None, "42").assert_not_called()


def test_callback_accepted_with_warning_when_user_not_configured(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="telegram_manager"):
        _poll_once(123, 77, "").assert_called_once()
    assert any("TELEGRAM_ALLOWED_USER_ID" in r.getMessage() for r in caplog.records)


def test_httpx_logger_pinned_to_warning() -> None:
    import logging

    assert logging.getLogger("httpx").level == logging.WARNING


def test_bot_token_not_in_logs_after_request(caplog: pytest.LogCaptureFixture) -> None:
    import httpx

    bot_token = "123456789:AAFgizli-bot-tokeni-loga-dusmemeli"
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(200, json={"ok": True})

    def fake_post(url: str, **kwargs: Any) -> httpx.Response:
        with httpx.Client(transport=httpx.MockTransport(handler)) as client:
            return client.post(url, **kwargs)

    with patch.object(Mgr, "_get_credentials", return_value=(bot_token, "123")), \
         patch.object(telegram_manager.httpx, "post", side_effect=fake_post), \
         caplog.at_level(logging.DEBUG):
        assert Mgr.send_simple_message("deneme")["success"] is True
    assert seen and bot_token in seen[0]
    assert bot_token not in caplog.text
