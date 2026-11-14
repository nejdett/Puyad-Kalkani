from __future__ import annotations

import hashlib
import hmac
import json
import logging
import threading
import time
from typing import Any, cast

import auth
import backup_manager
import config
import database
import httpx

APPROVAL_TTL_HOURS: int = 1

# httpx INFO'da tam URL'yi logluyor — Telegram bot token'ı path'te
logging.getLogger("httpx").setLevel(logging.WARNING)

logger = logging.getLogger(__name__)

_polling_active: bool = False
_polling_thread: threading.Thread | None = None


class PuyadTelegramManager:

    @staticmethod
    def _get_credentials() -> tuple[str, str]:
        cfg: dict[str, Any] = config.load_config()
        return cfg.get("TELEGRAM_BOT_TOKEN", ""), cfg.get("TELEGRAM_CHAT_ID", "")

    @staticmethod
    def _is_enabled() -> bool:
        cfg: dict[str, Any] = config.load_config()
        return bool(cfg.get("TELEGRAM_ENABLED")) and bool(cfg.get("TELEGRAM_BOT_TOKEN"))

    @staticmethod
    def _generate_token(action_type: str, payload: dict[str, Any]) -> str:
        raw: str = f"{action_type}:{json.dumps(payload, sort_keys=True)}:{time.time()}"
        secret_bytes = auth._get_secret().encode("utf-8")
        return hmac.new(secret_bytes, raw.encode("utf-8"), hashlib.sha256).hexdigest()[:32]

    @staticmethod
    def _send_message(token: str, payload: dict[str, Any]) -> httpx.Response:
        return httpx.post(f"https://api.telegram.org/bot{token}/sendMessage", json=payload, timeout=10)

    @staticmethod
    def send_approval_notification(title: str, message: str, action_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        token, chat_id = PuyadTelegramManager._get_credentials()
        if not token or not chat_id:
            return {"success": False, "error": "Telegram yapılandırılmamış."}

        approval_token: str = PuyadTelegramManager._generate_token(action_type, payload)

        try:
            with database.get_connection() as conn:
                conn.execute(
                    "INSERT INTO pending_actions (token, action_type, target_payload, status) VALUES (?, ?, ?, 'pending')",
                    (approval_token, action_type, json.dumps(payload))
                )
        except Exception:
            logger.exception("Onay isteği kaydedilemedi: %s", action_type)
            return {"success": False, "error": "Onay isteği kaydedilemedi."}

        keyboard: dict[str, list[list[dict[str, str]]]] = {
            "inline_keyboard": [
                [
                    {"text": "Onayla ve IP'yi Engelle", "callback_data": f"approve:{approval_token}"},
                ],
                [
                    {"text": "İptal Et", "callback_data": f"reject:{approval_token}"},
                ],
            ]
        }

        html_text: str = (
            f"<b>{title}</b>\n\n"
            f"{message}\n\n"
            f"<code>Token: {approval_token[:8]}...</code>\n"
            f"<i>Butonlara basarak işlemi onaylayın veya iptal edin.</i>"
        )

        resp = PuyadTelegramManager._send_message(token, {
            "chat_id": chat_id,
            "text": html_text,
            "parse_mode": "HTML",
            "reply_markup": keyboard,
        })
        if resp.status_code == 200:
            return {"success": True, "token": approval_token}
        return {"success": False, "error": f"Telegram API hata: {resp.text}"}

    @staticmethod
    def send_simple_message(text: str) -> dict[str, Any]:
        token, chat_id = PuyadTelegramManager._get_credentials()
        if not token or not chat_id:
            return {"success": False, "error": "Telegram yapılandırılmamış."}

        resp = PuyadTelegramManager._send_message(token, {"chat_id": chat_id, "text": text, "parse_mode": "HTML"})
        if resp.status_code == 200:
            return {"success": True}
        return {"success": False, "error": f"Telegram API hata: {resp.text}"}

    @staticmethod
    def approve_action(approval_token: str, msg_id: int | None = None, chat_id: int | None = None) -> dict[str, Any]:
        # Panel ve Telegram aynı anda onaylarsa ikisi de pending görüp iki iptables kuralı ekliyordu
        with database.get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM pending_actions WHERE token = ? AND status = 'pending'"
                " AND created_at >= datetime('now', 'localtime', ?)",
                (approval_token, f"-{APPROVAL_TTL_HOURS} hours")
            ).fetchone()
            claimed = row is not None and conn.execute(
                "UPDATE pending_actions SET status = 'processing' WHERE token = ? AND status = 'pending'",
                (approval_token,)
            ).rowcount == 1
        if not row or not claimed:
            return {"success": False, "error": "Geçersiz, süresi dolmuş veya zaten işlenmiş token."}

        error = PuyadTelegramManager._run_action(row["action_type"], json.loads(row["target_payload"]))
        with database.get_connection() as conn:
            conn.execute(
                "UPDATE pending_actions SET status = ? WHERE token = ? AND status = 'processing'",
                ("pending" if error else "approved", approval_token)
            )
        if error:
            return {"success": False, "error": error}

        if msg_id and chat_id:
            PuyadTelegramManager._update_callback_message(msg_id, chat_id, "İşlem Onaylandı ve IP Engellendi.")

        return {"success": True, "message": "İşlem onaylandı."}

    @staticmethod
    def _run_action(action_type: str, payload: dict[str, Any]) -> str:
        if action_type != "block_ip" or "ip" not in payload:
            return ""
        import firewall
        res = firewall.block(str(payload.get("ip", "")), "Telegram onayı", "telegram")
        return "" if res["success"] else str(res["message"])

    @staticmethod
    def reject_action(approval_token: str, msg_id: int | None = None, chat_id: int | None = None) -> dict[str, Any]:
        with database.get_connection() as conn:
            rejected = conn.execute(
                "UPDATE pending_actions SET status = 'rejected' WHERE token = ? AND status = 'pending'",
                (approval_token,)
            ).rowcount
        if rejected != 1:
            return {"success": False, "error": "Geçersiz veya zaten işlenmiş token."}

        if msg_id and chat_id:
            PuyadTelegramManager._update_callback_message(msg_id, chat_id, "İşlem İptal Edildi.")

        return {"success": True, "message": "İşlem iptal edildi."}

    @staticmethod
    def _update_callback_message(msg_id: int, chat_id: int, new_text: str) -> None:
        token, _ = PuyadTelegramManager._get_credentials()
        if not token or not msg_id or not chat_id:
            return

        try:
            httpx.post(
                f"https://api.telegram.org/bot{token}/editMessageText",
                json={"chat_id": chat_id, "message_id": msg_id, "text": new_text},
                timeout=5,
            )
        except Exception:
            pass

    @staticmethod
    def get_pending_actions() -> list[dict[str, Any]]:
        with database.get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM pending_actions WHERE status = 'pending' ORDER BY created_at DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    @staticmethod
    def poll_telegram_callbacks() -> None:
        global _polling_active
        offset: int = 0
        _polling_active = True

        while _polling_active:
            try:
                token, allowed_chat = PuyadTelegramManager._get_credentials()
                if not token or not PuyadTelegramManager._is_enabled():
                    time.sleep(5)
                    continue

                url: str = f"https://api.telegram.org/bot{token}/getUpdates"
                resp: httpx.Response = httpx.get(url, params={"offset": offset, "timeout": 30}, timeout=35)

                if resp.status_code != 200:
                    time.sleep(5)
                    continue

                data: dict[str, Any] = resp.json()
                for update in data.get("result", []):
                    offset = update["update_id"] + 1
                    callback: dict[str, Any] | None = update.get("callback_query")
                    if not callback:
                        continue

                    cb_id: str = callback.get("id", "")
                    cb_data: str = callback.get("data", "")
                    msg: dict[str, Any] = cast(dict[str, Any], callback.get("message", {}))
                    msg_id: int | None = cast(int | None, msg.get("message_id"))
                    _chat: dict[str, Any] = cast(dict[str, Any], msg.get("chat", {}))
                    chat_id_cb: int | None = _chat.get("id")
                    if str(chat_id_cb) != str(allowed_chat):
                        continue
                    # Chat bir grupsa her üye butona basabilir — basan kişi de kontrol edilmeli
                    allowed_user = str(config.load_config().get("TELEGRAM_ALLOWED_USER_ID", "")).strip()
                    from_id = cast(dict[str, Any], callback.get("from", {})).get("id")
                    if not allowed_user:
                        logger.warning(
                            "TELEGRAM_ALLOWED_USER_ID tanımlı değil, callback gönderen kullanıcı kontrol edilmiyor."
                        )
                    elif str(from_id) != allowed_user:
                        logger.warning("Telegram callback izinsiz kullanıcıdan reddedildi: %s", from_id)
                        continue

                    try:
                        httpx.post(
                            f"https://api.telegram.org/bot{token}/answerCallbackQuery",
                            json={"callback_query_id": cb_id},
                            timeout=5,
                        )
                    except Exception:
                        pass

                    if cb_data.startswith("approve:"):
                        tk: str = cb_data.split("approve:", 1)[1]
                        if not backup_manager.SYSTEM_CHANGE_LOCK.acquire(timeout=30):
                            logger.warning("Telegram onayı atlandı, başka bir sistem değişikliği sürüyor.")
                            continue
                        try:
                            PuyadTelegramManager.approve_action(tk, msg_id=msg_id, chat_id=chat_id_cb)
                        finally:
                            backup_manager.SYSTEM_CHANGE_LOCK.release()
                    elif cb_data.startswith("reject:"):
                        tk = cb_data.split("reject:", 1)[1]
                        PuyadTelegramManager.reject_action(tk, msg_id=msg_id, chat_id=chat_id_cb)

            except Exception:
                time.sleep(5)

    @staticmethod
    def start_polling() -> None:
        global _polling_thread
        if _polling_active and _polling_thread and _polling_thread.is_alive():
            return
        if not PuyadTelegramManager._is_enabled():
            return
        _polling_thread = threading.Thread(
            target=PuyadTelegramManager.poll_telegram_callbacks,
            daemon=True,
        )
        _polling_thread.start()


def stop_polling() -> None:
    global _polling_active
    _polling_active = False
