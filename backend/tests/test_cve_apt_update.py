from __future__ import annotations

import inspect
import sys
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parent.parent))
import auth
import backup_manager
import compat
import cve_analyzer
import main

OK = {"success": True, "message": "Paket listeleri güncellendi, taramayı yeniden çalıştırabilirsiniz.", "apt_lists": {"stale": False}}


def _client() -> TestClient:
    return TestClient(main.app, client=("192.168.99.94", 50000))


def _headers(user: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {auth.create_token(user)}"}


def _admin() -> str:
    return str(auth._load_credentials()["username"])


def test_admin_can_update() -> None:
    with patch.object(compat, "IS_LINUX", True), patch.object(cve_analyzer, "update_apt_lists", return_value=OK) as upd:
        res = _client().post("/api/cve/apt-update", headers=_headers(_admin()))
    assert res.status_code == 200
    assert res.json()["success"] is True
    upd.assert_called_once()


def test_non_admin_rejected() -> None:
    # test_auth auth modülünü yeniden yüklüyor — _require_admin'in tuttuğu fonksiyon nesnesine bağlanmalı
    current_user_dep = inspect.signature(main._require_admin).parameters["current_user"].default.dependency
    main.app.dependency_overrides[current_user_dep] = lambda: "baskasi"
    try:
        with patch.object(compat, "IS_LINUX", True), patch.object(cve_analyzer, "update_apt_lists", return_value=OK) as upd:
            res = _client().post("/api/cve/apt-update", headers=_headers(_admin()))
    finally:
        main.app.dependency_overrides.clear()
    assert res.status_code == 403
    upd.assert_not_called()


def test_without_token_rejected() -> None:
    with patch.object(cve_analyzer, "update_apt_lists", return_value=OK) as upd:
        res = _client().post("/api/cve/apt-update")
    assert res.status_code == 401
    upd.assert_not_called()


def test_locked_returns_409() -> None:
    assert backup_manager.SYSTEM_CHANGE_LOCK.acquire(blocking=False)
    try:
        with patch.object(compat, "IS_LINUX", True), patch.object(cve_analyzer, "update_apt_lists", return_value=OK) as upd:
            res = _client().post("/api/cve/apt-update", headers=_headers(_admin()))
    finally:
        backup_manager.SYSTEM_CHANGE_LOCK.release()
    assert res.status_code == 409
    upd.assert_not_called()


def test_failure_returns_short_message() -> None:
    fail = {"success": False, "message": "Paket listeleri güncellenemedi. Ayrıntı sunucu logunda."}
    with patch.object(compat, "IS_LINUX", True), patch.object(cve_analyzer, "update_apt_lists", return_value=fail):
        res = _client().post("/api/cve/apt-update", headers=_headers(_admin()))
    assert res.status_code == 500
    assert res.json()["detail"] == fail["message"]


def test_lock_released_after_update() -> None:
    with patch.object(compat, "IS_LINUX", True), patch.object(cve_analyzer, "update_apt_lists", return_value=OK):
        _client().post("/api/cve/apt-update", headers=_headers(_admin()))
    assert backup_manager.SYSTEM_CHANGE_LOCK.acquire(blocking=False)
    backup_manager.SYSTEM_CHANGE_LOCK.release()
