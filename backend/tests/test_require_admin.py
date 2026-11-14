from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parent.parent))
import auth
import main


def _set_user(name: str) -> None:
    creds = auth._load_credentials()
    creds["username"] = name
    auth._save_credentials(creds)


def test_registered_username_is_admin() -> None:
    _set_user("yonetici")
    assert main._require_admin("yonetici") == "yonetici"
    with pytest.raises(HTTPException) as exc:
        main._require_admin("admin")
    assert exc.value.status_code == 403


def test_admin_endpoint_with_renamed_user() -> None:
    _set_user("yonetici")
    client = TestClient(main.app, client=("192.168.99.93", 50000))
    ok = {"Authorization": f"Bearer {auth.create_token('yonetici')}"}
    stale = {"Authorization": f"Bearer {auth.create_token('admin')}"}
    assert client.delete("/api/snapshots/yok_boyle_bir_snapshot", headers=ok).status_code != 403
    assert client.delete("/api/snapshots/yok_boyle_bir_snapshot", headers=stale).status_code == 401
