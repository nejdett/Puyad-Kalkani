from __future__ import annotations

import sys
from collections.abc import Iterator
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parent.parent))
import auth
import backup_manager
import compat
import cve_analyzer
import main
import remediation_engine

CALLS = [
    ("post", "/api/fix/rule_1", {"server_id": 1}),
    ("post", "/api/snapshots", {"label": "x"}),
    ("post", "/api/snapshots/snap_1/rollback", None),
    ("post", "/api/cve/fix", {"package": "openssl"}),
    ("post", "/api/cve/fix-batch", {"packages": ["openssl"]}),
]


@pytest.fixture
def client() -> TestClient:
    return TestClient(main.app, client=("192.168.99.92", 50000))


@pytest.fixture
def headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {auth.create_token(auth._load_credentials()['username'])}"}


@pytest.fixture
def linux() -> Iterator[None]:
    with patch.object(compat, "IS_LINUX", True):
        yield


@pytest.mark.parametrize("method,path,body", CALLS)
def test_busy_lock_returns_409_without_running(
    client: TestClient, headers: dict[str, str], linux: None, method: str, path: str, body: object
) -> None:
    with patch.object(remediation_engine, "fix_with_snapshot") as fix, \
         patch.object(backup_manager, "create_snapshot") as snap, \
         patch.object(backup_manager, "rollback_snapshot") as rb, \
         patch.object(cve_analyzer, "fix_cve_package") as cve, \
         patch.object(cve_analyzer, "fix_cve_batch") as batch:
        assert backup_manager.SYSTEM_CHANGE_LOCK.acquire(blocking=False)
        try:
            resp = getattr(client, method)(path, json=body, headers=headers)
        finally:
            backup_manager.SYSTEM_CHANGE_LOCK.release()
    assert resp.status_code == 409
    for m in (fix, snap, rb, cve, batch):
        m.assert_not_called()


def test_lock_released_after_success_and_error(client: TestClient, headers: dict[str, str], linux: None) -> None:
    with patch.object(backup_manager, "create_snapshot", return_value={"success": True, "snapshot_id": "s"}):
        assert client.post("/api/snapshots", json={"label": "x"}, headers=headers).status_code == 200
    assert not backup_manager.SYSTEM_CHANGE_LOCK.locked()
    with patch.object(backup_manager, "create_snapshot", side_effect=RuntimeError("disk")):
        assert client.post("/api/snapshots", json={"label": "x"}, headers=headers).status_code == 500
    assert not backup_manager.SYSTEM_CHANGE_LOCK.locked()
    with patch.object(cve_analyzer, "fix_cve_package", return_value={"success": False, "message": "yok"}):
        assert client.post("/api/cve/fix", json={"package": "openssl"}, headers=headers).status_code == 400
    assert not backup_manager.SYSTEM_CHANGE_LOCK.locked()


def test_nested_snapshot_inside_fix_not_blocked(client: TestClient, headers: dict[str, str], linux: None) -> None:
    def fake_fix(**_kw: object) -> dict[str, object]:
        assert backup_manager.SYSTEM_CHANGE_LOCK.locked()
        return {"success": True, "message": "ok", "output": "", "snapshot_id": None}

    with patch.object(remediation_engine, "fix_with_snapshot", side_effect=fake_fix):
        assert client.post("/api/fix/rule_1", json={"server_id": 1}, headers=headers).status_code == 200
    assert not backup_manager.SYSTEM_CHANGE_LOCK.locked()
