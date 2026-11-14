from __future__ import annotations

import sys
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parent.parent))
import auth
import compat
import database
import jobs
import main


@pytest.fixture(autouse=True)
def clean_jobs() -> Iterator[None]:
    with database.get_connection() as conn:
        conn.execute("DELETE FROM scan_jobs")
    with patch.object(compat, "IS_LINUX", True):
        yield


def _headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {auth.create_token('admin')}"}


def _wait(job_id: int) -> dict[str, Any]:
    for _ in range(200):
        job = jobs.get(job_id)
        assert job is not None
        if job["status"] in ("done", "error"):
            return job
        time.sleep(0.02)
    raise AssertionError("iş bitmedi")


def test_ikinci_istek_ayni_is() -> None:
    gate = threading.Event()

    def slow(server_id: int) -> dict[str, object]:
        gate.wait(5)
        return {"summary": {"score": 80}, "results": []}

    c = TestClient(main.app)
    with patch.object(main, "_dispatch_scan", slow):
        first = c.post("/api/jobs", json={"kind": "scan"}, headers=_headers()).json()
        second = c.post("/api/jobs", json={"kind": "scan"}, headers=_headers()).json()
        assert first["started"] is True
        assert second["started"] is False
        assert second["job"]["id"] == first["job"]["id"]
        cur = c.get("/api/jobs/current", params={"kind": "scan"}, headers=_headers()).json()
        assert cur["job"]["status"] in ("pending", "running")
        gate.set()
        done = _wait(first["job"]["id"])
        assert done["status"] == "done"
        resp = c.get(f"/api/jobs/{first['job']['id']}", headers=_headers()).json()
        assert resp["job"]["result"]["summary"]["score"] == 80
        third = c.post("/api/jobs", json={"kind": "scan"}, headers=_headers()).json()
        assert third["started"] is True
        assert third["job"]["id"] != first["job"]["id"]
        _wait(third["job"]["id"])


def test_cve_taramayi_beklemiyor() -> None:
    gate = threading.Event()

    def slow(server_id: int) -> dict[str, object]:
        gate.wait(5)
        return {}

    cve = {"success": True, "summary": {"total": 0}, "results": []}
    c = TestClient(main.app)
    with patch.object(main, "_dispatch_scan", slow), \
            patch.object(main.cve_analyzer, "run_cve_scan", return_value=cve):
        scan = c.post("/api/jobs", json={"kind": "scan"}, headers=_headers()).json()
        res = c.post("/api/jobs", json={"kind": "cve"}, headers=_headers()).json()
        assert res["started"] is True
        assert _wait(res["job"]["id"])["result"]["success"] is True
        gate.set()
        _wait(scan["job"]["id"])


def test_hata_mesaji_sabit() -> None:
    def boom(server_id: int) -> dict[str, object]:
        raise RuntimeError("/etc/shadow okunamadı")

    with patch.object(main, "_dispatch_scan", boom):
        r = TestClient(main.app).post("/api/jobs", json={"kind": "scan"}, headers=_headers()).json()
        job = _wait(r["job"]["id"])
    assert job["status"] == "error"
    assert job["error"] == "Tarama beklenmeyen bir hatayla durdu."
    assert "shadow" not in str(job)


def test_http_hatasi_mesaji_kalir() -> None:
    def bad(server_id: int) -> dict[str, object]:
        raise HTTPException(status_code=502, detail="Uzak tarama başarısız")

    with patch.object(main, "_dispatch_scan", bad):
        r = TestClient(main.app).post("/api/jobs", json={"kind": "scan"}, headers=_headers()).json()
        job = _wait(r["job"]["id"])
    assert job["error"] == "Uzak tarama başarısız"


def test_cve_basarisiz_hata() -> None:
    fail = {"success": False, "message": "Paket listesi alınamadı."}
    with patch.object(main.cve_analyzer, "run_cve_scan", return_value=fail):
        r = TestClient(main.app).post("/api/jobs", json={"kind": "cve"}, headers=_headers()).json()
        job = _wait(r["job"]["id"])
    assert job["status"] == "error"
    assert job["error"] == "Paket listesi alınamadı."


def test_cve_desteklenmiyor_hata_degil() -> None:
    res = {"success": False, "supported": False, "message": main.cve_analyzer.UNSUPPORTED_MESSAGE}
    with patch.object(main.cve_analyzer, "run_cve_scan", return_value=res):
        r = TestClient(main.app).post("/api/jobs", json={"kind": "cve"}, headers=_headers()).json()
        job = _wait(r["job"]["id"])
    assert job["status"] == "done"
    assert job["result"]["supported"] is False
    assert job["error"] is None


def test_yarim_is_hata_olur() -> None:
    with database.get_connection() as conn:
        conn.execute("INSERT INTO scan_jobs (kind, server_id, status) VALUES ('scan', 1, 'running')")
        conn.execute("INSERT INTO scan_jobs (kind, server_id, status) VALUES ('cve', 1, 'pending')")
        conn.execute("INSERT INTO scan_jobs (kind, server_id, status) VALUES ('scan', 1, 'done')")
    assert jobs.fail_unfinished() == 2
    with database.get_connection() as conn:
        rows = [r["status"] for r in conn.execute("SELECT status FROM scan_jobs ORDER BY id")]
    assert rows == ["error", "error", "done"]
    assert jobs.fail_unfinished() == 0


def test_yetkisiz_istek() -> None:
    c = TestClient(main.app)
    assert c.post("/api/jobs", json={"kind": "scan"}).status_code == 401
    assert c.get("/api/jobs/current").status_code == 401
    assert c.get("/api/jobs/1").status_code == 401


def test_gecersiz_istekler() -> None:
    c = TestClient(main.app)
    assert c.post("/api/jobs", json={"kind": "rm"}, headers=_headers()).status_code == 422
    assert c.post("/api/jobs", json={"kind": "cve", "server_id": 2}, headers=_headers()).status_code == 400
    assert c.post("/api/jobs", json={"kind": "scan", "server_id": 99999}, headers=_headers()).status_code == 404
    assert c.get("/api/jobs/12345", headers=_headers()).status_code == 404
    assert c.get("/api/jobs/current", params={"kind": "x"}, headers=_headers()).status_code == 422
    assert c.get("/api/jobs/current", params={"kind": "cve"}, headers=_headers()).json() == {"job": None}
    with database.get_connection() as conn:
        assert conn.execute("SELECT COUNT(*) FROM scan_jobs").fetchone()[0] == 0


def test_eski_isler_temizleniyor() -> None:
    with database.get_connection() as conn:
        conn.executemany(
            "INSERT INTO scan_jobs (kind, server_id, status) VALUES ('scan', 1, 'done')",
            [()] * (jobs.KEEP_JOBS + 5),
        )
    with patch.object(main, "_dispatch_scan", lambda sid: {}):
        r = TestClient(main.app).post("/api/jobs", json={"kind": "scan"}, headers=_headers()).json()
        _wait(r["job"]["id"])
    with database.get_connection() as conn:
        assert conn.execute("SELECT COUNT(*) FROM scan_jobs").fetchone()[0] == jobs.KEEP_JOBS + 1
