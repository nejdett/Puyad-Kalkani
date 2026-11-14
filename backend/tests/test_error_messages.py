from __future__ import annotations

import logging
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

sys.path.insert(0, str(Path(__file__).parent.parent))
import agent_client
import auth
from tests.tls_certs import CERT_A, agent_client_context, agent_tls_files

LEAK = "/opt/gizli/yol: Permission denied (errno 13)"


def _client() -> agent_client.PuyadAgentClient:
    with patch.object(agent_client.config, "load_config", return_value={"AGENT_SHARED_SECRET": "a" * 64}):
        return agent_client.PuyadAgentClient("10.0.0.5", 8000, agent_id="a" * 32, cert_pem=CERT_A)


def test_corrupt_credentials_detail_is_generic(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                               caplog: pytest.LogCaptureFixture) -> None:
    creds = tmp_path / "credentials.json"
    creds.write_text("{bozuk json")
    monkeypatch.setattr(auth, "CREDS_FILE", creds)
    with caplog.at_level(logging.ERROR, logger="auth"), pytest.raises(HTTPException) as exc_info:
        auth._load_credentials()
    assert exc_info.value.status_code == 500
    assert "Expecting" not in str(exc_info.value.detail)
    assert "char" not in str(exc_info.value.detail)
    assert any("Expecting" in r.getMessage() for r in caplog.records)


@pytest.mark.parametrize("call", [
    lambda c: c.check_agent_status(),
    lambda c: c.trigger_remote_scan(),
    lambda c: c.trigger_remote_fix("r1"),
])
def test_agent_client_hides_exception_text(call, caplog: pytest.LogCaptureFixture) -> None:
    client = _client()
    with patch.object(agent_client.httpx.Client, "request", side_effect=RuntimeError(LEAK)), \
         caplog.at_level(logging.WARNING, logger="agent_client"):
        res = call(client)
    assert LEAK not in res["error"]
    assert res["error"]
    assert any(LEAK in r.getMessage() for r in caplog.records)


ROOT = Path(__file__).resolve().parent.parent.parent


def _assert_generic(text: str, expected: str, caplog: pytest.LogCaptureFixture) -> None:
    assert text == expected
    assert LEAK not in text
    assert LEAK in caplog.text


def test_snapshot_create_error_generic(caplog: pytest.LogCaptureFixture) -> None:
    import backup_manager
    import compat

    with patch.object(compat, "IS_LINUX", True), \
         patch.object(backup_manager.tarfile, "open", side_effect=OSError(LEAK)), \
         caplog.at_level(logging.ERROR, logger="backup_manager"):
        res = backup_manager.create_snapshot("deneme")
    _assert_generic(res["message"], "Snapshot oluşturulamadı.", caplog)


def test_snapshot_rollback_error_generic(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    import backup_manager
    import compat
    import database

    snap = tmp_path / "eski.tar.gz"
    snap.write_bytes(b"x")
    backup_manager.SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
    with database.get_connection() as conn:
        conn.execute("DELETE FROM snapshots WHERE id = 'sizinti-testi'")
        conn.execute("INSERT INTO snapshots (id, label, path) VALUES ('sizinti-testi', 't', ?)", (str(snap),))
    try:
        with patch.object(compat, "IS_LINUX", True), \
             patch.object(backup_manager, "create_snapshot", return_value={"success": True, "snapshot_id": "o"}), \
             patch.object(backup_manager.tarfile, "open", side_effect=OSError(LEAK)), \
             caplog.at_level(logging.ERROR, logger="backup_manager"):
            res = backup_manager.rollback_snapshot("sizinti-testi")
    finally:
        with database.get_connection() as conn:
            conn.execute("DELETE FROM snapshots WHERE id = 'sizinti-testi'")
    _assert_generic(res["message"], "Snapshot geri yüklenemedi.", caplog)


@pytest.mark.parametrize("fn,args,expected", [
    ("fix_cve_package", ("openssl",), "Paket güncelleme komutu çalıştırılamadı."),
    ("fix_cve_batch", (["openssl", "curl"],), "Toplu paket güncellemesi başlatılamadı."),
])
def test_cve_fix_error_generic(fn: str, args: tuple[object, ...], expected: str,
                               caplog: pytest.LogCaptureFixture) -> None:
    import compat
    import cve_analyzer

    with patch.object(compat, "IS_LINUX", True), \
         patch.object(cve_analyzer, "_installed_version", return_value="1.0"), \
         patch.object(cve_analyzer, "_fix_gate", return_value=(["openssl"], None)), \
         patch.object(cve_analyzer, "_apt_simulate", return_value=None), \
         patch.object(cve_analyzer, "_apt_upgrade", side_effect=RuntimeError(LEAK)), \
         caplog.at_level(logging.ERROR, logger="cve_analyzer"):
        res = getattr(cve_analyzer, fn)(*args)
    _assert_generic(res["message"], expected, caplog)


def test_run_command_error_generic(caplog: pytest.LogCaptureFixture) -> None:
    import engine

    with patch.object(engine.subprocess, "run", side_effect=RuntimeError(LEAK)), \
         caplog.at_level(logging.ERROR, logger="engine"):
        res = engine.run_command("true")
    _assert_generic(res["stderr"], "Komut başlatılamadı.", caplog)


def test_parse_error_generic() -> None:
    import engine

    ok, msg = engine.validate_user_command("echo 'kapanmamis")
    assert (ok, msg) == (False, "Komut ayrıştırılamadı, kapanmamış tırnak olabilir.")
    ok, msg = engine.validate_user_command("echo a && echo 'kapanmamis")
    assert ok is False
    assert "No closing quotation" not in msg


@pytest.mark.parametrize("exc,expected", [
    (OSError(LEAK), "Log dosyası okunamadı."),
    (RuntimeError(LEAK), "Log satırları işlenirken beklenmeyen bir hata oluştu."),
])
def test_log_tail_error_generic(exc: Exception, expected: str, caplog: pytest.LogCaptureFixture) -> None:
    import log_monitor

    with patch.object(log_monitor, "_read_last_lines", side_effect=exc), \
         caplog.at_level(logging.ERROR, logger="log_monitor"):
        res = log_monitor._file_tail("/var/log/syslog", 10)
    _assert_generic(res[0]["line"], expected, caplog)


def test_journald_tail_error_generic(caplog: pytest.LogCaptureFixture) -> None:
    import log_monitor

    with patch.object(log_monitor, "_journalctl_last", side_effect=RuntimeError(LEAK)), \
         caplog.at_level(logging.ERROR, logger="log_monitor"):
        res = log_monitor._journald_tail(10)
    _assert_generic(res[0]["line"], "journald kayıtları alınamadı.", caplog)


def test_telegram_db_error_generic(caplog: pytest.LogCaptureFixture) -> None:
    import telegram_manager

    mgr = telegram_manager.PuyadTelegramManager
    with patch.object(mgr, "_get_credentials", return_value=("bot", "1")), \
         patch.object(mgr, "_is_enabled", return_value=True), \
         patch.object(telegram_manager.database, "get_connection", side_effect=RuntimeError(LEAK)), \
         caplog.at_level(logging.ERROR, logger="telegram_manager"):
        res = mgr.send_approval_notification("t", "m", "block_ip", {"ip": "203.0.113.9"})
    _assert_generic(res["error"], "Onay isteği kaydedilemedi.", caplog)


@pytest.mark.parametrize("run_kwargs,expected", [
    ({"return_value": MagicMock(returncode=1, stderr=LEAK)}, "Güvenlik duvarı kuralı eklenemedi."),
    ({"side_effect": RuntimeError(LEAK)}, "IP engelleme komutu çalıştırılamadı."),
])
def test_iptables_error_generic(run_kwargs: dict[str, object], expected: str,
                                caplog: pytest.LogCaptureFixture) -> None:
    import subprocess

    import telegram_manager

    with patch.object(subprocess, "run", **run_kwargs), \
         caplog.at_level(logging.WARNING, logger="firewall"):
        err = telegram_manager.PuyadTelegramManager._run_action("block_ip", {"ip": "203.0.113.9"})
    _assert_generic(err, expected, caplog)


@pytest.mark.parametrize("target", ["check", "pool"])
def test_collector_error_generic(target: str, caplog: pytest.LogCaptureFixture) -> None:
    sys.path.insert(0, str(ROOT))
    from light_agent import collector

    rule = {"id": "r1", "check_command": "true"}
    with caplog.at_level(logging.ERROR, logger="light_agent.collector"):
        if target == "check":
            with patch.object(collector.subprocess, "run", side_effect=RuntimeError(LEAK)):
                res = collector.check_rule(rule)
            expected = "Kontrol komutu çalıştırılamadı."
        else:
            with patch.object(collector, "check_rule", side_effect=RuntimeError(LEAK)):
                res = collector.audit_rules([rule])["results"][0]
            expected = "Kural denetimi ajanda tamamlanamadı."
    assert LEAK not in str(res)
    assert expected in str(res)
    assert LEAK in caplog.text


def _agent_post(port: int, path: str, body: bytes) -> dict[str, object]:
    import json
    import urllib.error
    import urllib.request

    from light_agent import security

    headers = security.build_headers("c" * 64, "POST", path, body, target="a" * 32)
    req = urllib.request.Request(f"https://127.0.0.1:{port}{path}", data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5, context=agent_client_context()) as resp:
            return dict(json.loads(resp.read()))
    except urllib.error.HTTPError as e:
        return dict(json.loads(e.read()))


def test_agent_endpoints_error_generic(caplog: pytest.LogCaptureFixture) -> None:
    import threading

    sys.path.insert(0, str(ROOT))
    from light_agent import agent as agent_mod

    port = 18996
    server = agent_mod.PuyadAgentServer(
        agent_mod.AgentConfig(
            host="127.0.0.1", port=port, secret="c" * 64, agent_id="a" * 32,
            cert_file=agent_tls_files()[0], key_file=agent_tls_files()[1],
        )
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with caplog.at_level(logging.ERROR, logger="light_agent.agent"):
            with patch.object(agent_mod.subprocess, "run", side_effect=RuntimeError(LEAK)):
                fix = _agent_post(port, "/api/fix/r1", b'{"fix_command": "true"}')
            with patch.object(agent_mod.Path, "write_bytes", side_effect=OSError(LEAK)):
                upd = _agent_post(port, "/api/update/collector.py", b"print(1)")
    finally:
        server.shutdown_cleanly()
        server.server_close()
    assert (fix["message"], fix["output"]) == ("Düzeltme komutu çalıştırılamadı.", "")
    assert upd["message"] == "collector.py güncellemesi diske yazılamadı."
    assert LEAK not in str(fix) + str(upd)
    assert caplog.text.count(LEAK) >= 2
