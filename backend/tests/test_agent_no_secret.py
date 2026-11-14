from __future__ import annotations

import json
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch
import pytest

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT_DIR))

from light_agent import agent, security
from light_agent.agent import AgentConfig, PuyadAgentServer
from tests.tls_certs import agent_client_context, agent_tls_files

PLACEHOLDER_SECRET = "BURAYA_BACKEND_AGENT_SHARED_SECRET_DEGERI_YAZILMALI"
WEAK_VALUES = [PLACEHOLDER_SECRET, "     ", "a" * 31]
VALID_SECRET = "0123456789abcdef" * 4


def test_verify_request_rejects_when_no_credentials() -> None:
    ok, _ = security.verify_request({}, "POST", "/api/fix/x", body="{}", secret="", token="")
    assert ok is False


class TestAgentWithoutCredentials:

    @classmethod
    def setup_class(cls) -> None:
        cls.port = 18993
        cls.tmpdir = tempfile.TemporaryDirectory()
        cls.dir_patch = patch.object(agent, "_AGENT_DIR", Path(cls.tmpdir.name))
        cls.dir_patch.start()
        cls.server = PuyadAgentServer(
            AgentConfig(host="127.0.0.1", port=cls.port, cert_file=agent_tls_files()[0], key_file=agent_tls_files()[1])
        )
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        time.sleep(0.3)

    @classmethod
    def teardown_class(cls) -> None:
        cls.server.shutdown_cleanly()
        cls.server.server_close()
        cls.dir_patch.stop()
        cls.tmpdir.cleanup()

    def _post(self, path: str, body: str) -> int:
        req = urllib.request.Request(
            f"https://127.0.0.1:{self.port}{path}",
            data=body.encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=5, context=agent_client_context()) as resp:
                return int(resp.status)
        except urllib.error.HTTPError as e:
            return e.code

    def test_fix_command_not_executed(self) -> None:
        marker = Path(self.tmpdir.name) / "pwned"
        status = self._post("/api/fix/x", json.dumps({"fix_command": f"touch {marker}"}))
        assert status == 401
        assert not marker.exists()

    def test_update_rejected(self) -> None:
        status = self._post("/api/update/agent.py", "print('pwned')")
        assert status == 401
        assert not (Path(self.tmpdir.name) / "agent.py").exists()


@pytest.mark.parametrize("action", ["run", "start", "restart"])
def test_cli_refuses_to_start_without_credentials(action: str, monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("PUYAD_AGENT_SECRET", "PUYAD_AGENT_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg_file = Path(tmpdir) / "config.json"
        cfg_file.write_text("{}")
        monkeypatch.setattr(sys, "argv", ["agent.py", action, "--config", str(cfg_file)])
        with patch.object(agent, "run_server") as run, patch.object(agent, "cmd_start") as start, \
                patch.object(agent, "cmd_stop"):
            with pytest.raises(SystemExit) as exc_info:
                agent.main()
            assert exc_info.value.code != 0
            run.assert_not_called()
            start.assert_not_called()


@pytest.mark.parametrize("action", ["stop", "status"])
def test_cli_management_commands_work_without_credentials(action: str, monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("PUYAD_AGENT_SECRET", "PUYAD_AGENT_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg_file = Path(tmpdir) / "config.json"
        cfg_file.write_text("{}")
        monkeypatch.setattr(sys, "argv", ["agent.py", action, "--config", str(cfg_file)])
        with patch.object(agent, f"cmd_{action}") as cmd:
            agent.main()
            cmd.assert_called_once()


@pytest.mark.parametrize("weak", WEAK_VALUES)
def test_verify_request_rejects_weak_secret(weak: str) -> None:
    headers = security.build_headers(weak, "GET", "/api/status")
    ok, reason = security.verify_request(headers, "GET", "/api/status", secret=weak)
    assert ok is False
    assert "token_hex(32)" in reason


@pytest.mark.parametrize("weak", WEAK_VALUES)
def test_verify_request_rejects_weak_token(weak: str) -> None:
    ok, _ = security.verify_request({"Authorization": f"Bearer {weak}"}, "GET", "/api/status", token=weak)
    assert ok is False


def test_verify_request_accepts_valid_secret_and_token() -> None:
    headers = security.build_headers(VALID_SECRET, "GET", "/api/status", target="a" * 32)
    assert security.verify_request(headers, "GET", "/api/status", secret=VALID_SECRET, agent_id="a" * 32) == (True, "")
    bearer = {"Authorization": f"Bearer {VALID_SECRET}"}
    assert security.verify_request(bearer, "GET", "/api/status", token=VALID_SECRET) == (True, "")


def _prepare_cli(monkeypatch: pytest.MonkeyPatch, tmpdir: str, extra: list[str]) -> None:
    for name in ("PUYAD_AGENT_SECRET", "PUYAD_AGENT_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    cfg_file = Path(tmpdir) / "config.json"
    cfg_file.write_text(json.dumps({"cert_file": str(Path(tmpdir) / "a.crt"), "key_file": str(Path(tmpdir) / "a.key")}))
    monkeypatch.setattr(sys, "argv", ["agent.py", "run", "--config", str(cfg_file), *extra])


@pytest.mark.parametrize("weak", WEAK_VALUES)
@pytest.mark.parametrize("flag", ["--secret", "--token"])
def test_cli_refuses_weak_credentials(flag: str, weak: str, monkeypatch: pytest.MonkeyPatch,
                                      capsys: pytest.CaptureFixture[str]) -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        _prepare_cli(monkeypatch, tmpdir, [flag, weak])
        with patch.object(agent, "run_server") as run:
            with pytest.raises(SystemExit) as exc_info:
                agent.main()
            assert exc_info.value.code != 0
            run.assert_not_called()
    assert "token_hex(32)" in capsys.readouterr().err


def test_cli_starts_with_valid_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        _prepare_cli(monkeypatch, tmpdir, ["--secret", VALID_SECRET])
        with patch.object(agent, "run_server") as run:
            agent.main()
            run.assert_called_once()


class TestAgentSecretWeakenedAtRuntime:

    @classmethod
    def setup_class(cls) -> None:
        cls.port = 18994
        cls.cfg = AgentConfig(
            host="127.0.0.1", port=cls.port, secret=VALID_SECRET, agent_id="a" * 32,
            cert_file=agent_tls_files()[0], key_file=agent_tls_files()[1],
        )
        cls.server = PuyadAgentServer(cls.cfg)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        time.sleep(0.3)

    @classmethod
    def teardown_class(cls) -> None:
        cls.server.shutdown_cleanly()
        cls.server.server_close()

    def _get(self, secret: str) -> int:
        req = urllib.request.Request(
            f"https://127.0.0.1:{self.port}/api/status",
            headers=security.build_headers(secret, "GET", "/api/status", target="a" * 32),
        )
        try:
            with urllib.request.urlopen(req, timeout=5, context=agent_client_context()) as resp:
                return int(resp.status)
        except urllib.error.HTTPError as e:
            return e.code

    def test_weak_secret_rejected_after_config_change(self) -> None:
        assert self._get(VALID_SECRET) == 200
        self.cfg.secret = PLACEHOLDER_SECRET
        try:
            assert self._get(PLACEHOLDER_SECRET) == 401
        finally:
            self.cfg.secret = VALID_SECRET
