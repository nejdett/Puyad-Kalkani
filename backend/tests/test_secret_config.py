from __future__ import annotations

import json
import sys
from pathlib import Path
import pytest

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT_DIR / "backend"))

import config

SECRET_KEYS = ("AGENT_SHARED_SECRET", "TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID")


def test_defaults_have_no_secret_values() -> None:
    for key in SECRET_KEYS:
        assert config.DEFAULTS[key] == ""


def test_example_configs_have_no_secret_values() -> None:
    backend_example = json.loads((ROOT_DIR / "config.json.example").read_text(encoding="utf-8"))
    for key in SECRET_KEYS:
        assert backend_example[key] == ""
    agent_example = json.loads((ROOT_DIR / "light_agent" / "config.json.example").read_text(encoding="utf-8"))
    assert agent_example["secret"] == ""
    assert agent_example["token"] == ""


def test_env_example_lists_keys_without_values() -> None:
    lines = (ROOT_DIR / ".env.example").read_text(encoding="utf-8").splitlines()
    entries = dict(line.split("=", 1) for line in lines if line and not line.startswith("#"))
    assert {"PUYAD_SECRET_KEY", "PUYAD_AGENT_SHARED_SECRET", "PUYAD_TELEGRAM_BOT_TOKEN"} <= set(entries)
    assert all(v == "" for v in entries.values())


def test_empty_env_var_does_not_override_config_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg_file = tmp_path / "config.json"
    cfg_file.write_text(json.dumps({"AGENT_SHARED_SECRET": "dosyadaki-gercek-sir"}))
    monkeypatch.setattr(config, "CONFIG_FILE", cfg_file)
    monkeypatch.setenv("PUYAD_AGENT_SHARED_SECRET", "")
    assert config.load_config()["AGENT_SHARED_SECRET"] == "dosyadaki-gercek-sir"
    monkeypatch.setenv("PUYAD_AGENT_SHARED_SECRET", "ortamdaki-sir")
    assert config.load_config()["AGENT_SHARED_SECRET"] == "ortamdaki-sir"


def test_missing_config_file_generates_random_agent_secret(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config, "CONFIG_FILE", tmp_path / "yok.json")
    monkeypatch.delenv("PUYAD_AGENT_SHARED_SECRET", raising=False)
    assert len(config.load_config()["AGENT_SHARED_SECRET"]) == 64


def test_missing_config_file_persists_generated_secret(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg_file = tmp_path / "config.json"
    monkeypatch.setattr(config, "CONFIG_FILE", cfg_file)
    monkeypatch.delenv("PUYAD_AGENT_SHARED_SECRET", raising=False)
    first = config.load_config()["AGENT_SHARED_SECRET"]
    assert cfg_file.stat().st_mode & 0o777 == 0o600
    assert json.loads(cfg_file.read_text())["AGENT_SHARED_SECRET"] == first
    assert config.load_config()["AGENT_SHARED_SECRET"] == first
    assert not list(tmp_path.glob(".config.json.tmp.*"))


def test_corrupt_config_file_not_overwritten(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg_file = tmp_path / "config.json"
    cfg_file.write_text("{bozuk")
    monkeypatch.setattr(config, "CONFIG_FILE", cfg_file)
    assert len(config.load_config()["AGENT_SHARED_SECRET"]) == 64
    assert cfg_file.read_text() == "{bozuk"


def test_env_secret_overrides_persisted_secret(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config, "CONFIG_FILE", tmp_path / "config.json")
    monkeypatch.setenv("PUYAD_AGENT_SHARED_SECRET", "ortamdaki-sir")
    assert config.load_config()["AGENT_SHARED_SECRET"] == "ortamdaki-sir"
    assert json.loads((tmp_path / "config.json").read_text())["AGENT_SHARED_SECRET"] != "ortamdaki-sir"


@pytest.mark.parametrize("value", [
    " puyad-secure-key-degistirin ",
    "PUYAD-SECURE-KEY-DEGISTIRIN",
    "buraya_backend_agent_shared_secret_degeri_yazilmali",
    "\tGuclu-Bir-Secret-Key-Buraya-Yazin\n",
    "   ",
])
def test_weak_secret_variants_rejected(value: str) -> None:
    sys.path.insert(0, str(ROOT_DIR))
    import agent_auth
    from light_agent import security

    assert agent_auth.is_weak_secret(value)
    assert security.is_weak_secret(value)
