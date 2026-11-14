from __future__ import annotations

import sys
from collections.abc import Iterator
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
import auth
import backup_manager
import config
import database
import engine
import firewall
import honeypot
import migrate
import scheduler
import throttle


@pytest.fixture(autouse=True, scope="session")
def setup_test_db(tmp_path_factory: pytest.TempPathFactory) -> Iterator[None]:
    # gerçek history.db'ye test kaydı düşmesin
    db_file = tmp_path_factory.mktemp("db") / "history.db"
    mp = pytest.MonkeyPatch()
    mp.setattr(database, "DB_FILE", db_file)
    mp.setattr(migrate, "DB_FILE", db_file)
    database.init_db()
    yield
    mp.undo()


@pytest.fixture(autouse=True)
def isolate_state_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # temiz klonda credentials.json ve .secret_key testlerden oluşmasın
    state = tmp_path / "state"
    state.mkdir()
    monkeypatch.setattr(auth, "CREDS_FILE", state / "credentials.json")
    monkeypatch.setattr(auth, "SECRET_KEY_FILE", state / ".secret_key")
    monkeypatch.setattr(auth, "SECRET_KEY", None)
    monkeypatch.setattr(config, "CONFIG_FILE", state / "config.json")
    monkeypatch.setattr(engine, "IGNORED_FILE", state / "ignored.json")
    monkeypatch.setattr(firewall, "LAST_LOGIN_FILE", state / "last_login.json")
    monkeypatch.setattr(honeypot, "CONFIG_FILE", state / "honeypot_config.json")
    monkeypatch.setattr(scheduler, "CONFIG_FILE", state / "scheduler_config.json")
    monkeypatch.setattr(scheduler, "ALERT_FILE", state / "scheduler_alerts.json")
    monkeypatch.setattr(backup_manager, "SNAPSHOT_DIR", state / "snapshots")
    monkeypatch.setattr(throttle, "RATE_LIMIT_LOG_DIR", state / "logs")
    monkeypatch.setattr(throttle, "RATE_LIMIT_LOG_FILE", state / "logs" / "rate_limit.log")
    monkeypatch.setattr(throttle, "RATE_LIMIT_LOG_JSON", state / "logs" / "rate_limit.json")
    auth.reset_lockout()
