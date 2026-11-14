from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
import compat


@pytest.fixture
def sbin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    d = tmp_path / "sbin"
    d.mkdir()
    tool = d / "puyadtool"
    tool.write_text("#!/bin/sh\necho sbin-ok\n")
    tool.chmod(0o755)
    empty = tmp_path / "bin"
    empty.mkdir()
    monkeypatch.setattr(compat, "SBIN_DIRS", (str(d),))
    monkeypatch.setenv("PATH", str(empty) + ":/usr/bin:/bin")
    return d


def test_sbin_altinda_bulunuyor(sbin: Path) -> None:
    assert compat.find_cmd("puyadtool") == str(sbin / "puyadtool")
    assert compat.need_cmd("puyadtool") == str(sbin / "puyadtool")


def test_yoksa_net_mesaj(sbin: Path) -> None:
    assert compat.find_cmd("olmayan-komut") is None
    with pytest.raises(compat.CommandNotFound, match="^olmayan-komut bulunamadı.$"):
        compat.need_cmd("olmayan-komut")


def test_calistirilamayan_dosya_sayilmiyor(sbin: Path) -> None:
    (sbin / "puyadtool").chmod(0o644)
    assert compat.find_cmd("puyadtool") is None


def test_shell_env_sbin_ekliyor(sbin: Path) -> None:
    parts = compat.shell_env()["PATH"].split(":")
    assert parts[-1] == str(sbin)
    assert parts.count(str(sbin)) == 1


@pytest.mark.skipif(not compat.IS_LINUX, reason="yalnızca Linux")
def test_run_shell_sbin_komutunu_buluyor(sbin: Path) -> None:
    assert compat.run_shell("puyadtool") == "sbin-ok"
