from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
import compat
import forensic_manager

CMD = forensic_manager._LINUX_COMMANDS["running_processes"]


def test_process_listing_has_no_arguments_column() -> None:
    assert "aux" not in CMD
    assert "-eo pid,user,comm" in CMD


@pytest.mark.skipif(not compat.IS_LINUX, reason="ps yalnızca Linux'ta")
def test_command_line_secrets_not_collected() -> None:
    marker = "GIZLI-PAROLA-12345"
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)", marker])
    try:
        out = subprocess.run(CMD.split("|")[0], shell=True, capture_output=True, text=True, check=True).stdout
        assert str(proc.pid) in out
        assert marker not in out
    finally:
        proc.kill()
        proc.wait()
