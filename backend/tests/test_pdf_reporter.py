from __future__ import annotations

import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
import database
import pdf_reporter

HOSTILE_NAMES = [
    "Kural <b>kapanmayan etiket",
    "Kural </para><font name='yok'>",
    "Kural & <img src='/etc/passwd'/>",
    "<a href='http://evil'>tikla</a> kural",
]


@pytest.fixture
def scan_id() -> Iterator[int]:
    with database.get_connection() as conn:
        cur = conn.execute("INSERT INTO scan_history (total, warnings, ok_count, score) VALUES (4, 2, 2, 50)")
        sid = int(cur.lastrowid or 0)
        for i, name in enumerate(HOSTILE_NAMES):
            conn.execute(
                "INSERT INTO scan_results (scan_id, rule_id, rule_name, status, output) VALUES (?, ?, ?, ?, '')",
                (sid, f"x.{i}", name, "ok" if i % 2 else "warning"),
            )
    yield sid
    with database.get_connection() as conn:
        conn.execute("DELETE FROM scan_results WHERE scan_id = ?", (sid,))
        conn.execute("DELETE FROM scan_history WHERE id = ?", (sid,))


def test_report_with_markup_in_rule_names(scan_id: int) -> None:
    pdf = pdf_reporter.generate_report(scan_id)
    assert pdf.startswith(b"%PDF")


def test_hostname_with_markup(scan_id: int, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pdf_reporter.platform, "node", lambda: "<b>sunucu&")
    assert pdf_reporter.generate_report(scan_id).startswith(b"%PDF")
