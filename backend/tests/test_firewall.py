from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
import compat
import config
import database
import firewall


class FakeIptables:

    def __init__(self) -> None:
        self.rules: dict[str, list[list[str]]] = {"iptables": [], "ip6tables": []}
        self.calls: list[list[str]] = []
        self.exes: list[str] = []
        self.fail_insert = False

    def __call__(self, cmd: list[str], **kw: Any) -> subprocess.CompletedProcess[str]:
        self.calls.append(cmd)
        self.exes.append(kw.get("executable", ""))
        if cmd[0] == "ip":
            out = json.dumps([{"addr_info": [{"local": "10.0.0.5"}]}])
            return subprocess.CompletedProcess(cmd, 0, out, "")
        tool, args = cmd[0], cmd[3:]
        rules = self.rules[tool]
        op = args[0]
        if op == "-S":
            lines = ["-P INPUT ACCEPT"] + [f"-A INPUT {self._fmt(r)}" for r in rules]
            return subprocess.CompletedProcess(cmd, 0, "\n".join(lines), "")
        if op == "-C":
            return subprocess.CompletedProcess(cmd, 0 if args[2:] in rules else 1, "", "")
        if op == "-I":
            if self.fail_insert:
                return subprocess.CompletedProcess(cmd, 1, "", "hata")
            assert args[1:3] == ["INPUT", "1"]
            rules.insert(0, args[3:])
            return subprocess.CompletedProcess(cmd, 0, "", "")
        if op == "-D":
            rules.remove(args[2:])
            return subprocess.CompletedProcess(cmd, 0, "", "")
        raise AssertionError(cmd)

    @staticmethod
    def _fmt(spec: list[str]) -> str:
        out = list(spec)
        ip = out[1]
        out[1] = ip + ("/128" if ":" in ip else "/32")
        return " ".join(out)

    def blocked(self, tool: str = "iptables") -> list[str]:
        return [r[1] for r in self.rules[tool]]


@pytest.fixture
def fw(monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeIptables]:
    fake = FakeIptables()
    monkeypatch.setattr(firewall.subprocess, "run", fake)
    monkeypatch.setattr(compat, "find_cmd", lambda name: f"/usr/sbin/{name}")
    monkeypatch.setattr(firewall, "_own_cache", (0.0, set()))
    with database.get_connection() as conn:
        conn.execute("DELETE FROM ip_blocks")
    yield fake


def test_engel_basa_ekleniyor(fw: FakeIptables) -> None:
    res = firewall.block("203.0.113.7", "test", "panel")
    assert res["success"] is True
    assert fw.rules["iptables"] == [["-s", "203.0.113.7", "-m", "comment", "--comment", "puyad-honeypot", "-j", "DROP"]]
    active = firewall.list_active()
    assert [b["ip"] for b in active] == ["203.0.113.7"]


def test_ayni_ip_tekrar_eklenmiyor(fw: FakeIptables) -> None:
    firewall.block("203.0.113.7", "test", "panel")
    firewall.block("203.0.113.7", "test", "telegram")
    assert fw.blocked() == ["203.0.113.7"]
    assert len(firewall.list_active()) == 1


def test_ipv6_ip6tables(fw: FakeIptables) -> None:
    assert firewall.block("2001:db8::1", "test", "panel")["success"] is True
    assert fw.blocked("ip6tables") == ["2001:db8::1"]
    assert fw.blocked() == []


def test_ipv4_mapped_v4_olarak(fw: FakeIptables) -> None:
    assert firewall.block("::ffff:203.0.113.9", "test", "panel")["ip"] == "203.0.113.9"
    assert fw.blocked() == ["203.0.113.9"]


@pytest.mark.parametrize("ip", ["127.0.0.1", "::1", "0.0.0.0", "169.254.1.1", "10.0.0.5", "::ffff:127.0.0.1"])
def test_korunan_adres_engellenmiyor(fw: FakeIptables, ip: str) -> None:
    res = firewall.block(ip, "test", "panel")
    assert res["success"] is False
    assert fw.rules == {"iptables": [], "ip6tables": []}
    assert firewall.list_active() == []


def test_yeni_acilista_kendi_ip_korunuyor(fw: FakeIptables, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(firewall.time, "monotonic", lambda: 60.0)
    assert firewall.block("10.0.0.5", "test", "panel")["success"] is False
    assert firewall.block("203.0.113.7", "test", "panel")["success"] is True
    assert fw.blocked() == ["203.0.113.7"]


def test_gecersiz_ip(fw: FakeIptables) -> None:
    assert firewall.block("1.2.3.4; rm -rf /", "test", "panel")["success"] is False
    assert not any(c[0] == "iptables" for c in fw.calls)


def test_ajan_sunucusu_korunuyor(fw: FakeIptables) -> None:
    with database.get_connection() as conn:
        conn.execute("INSERT INTO servers (name, ip_address, port, status) VALUES ('ajan', '198.51.100.20', 8000, 'online')")
    try:
        assert firewall.block("198.51.100.20", "test", "panel")["success"] is False
        assert firewall.block("198.51.100.21", "test", "panel")["success"] is True
    finally:
        with database.get_connection() as conn:
            conn.execute("DELETE FROM servers WHERE ip_address = '198.51.100.20'")


def test_son_giris_ip_korunuyor(fw: FakeIptables) -> None:
    firewall.record_login("198.51.100.30")
    assert firewall.block("198.51.100.30", "test", "panel")["success"] is False
    firewall.record_login("198.51.100.31")
    assert firewall.block("198.51.100.30", "test", "panel")["success"] is True


def test_beyaz_liste_cidr(fw: FakeIptables, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config, "load_config", lambda: {"HONEYPOT_WHITELIST": "192.0.2.0/24, bozuk, 2001:db8:1::/48"})
    assert firewall.block("192.0.2.55", "test", "panel")["success"] is False
    assert firewall.block("2001:db8:1::9", "test", "panel")["success"] is False
    assert firewall.block("192.0.3.1", "test", "panel")["success"] is True


def test_kural_eklenemezse_kayit_yok(fw: FakeIptables) -> None:
    fw.fail_insert = True
    res = firewall.block("203.0.113.7", "test", "panel")
    assert res == {"success": False, "message": "Güvenlik duvarı kuralı eklenemedi."}
    assert firewall.list_active() == []


def test_iptables_yoksa_hata(monkeypatch: pytest.MonkeyPatch) -> None:
    def missing(cmd: list[str], **kw: Any) -> None:
        raise FileNotFoundError(cmd[0])

    monkeypatch.setattr(firewall.subprocess, "run", missing)
    monkeypatch.setattr(firewall, "_own_cache", (1e18, set()))
    assert firewall.block("203.0.113.8", "test", "panel")["success"] is False


def test_sbin_yolu_kullaniliyor(fw: FakeIptables) -> None:
    firewall.block("203.0.113.7", "test", "panel")
    firewall.block("2001:db8::7", "test", "panel")
    assert "/usr/sbin/iptables" in fw.exes
    assert "/usr/sbin/ip6tables" in fw.exes
    assert fw.calls[-1][0] == "ip6tables"


def test_iptables_bulunamadi(fw: FakeIptables, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(compat, "find_cmd", lambda name: None)
    assert firewall.block("203.0.113.7", "test", "panel") == {"success": False, "message": "iptables bulunamadı."}
    assert firewall.block("2001:db8::7", "test", "panel")["message"] == "ip6tables bulunamadı."
    assert firewall.list_active() == []


def test_kaldirirken_iptables_yok(fw: FakeIptables, monkeypatch: pytest.MonkeyPatch) -> None:
    firewall.block("203.0.113.7", "test", "panel")
    bid = firewall.list_active()[0]["id"]
    monkeypatch.setattr(compat, "find_cmd", lambda name: None)
    assert firewall.unblock(bid) == {"success": False, "message": "iptables bulunamadı."}
    assert [b["id"] for b in firewall.list_active()] == [bid]
    assert fw.blocked() == ["203.0.113.7"]


def test_engel_kaldirma(fw: FakeIptables) -> None:
    firewall.block("203.0.113.7", "test", "panel")
    fw.rules["iptables"].append(list(fw.rules["iptables"][0]))
    bid = firewall.list_active()[0]["id"]
    assert firewall.unblock(bid)["success"] is True
    assert fw.blocked() == []
    assert firewall.list_active() == []
    assert firewall.unblock(bid)["success"] is False


def test_suresi_dolan_kalkiyor(fw: FakeIptables) -> None:
    firewall.block("203.0.113.7", "test", "panel")
    firewall.block("203.0.113.8", "test", "panel")
    with database.get_connection() as conn:
        conn.execute("UPDATE ip_blocks SET expires_at = datetime('now','localtime','-1 minutes') WHERE ip = '203.0.113.7'")
    assert firewall.expire() == 1
    assert fw.blocked() == ["203.0.113.8"]
    assert [b["ip"] for b in firewall.list_active()] == ["203.0.113.8"]


def test_varsayilan_sure_24_saat(fw: FakeIptables, monkeypatch: pytest.MonkeyPatch) -> None:
    firewall.block("203.0.113.7", "test", "panel")
    with database.get_connection() as conn:
        hours = conn.execute(
            "SELECT (julianday(expires_at) - julianday(created_at)) * 24 FROM ip_blocks"
        ).fetchone()[0]
    assert round(hours) == 24
    monkeypatch.setattr(config, "load_config", lambda: {"HONEYPOT_BLOCK_HOURS": 2})
    firewall.block("203.0.113.9", "test", "panel")
    with database.get_connection() as conn:
        hours = conn.execute(
            "SELECT (julianday(expires_at) - julianday(created_at)) * 24 FROM ip_blocks WHERE ip = '203.0.113.9'"
        ).fetchone()[0]
    assert round(hours) == 2


def test_acilista_esitleme(fw: FakeIptables) -> None:
    firewall.block("203.0.113.7", "test", "panel")
    firewall.block("2001:db8::7", "test", "panel")
    fw.rules = {"iptables": [], "ip6tables": []}
    fw.rules["iptables"].append(firewall._spec("198.51.100.99"))
    fw.rules["iptables"].append(["-s", "198.51.100.98", "-j", "ACCEPT"])
    firewall.sync()
    assert fw.blocked() == ["203.0.113.7", "198.51.100.98"]
    assert fw.blocked("ip6tables") == ["2001:db8::7"]


def _client() -> Any:
    from fastapi.testclient import TestClient
    import main
    return TestClient(main.app, client=("198.51.100.40", 50000))


def _admin_token() -> str:
    import auth
    from datetime import datetime
    auth._save_credentials({"username": "admin", "password_hash": auth._hash_password("parola-123"), "created_at": datetime.now().isoformat()})
    return auth.create_token("admin")


def test_giris_ip_kaydediliyor(fw: FakeIptables) -> None:
    _admin_token()
    c = _client()
    assert c.post("/api/auth/login", json={"username": "admin", "password": "yanlis"}).status_code == 401
    assert firewall._last_login_ip() == ""
    assert c.post("/api/auth/login", json={"username": "admin", "password": "parola-123"}).status_code == 200
    assert firewall._last_login_ip() == "198.51.100.40"
    assert firewall.block("198.51.100.40", "test", "panel")["success"] is False


def test_telegram_onayi_kilitli(fw: FakeIptables) -> None:
    import backup_manager
    token = _admin_token()
    with database.get_connection() as conn:
        conn.execute(
            "INSERT INTO pending_actions (token, action_type, target_payload, status) VALUES ('tk-fw', 'block_ip', ?, 'pending')",
            (json.dumps({"ip": "203.0.113.50"}),),
        )
    h = {"Authorization": f"Bearer {token}"}
    assert backup_manager.SYSTEM_CHANGE_LOCK.acquire(blocking=False)
    try:
        assert _client().post("/api/telegram/approve/tk-fw", headers=h).status_code == 409
    finally:
        backup_manager.SYSTEM_CHANGE_LOCK.release()
    assert fw.blocked() == []
    assert _client().post("/api/telegram/approve/tk-fw", headers=h).status_code == 200
    assert fw.blocked() == ["203.0.113.50"]
    assert firewall.list_active()[0]["source"] == "telegram"


def test_panel_engel_listesi_ve_kaldirma(fw: FakeIptables) -> None:
    import backup_manager
    import compat
    from unittest.mock import patch
    h = {"Authorization": f"Bearer {_admin_token()}"}
    firewall.block("203.0.113.60", "test", "telegram")
    c = _client()
    blocks = c.get("/api/honeypot/blocks", headers=h).json()["blocks"]
    assert [b["ip"] for b in blocks] == ["203.0.113.60"]
    bid = blocks[0]["id"]
    with patch.object(compat, "IS_LINUX", True):
        assert c.delete("/api/honeypot/blocks/99999", headers=h).status_code == 404
        assert backup_manager.SYSTEM_CHANGE_LOCK.acquire(blocking=False)
        try:
            assert c.delete(f"/api/honeypot/blocks/{bid}", headers=h).status_code == 409
        finally:
            backup_manager.SYSTEM_CHANGE_LOCK.release()
        assert fw.blocked() == ["203.0.113.60"]
        assert c.delete(f"/api/honeypot/blocks/{bid}", headers=h).status_code == 200
    assert fw.blocked() == []
    assert c.get("/api/honeypot/blocks", headers=h).json()["blocks"] == []


def test_panel_engel_yetkisiz(fw: FakeIptables) -> None:
    import auth
    _admin_token()
    c = _client()
    assert c.get("/api/honeypot/blocks").status_code == 401
    assert c.delete("/api/honeypot/blocks/1").status_code == 401
    other = {"Authorization": f"Bearer {auth.create_token('baskasi')}"}
    assert c.get("/api/honeypot/blocks", headers=other).status_code == 401
