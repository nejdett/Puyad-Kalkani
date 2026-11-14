import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
sys.path.insert(0, str(Path(__file__).parent.parent))
import cve_analyzer

FIXTURES = Path(__file__).parent / "fixtures" / "osv"

class TestDebianVersionCompare:

    @pytest.mark.parametrize("a,b,expected", [
        ("1:1.0", "9.9", 1),
        ("1.0~rc1", "1.0", -1),
        ("1.0~~", "1.0~", -1),
        ("3.0.11-1~deb12u2", "3.0.11-1~deb12u3", -1),
        ("2.36-9+deb12u4", "2.36-9+deb12u10", -1),
        ("1.2-1", "1.2-1+b1", -1),
        ("1.0a", "1.0", 1),
        ("1.0", "1.0-0", 0),
        ("1:9.2p1-2+deb12u2", "1:9.2p1-2+deb12u3", -1),
        ("9.7p1", "9.8", -1),
        ("10", "9", 1),
    ])
    def test_cases(self, a, b, expected):
        r = cve_analyzer._deb_cmp(a, b)
        assert (r > 0) - (r < 0) == expected

    @pytest.mark.skipif(shutil.which("dpkg") is None, reason="dpkg yok")
    def test_matches_dpkg(self):
        vs = ["1:1.0", "9.9", "1.0~rc1", "1.0", "1.0-0", "1.0a", "1.0+", "3.0.11-1~deb12u2",
              "3.0.11-1~deb12u3", "2.36-9+deb12u4", "2.36-9+deb12u10", "1.2-1+b1", "1.0~", "2:0"]
        for a in vs:
            for b in vs:
                lt = subprocess.run(["dpkg", "--compare-versions", a, "lt", b]).returncode == 0
                assert (cve_analyzer._deb_cmp(a, b) < 0) == lt, (a, b)

    def test_invalid_raises(self):
        with pytest.raises(ValueError):
            cve_analyzer._deb_cmp("", "1.0")
        with pytest.raises(ValueError):
            cve_analyzer._deb_cmp("x:1.0", "1.0")


def _fixture(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


class TestEvaluateVuln:

    def test_mixed_record_uses_only_host_block(self):
        vuln = _fixture("debian_cve_mixed.json")
        assert cve_analyzer._evaluate_vuln("openssl", "3.0.11-1~deb12u2", vuln, "Debian:12") == ("affected", "3.0.14-1~deb12u1")
        assert cve_analyzer._evaluate_vuln("openssl", "3.0.14-1~deb12u1", vuln, "Debian:12") == ("clear", None)

    def test_debian11_block_ignored_on_debian12(self):
        vuln = _fixture("debian_cve_mixed.json")
        assert cve_analyzer._evaluate_vuln("openssl", "3.0.14-1~deb12u1", vuln, "Debian:12")[0] == "clear"

    def test_android_macos_pypi_filtered(self):
        vuln = _fixture("other_ecosystem_only.json")
        assert cve_analyzer._evaluate_vuln("openssl", "3.0.11-1~deb12u2", vuln, "Debian:12") == ("other", None)

    def test_ubuntu_pro_and_other_package_blocks_ignored(self):
        vuln = _fixture("ubuntu_mixed.json")
        assert cve_analyzer._evaluate_vuln("openssl", "3.0.2-0ubuntu1", vuln, "Ubuntu:22.04") == ("affected", "3.0.2-0ubuntu1.1")
        assert cve_analyzer._evaluate_vuln("openssl", "3.0.2-0ubuntu1", vuln, "Ubuntu:20.04") == ("other", None)

    def test_epoch_fixed_version(self):
        vuln = _fixture("debian_epoch.json")
        assert cve_analyzer._evaluate_vuln("openssh", "1:9.2p1-2+deb12u2", vuln, "Debian:12") == ("affected", "1:9.2p1-2+deb12u3")
        assert cve_analyzer._evaluate_vuln("openssh", "1:9.2p1-2+deb12u3", vuln, "Debian:12")[0] == "clear"

    def test_unfixed_is_affected_without_fix(self):
        vuln = _fixture("debian_unfixed.json")
        assert cve_analyzer._evaluate_vuln("openssl", "3.0.11-1~deb12u2", vuln, "Debian:12") == ("affected", None)

    def test_bad_version_is_uncertain(self):
        vuln = _fixture("debian_epoch.json")
        assert cve_analyzer._evaluate_vuln("openssh", "x:1", vuln, "Debian:12") == ("uncertain", None)



def _src(version, binaries, known=True):
    return {"version": version, "binaries": binaries, "source_known": known}


def _finding(fixed="3.0.14-1~deb12u1", match="affected"):
    return {"package": "openssl", "installed_version": "3.0.11-1~deb12u2", "fixed_version": fixed or "Mevcut değil",
            "cve_id": "DEBIAN-CVE-2024-2511", "severity": "high", "match": match}


class TestClassify:

    BINS = {"libssl3": "3.0.11-1~deb12u2", "openssl": "3.0.11-1~deb12u2"}

    def test_verified(self):
        v = _finding()
        cands = {"libssl3": "3.0.14-1~deb12u2", "openssl": "3.0.14-1~deb12u2"}
        cve_analyzer._classify(v, _src("3.0.11-1~deb12u2", self.BINS), cands)
        assert v["confidence"] == "verified"
        assert v["can_upgrade"] is True
        assert v["binaries"] == ["libssl3", "openssl"]

    def test_candidate_missing_is_pending(self):
        v = _finding()
        cve_analyzer._classify(v, _src("3.0.11-1~deb12u2", self.BINS), {"libssl3": None, "openssl": None})
        assert v["confidence"] == "pending"
        assert "apt'de düzeltilmiş sürüm yok" in v["confidence_reason"]

    def test_candidate_lower_than_fixed_is_pending(self):
        v = _finding()
        cands = {"libssl3": "3.0.13-1~deb12u1", "openssl": "3.0.14-1~deb12u2"}
        cve_analyzer._classify(v, _src("3.0.11-1~deb12u2", self.BINS), cands)
        assert v["confidence"] == "pending"

    def test_no_fix_is_pending(self):
        v = _finding(fixed=None)
        cve_analyzer._classify(v, _src("3.0.11-1~deb12u2", self.BINS), {})
        assert v["confidence"] == "pending"
        assert v["can_upgrade"] is False

    def test_own_version_binary_skipped_in_check(self):
        v = _finding()
        bins = {"bsdutils": "1:3.0.11-1~deb12u2", "openssl": "3.0.11-1~deb12u2"}
        cve_analyzer._classify(v, _src("3.0.11-1~deb12u2", bins), {"bsdutils": "1:3.0.11-1~deb12u2", "openssl": "3.0.14-1~deb12u1"})
        assert v["confidence"] == "verified"
        assert v["check_binaries"] == ["openssl"]
        assert v["binaries"] == ["bsdutils", "openssl"]

    def test_source_binary_mismatch_is_review(self):
        v = _finding()
        bins = {"libldb2": "2:2.11.0+samba4.22.11-1"}
        cve_analyzer._classify(v, _src("2:4.22.11-1", bins), {"libldb2": "2:2.11.0+samba4.22.12-1"})
        assert v["confidence"] == "review"

    def test_binnmu_is_not_mismatch(self):
        v = _finding()
        bins = {"libssl3": "3.0.11-1~deb12u2+b1"}
        cve_analyzer._classify(v, _src("3.0.11-1~deb12u2", bins), {"libssl3": "3.0.14-1~deb12u1+b1"})
        assert v["confidence"] == "verified"

    def test_unknown_source_is_review(self):
        v = _finding()
        cve_analyzer._classify(v, _src("3.0.11-1~deb12u2", self.BINS, known=False), {})
        assert v["confidence"] == "review"


class TestInstalledSources:

    @patch("cve_analyzer.compat.IS_LINUX", True)
    @patch("cve_analyzer.subprocess.run")
    def test_binaries_grouped_by_source(self, mock_run):
        output = (
            "installed\tlibssl3:amd64\t3.0.11-1~deb12u2\topenssl\t3.0.11-1~deb12u2\n"
            "installed\topenssl\t3.0.11-1~deb12u2\topenssl\t3.0.11-1~deb12u2\n"
            "installed\tlibcurl4:amd64\t7.88.1-10+deb12u5+b1\tcurl\t7.88.1-10+deb12u5\n"
            "config-files\tgnuradio\t3.10.12.0-6\tgnuradio\t3.10.12.0-6\n"
        )
        mock_run.return_value = MagicMock(returncode=0, stdout=output)
        src = cve_analyzer._get_installed_sources()
        assert set(src) == {"openssl", "curl"}
        assert src["openssl"]["binaries"] == {"libssl3": "3.0.11-1~deb12u2", "openssl": "3.0.11-1~deb12u2"}
        assert src["curl"]["version"] == "7.88.1-10+deb12u5"

    @patch("cve_analyzer._fetch_vuln_details")
    @patch("cve_analyzer.httpx.Client")
    def test_query_uses_source_name_and_filters(self, mock_client, mock_fetch):
        cve_analyzer.clear_osv_cache()
        resp = MagicMock(status_code=200)
        resp.json.return_value = {"results": [{"vulns": [{"id": "DEBIAN-CVE-2024-2511"}, {"id": "CVE-2024-36971"}]}]}
        post = mock_client.return_value.__enter__.return_value.post
        post.return_value = resp
        mock_fetch.return_value = {
            "DEBIAN-CVE-2024-2511": _fixture("debian_cve_mixed.json"),
            "CVE-2024-36971": _fixture("other_ecosystem_only.json"),
        }
        res = cve_analyzer._query_osv_batch({"openssl": "3.0.11-1~deb12u2"}, ecosystem="Debian:12")
        query = post.call_args.kwargs["json"]["queries"][0]
        assert query["package"] == {"name": "openssl", "ecosystem": "Debian:12"}
        affected = [r for r in res if r["match"] == "affected"]
        other = [r for r in res if r["match"] == "other"]
        assert [r["cve_id"] for r in affected] == ["DEBIAN-CVE-2024-2511"]
        assert affected[0]["fixed_version"] == "3.0.14-1~deb12u1"
        assert [r["cve_id"] for r in other] == ["CVE-2024-36971"]


class TestCvssMapping:

    def test_numeric_score_critical(self):
        assert cve_analyzer._cvss_score_to_severity('9.8') == 'critical'

    def test_numeric_score_high(self):
        assert cve_analyzer._cvss_score_to_severity('7.5') == 'high'

    def test_numeric_score_medium(self):
        assert cve_analyzer._cvss_score_to_severity('5.0') == 'medium'

    def test_numeric_score_low(self):
        assert cve_analyzer._cvss_score_to_severity('2.1') == 'low'

    def test_vector_v3_critical(self):
        assert cve_analyzer._cvss_vector_to_severity('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 'CVSS_V3') == 'critical'

    def test_vector_v4_critical(self):
        assert cve_analyzer._cvss_vector_to_severity('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H', 'CVSS_V4') == 'critical'

    def test_extract_severity_prefers_v4(self):
        vuln = {'severity': [{'type': 'CVSS_V3', 'score': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'}, {'type': 'CVSS_V4', 'score': 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H'}]}
        sev, _ = cve_analyzer._extract_severity(vuln)
        assert sev == 'critical'

    def test_extract_severity_numeric(self):
        vuln = {'severity': [{'type': 'CVSS_V3', 'score': '9.8'}]}
        sev, _ = cve_analyzer._extract_severity(vuln)
        assert sev == 'critical'

class TestCalculateScore:

    def test_perfect_score(self):
        score = cve_analyzer._calculate_score(0, 0, 0, 0)
        assert score == 100

    def test_critical_affects_score(self):
        score = cve_analyzer._calculate_score(1, 0, 0, 0)
        assert score == 75

    def test_high_affects_score(self):
        score = cve_analyzer._calculate_score(0, 1, 0, 0)
        assert score == 90

    def test_medium_affects_score(self):
        score = cve_analyzer._calculate_score(0, 0, 1, 0)
        assert score == 95

    def test_low_affects_score(self):
        score = cve_analyzer._calculate_score(0, 0, 0, 1)
        assert score == 98

    def test_minimum_score(self):
        score = cve_analyzer._calculate_score(10, 10, 10, 10)
        assert score == 0

    def test_mixed_severities(self):
        score = cve_analyzer._calculate_score(1, 2, 3, 4)
        assert score == 32

class TestLoadCveDb:

    def test_load_cve_db_returns_list(self):
        db = cve_analyzer._load_cve_db()
        assert isinstance(db, list)

class TestGetInstalledPackages:

    def test_returns_dict(self):
        packages = cve_analyzer._get_installed_packages()
        assert isinstance(packages, dict)

    def test_packages_have_versions(self):
        packages = cve_analyzer._get_installed_packages()
        for pkg, ver in list(packages.items())[:5]:
            assert isinstance(ver, str)
            assert len(ver) > 0

    @patch("cve_analyzer.compat.IS_LINUX", True)
    @patch("cve_analyzer.subprocess.run")
    def test_filter_only_installed_and_strip_arch(self, mock_run):
        output = (
            "installed\tcurl:amd64\t7.88.1-10\n"
            "config-files\tgnuradio\t3.10.12.0-6\n"
            "not-installed\tapache2\t2.4.50-1\n"
            "installed\topenssl\t3.0.11-1\n"
        )
        mock_run.return_value = MagicMock(returncode=0, stdout=output)
        pkgs = cve_analyzer._get_installed_packages()
        assert "curl" in pkgs
        assert pkgs["curl"] == "7.88.1-10"
        assert "openssl" in pkgs
        assert pkgs["openssl"] == "3.0.11-1"
        assert "gnuradio" not in pkgs
        assert "apache2" not in pkgs

class TestOsvCache:

    def test_cache_set_and_get(self):
        cve_analyzer.clear_osv_cache()
        cve_analyzer._cache_set('testpkg', '1.0', [{'cve_id': 'CVE-2024-0001'}])
        hit = cve_analyzer._cache_get('testpkg', '1.0')
        assert hit is not None
        assert hit[0]['cve_id'] == 'CVE-2024-0001'

    def test_cache_miss(self):
        cve_analyzer.clear_osv_cache()
        assert cve_analyzer._cache_get('nope', '9.9') is None

    def test_clear_cache(self):
        cve_analyzer._cache_set('a', '1.0', [])
        cve_analyzer.clear_osv_cache()
        assert cve_analyzer._cache_get('a', '1.0') is None

class TestQueryOsvBatch:

    def test_empty_packages(self):
        cve_analyzer.clear_osv_cache()
        results = cve_analyzer._query_osv_batch({})
        assert results == []

    @patch('cve_analyzer._fetch_vuln_details')
    @patch('cve_analyzer.httpx.Client')
    def test_querybatch_success(self, mock_client, mock_fetch):
        cve_analyzer.clear_osv_cache()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {'results': [{'vulns': [{'id': 'DEBIAN-CVE-2024-1234'}]}]}
        mock_client.return_value.__enter__.return_value.post.return_value = mock_resp
        mock_fetch.return_value = {'DEBIAN-CVE-2024-1234': {'id': 'DEBIAN-CVE-2024-1234', 'summary': 'Test vuln', 'details': 'Detailed test vuln', 'severity': [{'type': 'CVSS_V3', 'score': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'}], 'affected': [{'package': {'name': 'testpkg', 'ecosystem': 'Debian:12'}, 'ranges': [{'type': 'ECOSYSTEM', 'events': [{'introduced': '0'}, {'fixed': '2.0'}]}]}], 'aliases': ['CVE-2024-1234']}}
        results = cve_analyzer._query_osv_batch({'testpkg': '1.0'}, ecosystem='Debian:12')
        assert len(results) == 1
        assert results[0]['cve_id'] == 'DEBIAN-CVE-2024-1234'
        assert results[0]['package'] == 'testpkg'
        assert results[0]['severity'] == 'critical'

    @patch('cve_analyzer.httpx.Client')
    def test_querybatch_no_vulns(self, mock_client):
        cve_analyzer.clear_osv_cache()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {'results': [{'vulns': []}]}
        mock_client.return_value.__enter__.return_value.post.return_value = mock_resp
        results = cve_analyzer._query_osv_batch({'testpkg': '1.0'})
        assert results == []

class TestRunCveScan:

    @patch('cve_analyzer._host_ecosystem', return_value=('Debian:12', True))
    @patch('cve_analyzer._get_installed_sources')
    def test_scan_no_packages(self, mock_pkgs, _eco):
        mock_pkgs.return_value = {}
        result = cve_analyzer.run_cve_scan()
        assert result['success'] is False

    @patch('cve_analyzer._apt_candidates', return_value={})
    @patch('cve_analyzer._host_ecosystem', return_value=('Debian:12', True))
    @patch('cve_analyzer.database.get_connection')
    @patch('cve_analyzer._query_osv_batch')
    @patch('cve_analyzer._get_installed_sources')
    def test_scan_with_vulns(self, mock_pkgs, mock_batch, mock_conn, _eco, _cands):
        mock_pkgs.return_value = {'testpkg': {'version': '1.0', 'binaries': {'testpkg': '1.0'}, 'source_known': True}}
        mock_batch.return_value = [{'package': 'testpkg', 'cve_id': 'CVE-2024-1234', 'severity': 'high', 'installed_version': '1.0', 'description': 'Test vuln', 'fix': 'apt upgrade', 'source': 'osv.dev', 'cvss_score': '7.5', 'affected_range': '', 'aliases': []}]
        mock_cursor = MagicMock()
        mock_cursor.lastrowid = 1
        mock_connection = MagicMock()
        mock_connection.execute.return_value = mock_cursor
        mock_connection.__enter__ = MagicMock(return_value=mock_connection)
        mock_connection.__exit__ = MagicMock(return_value=False)
        mock_conn.return_value = mock_connection
        result = cve_analyzer.run_cve_scan()
        assert result['success'] is True
        assert len(result['results']) > 0
        assert result['results'][0]['confidence'] == 'pending'
        assert result['results'][0]['section'] == 'unfixed'
        assert result['summary']['pending'] == 1
        assert result['summary']['unfixed'] == 1
        assert result['summary']['high'] == 0
        assert result['summary']['score'] == 100

    @patch('cve_analyzer._host_ecosystem', return_value=('Debian:12', True))
    @patch('cve_analyzer.database.get_connection')
    @patch('cve_analyzer._query_osv_batch')
    @patch('cve_analyzer._get_installed_sources')
    def test_scan_no_vulns_success(self, mock_pkgs, mock_batch, mock_conn, _eco):
        mock_pkgs.return_value = {'testpkg': {'version': '1.0', 'binaries': {'testpkg': '1.0'}, 'source_known': True}}
        mock_batch.return_value = []
        mock_cursor = MagicMock()
        mock_cursor.lastrowid = 1
        mock_connection = MagicMock()
        mock_connection.execute.return_value = mock_cursor
        mock_connection.__enter__ = MagicMock(return_value=mock_connection)
        mock_connection.__exit__ = MagicMock(return_value=False)
        mock_conn.return_value = mock_connection
        result = cve_analyzer.run_cve_scan()
        assert result['success'] is True
        assert result['summary']['total'] == 0
        assert result['summary']['score'] == 100

    @patch('cve_analyzer._apt_candidates', return_value={'testpkg': '2.0'})
    @patch('cve_analyzer._host_ecosystem', return_value=('Debian:12', True))
    @patch('cve_analyzer._query_osv_batch')
    @patch('cve_analyzer._get_installed_sources')
    def test_other_and_review_not_counted(self, mock_pkgs, mock_batch, _eco, _cands):
        mock_pkgs.return_value = {'testpkg': {'version': '1.0', 'binaries': {'testpkg': '1.0'}, 'source_known': True}}
        base = {'package': 'testpkg', 'installed_version': '1.0', 'severity': 'critical', 'description': ''}
        mock_batch.return_value = [
            {'package': 'testpkg', 'cve_id': 'CVE-A', 'match': 'other'},
            dict(base, cve_id='CVE-B', fixed_version='Mevcut değil', match='uncertain'),
            dict(base, cve_id='CVE-C', fixed_version='2.0', match='affected'),
        ]
        result = cve_analyzer.run_cve_scan()
        s = result['summary']
        assert (s['filtered_other_ecosystem'], s['review'], s['verified'], s['total'], s['critical']) == (1, 1, 1, 1, 1)
        assert {r['cve_id'] for r in result['results']} == {'CVE-B', 'CVE-C'}


class TestGetScanHistory:

    def test_get_history_returns_list(self):
        history = cve_analyzer.get_scan_history()
        assert isinstance(history, list)

    def test_get_history_with_limit(self):
        history = cve_analyzer.get_scan_history(limit=5)
        assert len(history) <= 5

class TestGetScanDetail:

    def test_nonexistent_scan(self):
        result = cve_analyzer.get_scan_detail(999999)
        assert result is None

class TestPackageAliases:

    def test_aliases_exist(self):
        assert isinstance(cve_analyzer.PACKAGE_ALIASES, dict)
        assert len(cve_analyzer.PACKAGE_ALIASES) > 0

    def test_glibc_alias(self):
        assert 'libc6' in cve_analyzer.PACKAGE_ALIASES.get('glibc', [])


POLICY_OK = (
    "libssl3:\n  Installed: 3.0.11-1~deb12u2\n  Candidate: 3.0.14-1~deb12u2\n  Version table:\n"
    "openssl:\n  Installed: 3.0.11-1~deb12u2\n  Candidate: 3.0.14-1~deb12u2\n  Version table:\n"
)
POLICY_NONE = (
    "libssl3:\n  Installed: 3.0.11-1~deb12u2\n  Candidate: (none)\n"
    "openssl:\n  Installed: 3.0.11-1~deb12u2\n  Candidate: (none)\n"
)
POLICY_LOW = (
    "libssl3:\n  Installed: 3.0.11-1~deb12u2\n  Candidate: 3.0.13-1~deb12u1\n"
    "openssl:\n  Installed: 3.0.11-1~deb12u2\n  Candidate: 3.0.13-1~deb12u1\n"
)


def _seed_scan(findings, server_id=1):
    import database
    with database.get_connection() as conn:
        conn.execute(
            "INSERT INTO cve_scans (server_id, vulnerability_score, critical_count, high_count, medium_count, low_count, scan_results) "
            "VALUES (?, 50, 0, 1, 0, 0, ?)",
            (server_id, json.dumps(findings)),
        )


def _seed_finding(package="openssl", confidence="verified", fixed="3.0.14-1~deb12u1", binaries=("libssl3", "openssl")):
    return {"package": package, "cve_id": f"CVE-{package}", "fixed_version": fixed, "binaries": list(binaries),
            "confidence": confidence, "confidence_reason": "apt'de düzeltilmiş sürüm yok." if confidence != "verified" else ""}


class FakeApt:

    def __init__(self, policy=POLICY_OK, sim_rc=0, sim_out="Inst libssl3 [3.0.11-1~deb12u2] (3.0.14-1~deb12u2 Debian:12)\n",
                 before="3.0.11-1~deb12u2", after="3.0.14-1~deb12u2"):
        self.policy, self.sim_rc, self.sim_out = policy, sim_rc, sim_out
        self.version, self.after = before, after
        self.calls = []

    @property
    def installs(self):
        return [c for c in self.calls if c[0] == "apt-get" and "-s" not in c]

    def __call__(self, cmd, **kwargs):
        self.calls.append(list(cmd))
        if cmd[:2] == ["apt-cache", "policy"]:
            return MagicMock(returncode=0, stdout=self.policy, stderr="")
        if cmd[:2] == ["apt-get", "-s"]:
            return MagicMock(returncode=self.sim_rc, stdout=self.sim_out, stderr="E: Unable to correct problems" if self.sim_rc else "")
        if cmd[0] == "apt-get":
            self.version = self.after
            return MagicMock(returncode=0, stdout="Setting up libssl3", stderr="")
        if cmd[0] == "dpkg-query":
            return MagicMock(returncode=0, stdout=self.version)
        raise AssertionError(cmd)


class TestFixCvePackage:

    def test_invalid_package_name(self):
        res = cve_analyzer.fix_cve_package("invalid;rm -rf /")
        assert res["success"] is False
        assert "Geçersiz" in res["message"]

    @patch("cve_analyzer.compat.IS_LINUX", False)
    def test_non_linux_rejected(self):
        res = cve_analyzer.fix_cve_package("curl")
        assert res["success"] is False
        assert "Linux" in res["message"]

    @patch("cve_analyzer.compat.IS_LINUX", True)
    def test_successful_upgrade(self):
        _seed_scan([_seed_finding()])
        fake = FakeApt()
        with patch("cve_analyzer.subprocess.run", side_effect=fake):
            res = cve_analyzer.fix_cve_package("openssl")
        assert res["success"] is True
        assert res["status"] == "upgraded"
        assert res["old_version"] == "3.0.11-1~deb12u2"
        assert res["new_version"] == "3.0.14-1~deb12u2"
        assert fake.installs[0][-2:] == ["libssl3", "openssl"]

    @patch("cve_analyzer.compat.IS_LINUX", True)
    def test_binary_name_resolves_to_finding(self):
        _seed_scan([_seed_finding()])
        fake = FakeApt()
        with patch("cve_analyzer.subprocess.run", side_effect=fake):
            res = cve_analyzer.fix_cve_package("libssl3")
        assert res["status"] == "upgraded"

    @pytest.mark.parametrize("fake,needle", [
        (FakeApt(policy=POLICY_NONE), "aday sürüm yok"),
        (FakeApt(policy=POLICY_LOW), "apt'de düzeltilmiş sürüm yok"),
        (FakeApt(sim_out="Remv libssl-dev [3.0.11-1~deb12u2]\nInst libssl3 [3.0.11-1~deb12u2] (3.0.14-1~deb12u2)\n"), "kaldıracağı için iptal"),
        (FakeApt(sim_rc=100, sim_out=""), "simülasyonu başarısız"),
    ])
    @patch("cve_analyzer.compat.IS_LINUX", True)
    def test_rejected_without_install(self, fake, needle):
        _seed_scan([_seed_finding()])
        with patch("cve_analyzer.subprocess.run", side_effect=fake):
            res = cve_analyzer.fix_cve_package("openssl")
        assert res["success"] is False
        assert res["status"] == "rejected"
        assert needle in res["message"]
        assert "Unable to correct" not in res["message"]
        assert fake.installs == []

    @patch("cve_analyzer.compat.IS_LINUX", True)
    def test_unverified_finding_rejected(self):
        _seed_scan([_seed_finding(confidence="pending")])
        fake = FakeApt()
        with patch("cve_analyzer.subprocess.run", side_effect=fake):
            res = cve_analyzer.fix_cve_package("openssl")
        assert res["success"] is False
        assert "doğrulanmış bulgu yok" in res["message"]
        assert fake.calls == []

    @patch("cve_analyzer.compat.IS_LINUX", True)
    def test_unknown_package_rejected(self):
        _seed_scan([_seed_finding()])
        fake = FakeApt()
        with patch("cve_analyzer.subprocess.run", side_effect=fake):
            res = cve_analyzer.fix_cve_package("curl")
        assert res["success"] is False
        assert fake.installs == []


    @patch("cve_analyzer.compat.IS_LINUX", True)
    def test_injected_binary_name_never_reaches_apt(self):
        _seed_scan([_seed_finding(binaries=("openssl", "x;rm -rf /"))])
        fake = FakeApt()
        with patch("cve_analyzer.subprocess.run", side_effect=fake):
            cve_analyzer.fix_cve_package("openssl")
        assert all("x;rm -rf /" not in c for c in fake.calls)


class TestFixCveBatch:

    def test_empty_packages_returns_error(self):
        res = cve_analyzer.fix_cve_batch([])
        assert res["success"] is False

    @patch("cve_analyzer.compat.IS_LINUX", True)
    def test_only_verified_packages_installed(self):
        _seed_scan([_seed_finding(), _seed_finding(package="curl", confidence="pending", binaries=("curl", "libcurl4"))])
        fake = FakeApt()
        with patch("cve_analyzer.subprocess.run", side_effect=fake):
            res = cve_analyzer.fix_cve_batch(["openssl", "curl"])
        assert res["success"] is True
        assert res["total_upgraded"] == 1
        assert [s["package"] for s in res["skipped"]] == ["curl"]
        assert len(fake.installs) == 1
        assert "curl" not in fake.installs[0] and "libcurl4" not in fake.installs[0]

    @patch("cve_analyzer.compat.IS_LINUX", True)
    def test_removal_in_simulation_blocks_batch(self):
        _seed_scan([_seed_finding()])
        fake = FakeApt(sim_out="Remv libssl-dev [3.0.11-1~deb12u2]\n")
        with patch("cve_analyzer.subprocess.run", side_effect=fake):
            res = cve_analyzer.fix_cve_batch(["openssl"])
        assert res["success"] is False
        assert "libssl-dev" in res["message"]
        assert fake.installs == []

    @patch("cve_analyzer.compat.IS_LINUX", True)
    def test_nothing_verified(self):
        _seed_scan([_seed_finding(confidence="review")])
        fake = FakeApt()
        with patch("cve_analyzer.subprocess.run", side_effect=fake):
            res = cve_analyzer.fix_cve_batch(["openssl"])
        assert res["success"] is False
        assert fake.installs == []


OS_RELEASES = {
    "debian12": (
        'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nNAME="Debian GNU/Linux"\nVERSION_ID="12"\n'
        'VERSION="12 (bookworm)"\nVERSION_CODENAME=bookworm\nID=debian\n',
        "12.7",
    ),
    "debian13": (
        'PRETTY_NAME="Debian GNU/Linux 13 (trixie)"\nNAME="Debian GNU/Linux"\nVERSION_ID="13"\n'
        'VERSION="13 (trixie)"\nVERSION_CODENAME=trixie\nID=debian\n',
        "13.1",
    ),
    "debian_testing": (
        'PRETTY_NAME="Debian GNU/Linux forky/sid"\nNAME="Debian GNU/Linux"\nVERSION_CODENAME=forky\nID=debian\n',
        "forky/sid",
    ),
    "ubuntu2204": (
        'PRETTY_NAME="Ubuntu 22.04.4 LTS"\nNAME="Ubuntu"\nVERSION_ID="22.04"\nVERSION="22.04.4 LTS (Jammy Jellyfish)"\n'
        'VERSION_CODENAME=jammy\nID=ubuntu\nID_LIKE=debian\nUBUNTU_CODENAME=jammy\n',
        "bookworm/sid",
    ),
    "ubuntu2404": (
        'PRETTY_NAME="Ubuntu 24.04.1 LTS"\nNAME="Ubuntu"\nVERSION_ID="24.04"\nVERSION="24.04.1 LTS (Noble Numbat)"\n'
        'VERSION_CODENAME=noble\nID=ubuntu\nID_LIKE=debian\nUBUNTU_CODENAME=noble\n',
        "trixie/sid",
    ),
    "ubuntu2410": (
        'PRETTY_NAME="Ubuntu 24.10"\nNAME="Ubuntu"\nVERSION_ID="24.10"\nVERSION_CODENAME=oracular\nID=ubuntu\n'
        'ID_LIKE=debian\nUBUNTU_CODENAME=oracular\n',
        "trixie/sid",
    ),
    "mint22": (
        'NAME="Linux Mint"\nVERSION="22 (Wilma)"\nID=linuxmint\nID_LIKE="ubuntu debian"\nPRETTY_NAME="Linux Mint 22"\n'
        'VERSION_ID="22"\nVERSION_CODENAME=wilma\nUBUNTU_CODENAME=noble\n',
        "trixie/sid",
    ),
    "lmde6": (
        'PRETTY_NAME="LMDE 6 (faye)"\nNAME="LMDE"\nVERSION_ID="6"\nVERSION="6 (faye)"\nVERSION_CODENAME=faye\n'
        'ID=linuxmint\nID_LIKE=debian\nDEBIAN_CODENAME=bookworm\n',
        "12.7",
    ),
    "pop2204": (
        'NAME="Pop!_OS"\nVERSION="22.04 LTS"\nID=pop\nID_LIKE="ubuntu debian"\nPRETTY_NAME="Pop!_OS 22.04 LTS"\n'
        'VERSION_ID="22.04"\nVERSION_CODENAME=jammy\nUBUNTU_CODENAME=jammy\n',
        "bookworm/sid",
    ),
    "raspbian11": (
        'PRETTY_NAME="Raspbian GNU/Linux 11 (bullseye)"\nNAME="Raspbian GNU/Linux"\nVERSION_ID="11"\n'
        'VERSION="11 (bullseye)"\nVERSION_CODENAME=bullseye\nID=raspbian\nID_LIKE=debian\n',
        "11.9",
    ),
    "debian_derivative_version_file": (
        'PRETTY_NAME="Ornek Turev 23"\nNAME="Ornek Turev"\nVERSION_ID="23"\nVERSION_CODENAME=libretto\nID=ornek\nID_LIKE=debian\n',
        "12.5",
    ),
    "kali": (
        'PRETTY_NAME="Kali GNU/Linux Rolling"\nNAME="Kali GNU/Linux"\nVERSION_ID="2024.2"\nVERSION="2024.2"\n'
        'VERSION_CODENAME=kali-rolling\nID=kali\nID_LIKE=debian\n',
        "kali-rolling",
    ),
    "rocky9": (
        'NAME="Rocky Linux"\nVERSION="9.4 (Blue Onyx)"\nID="rocky"\nID_LIKE="rhel centos fedora"\nVERSION_ID="9.4"\n'
        'PLATFORM_ID="platform:el9"\nPRETTY_NAME="Rocky Linux 9.4 (Blue Onyx)"\n',
        "",
    ),
}


def _detect(key, has_dpkg=True):
    text, debian_version = OS_RELEASES[key]
    with patch("cve_analyzer.get_os_info", return_value=cve_analyzer._parse_os_release(text)), \
         patch("cve_analyzer._read_debian_version", return_value=debian_version), \
         patch("cve_analyzer._has_dpkg", return_value=has_dpkg):
        return cve_analyzer.detect_distro()


class TestDetectDistro:

    @pytest.mark.parametrize("key,ecosystem", [
        ("debian12", "Debian:12"),
        ("debian13", "Debian:13"),
        ("debian_testing", "Debian:14"),
        ("ubuntu2204", "Ubuntu:22.04:LTS"),
        ("ubuntu2404", "Ubuntu:24.04:LTS"),
        ("ubuntu2410", "Ubuntu:24.10"),
        ("mint22", "Ubuntu:24.04:LTS"),
        ("lmde6", "Debian:12"),
        ("pop2204", "Ubuntu:22.04:LTS"),
        ("raspbian11", "Debian:11"),
        ("debian_derivative_version_file", "Debian:12"),
    ])
    def test_supported(self, key, ecosystem):
        d = _detect(key)
        assert d["supported"] is True
        assert d["ecosystem"] == ecosystem

    @pytest.mark.parametrize("key", ["kali", "rocky9"])
    def test_unsupported(self, key):
        d = _detect(key)
        assert d["supported"] is False
        assert d["ecosystem"] is None
        assert d["message"] == cve_analyzer.UNSUPPORTED_MESSAGE

    def test_rocky_without_dpkg(self):
        assert _detect("rocky9", has_dpkg=False)["supported"] is False

    def test_debian_without_dpkg_unsupported(self):
        d = _detect("debian12", has_dpkg=False)
        assert d["supported"] is False
        assert "dpkg" in d["reason"]

    def test_missing_os_release(self):
        with patch("cve_analyzer.get_os_info", return_value={}), \
             patch("cve_analyzer._read_debian_version", return_value=""), \
             patch("cve_analyzer._has_dpkg", return_value=True):
            assert cve_analyzer.detect_distro()["supported"] is False

    def test_parse_os_release_quotes_and_comments(self):
        info = cve_analyzer._parse_os_release('# yorum\nID="rocky"\nID_LIKE=\'rhel fedora\'\n\nNAME=Rocky\n')
        assert info == {"id": "rocky", "id_like": "rhel fedora", "name": "Rocky"}

    @patch("cve_analyzer._get_installed_sources")
    @patch("cve_analyzer._host_ecosystem", return_value=("", False))
    def test_scan_unsupported_returns_message(self, _eco, mock_sources):
        res = cve_analyzer.run_cve_scan()
        assert res["supported"] is False
        assert res["message"] == cve_analyzer.UNSUPPORTED_MESSAGE
        mock_sources.assert_not_called()


class TestCveSupportApi:

    def _client(self):
        from fastapi.testclient import TestClient
        import main
        return TestClient(main.app, client=("192.168.99.95", 50000))

    def _headers(self):
        import auth
        return {"Authorization": f"Bearer {auth.create_token(str(auth._load_credentials()['username']))}"}

    @patch("cve_analyzer.compat.IS_LINUX", True)
    def test_scan_endpoint_unsupported_is_not_error(self):
        with patch("cve_analyzer._host_ecosystem", return_value=("", False)):
            res = self._client().get("/api/cve/scan", headers=self._headers())
        assert res.status_code == 200
        body = res.json()
        assert body["supported"] is False
        assert body["message"] == cve_analyzer.UNSUPPORTED_MESSAGE

    @patch("cve_analyzer.compat.IS_LINUX", True)
    def test_support_endpoint(self):
        with patch("cve_analyzer.detect_distro", return_value={"supported": False, "name": "Rocky Linux 9.4",
                                                                "message": cve_analyzer.UNSUPPORTED_MESSAGE}):
            res = self._client().get("/api/cve/support", headers=self._headers())
        assert res.status_code == 200
        assert res.json() == {"supported": False, "message": cve_analyzer.UNSUPPORTED_MESSAGE, "distro": "Rocky Linux 9.4"}


class TestGetCveFixHistory:

    def test_returns_list(self):
        hist = cve_analyzer.get_cve_fix_history()
        assert isinstance(hist, list)



class TestScoringAndUrgency:

    BINS = {"openssl": "3.0.11-1~deb12u2"}

    def _classified(self, fixed, cand, urgency=None):
        v = _finding(fixed=fixed)
        v["distro_urgency"] = urgency
        cve_analyzer._classify(v, _src("3.0.11-1~deb12u2", self.BINS), {"openssl": cand})
        return v

    def test_sections_and_scored(self):
        verified = self._classified("3.0.14-1~deb12u1", "3.0.14-1~deb12u1")
        stale = self._classified("3.0.14-1~deb12u1", "3.0.11-1~deb12u2")
        unfixed = self._classified(None, "3.0.11-1~deb12u2")
        review = _finding(fixed="3.0.14-1~deb12u1", match="uncertain")
        cve_analyzer._classify(review, _src("3.0.11-1~deb12u2", self.BINS), {"openssl": "3.0.14-1~deb12u1"})
        assert [v["section"] for v in (verified, stale, unfixed, review)] == ["verified", "stale", "unfixed", "review"]
        assert [v["scored"] for v in (verified, stale, unfixed, review)] == [True, True, False, False]

    def test_unimportant_not_scored(self):
        v = self._classified("3.0.14-1~deb12u1", "3.0.14-1~deb12u1", urgency="unimportant")
        assert v["section"] == "verified"
        assert v["scored"] is False

    def test_unimportant_record_still_listed(self):
        vuln = _fixture("debian_unfixed.json")
        vuln["affected"][0]["ecosystem_specific"]["urgency"] = "unimportant"
        assert cve_analyzer._evaluate_vuln("openssl", "3.0.11-1~deb12u2", vuln, "Debian:12") == ("affected", None)
        assert cve_analyzer._distro_urgency("openssl", vuln, "Debian:12") == "unimportant"

    def test_urgency_sources(self):
        assert cve_analyzer._distro_urgency("openssl", _fixture("debian_unfixed.json"), "Debian:12") == "low"
        assert cve_analyzer._distro_urgency("openssl", _fixture("debian_cve_mixed.json"), "Debian:12") == "not yet assigned"
        assert cve_analyzer._distro_urgency("openssl", _fixture("ubuntu_mixed.json"), "Ubuntu:22.04") == "medium"
        assert cve_analyzer._distro_urgency("openssh", _fixture("debian_epoch.json"), "Debian:12") is None

    @patch('cve_analyzer._apt_candidates', return_value={'testpkg': '1.0'})
    @patch('cve_analyzer._host_ecosystem', return_value=('Debian:12', True))
    @patch('cve_analyzer._query_osv_batch')
    @patch('cve_analyzer._get_installed_sources')
    def test_score_counts_only_verified_and_stale(self, mock_pkgs, mock_batch, _eco, _cands):
        mock_pkgs.return_value = {'testpkg': {'version': '1.0', 'binaries': {'testpkg': '1.0'}, 'source_known': True}}
        base = {'package': 'testpkg', 'installed_version': '1.0', 'severity': 'critical', 'description': '', 'match': 'affected'}
        mock_batch.return_value = [
            dict(base, cve_id='CVE-STALE', fixed_version='2.0'),
            dict(base, cve_id='CVE-UNFIXED', fixed_version='Mevcut değil'),
            dict(base, cve_id='CVE-UNIMP', fixed_version='2.0', distro_urgency='unimportant'),
        ]
        s = cve_analyzer.run_cve_scan()['summary']
        assert (s['stale'], s['unfixed'], s['unimportant'], s['critical'], s['total']) == (2, 1, 1, 1, 1)
        assert s['score'] == cve_analyzer._calculate_score(1, 0, 0, 0, total_packages=1)
        assert 'apt_lists' in s


class TestAptLists:

    def _lists(self, tmp_path, age_seconds):
        lists = tmp_path / "lists"
        (lists / "partial").mkdir(parents=True)
        t = time.time() - age_seconds
        os.utime(lists / "partial", (t, t))
        os.utime(lists, (t, t))
        return lists

    def test_stale_after_24h(self, tmp_path):
        with patch("cve_analyzer._APT_LISTS_DIR", self._lists(tmp_path, 7 * 86400 + 60)):
            st = cve_analyzer.apt_lists_status()
        assert st["stale"] is True
        assert st["age_days"] == 7

    def test_fresh(self, tmp_path):
        with patch("cve_analyzer._APT_LISTS_DIR", self._lists(tmp_path, 3600)):
            st = cve_analyzer.apt_lists_status()
        assert st["stale"] is False
        assert st["age_days"] == 0

    def test_missing_dir(self, tmp_path):
        with patch("cve_analyzer._APT_LISTS_DIR", tmp_path / "yok"):
            assert cve_analyzer.apt_lists_status() == {"updated_at": None, "age_days": None, "stale": False}

    @patch("cve_analyzer.compat.IS_LINUX", True)
    @patch("cve_analyzer.subprocess.run")
    def test_update_uses_list_args_and_timeout(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="Reading package lists...", stderr="")
        res = cve_analyzer.update_apt_lists()
        args, kwargs = mock_run.call_args
        assert args[0] == ["apt-get", "update", "-q"]
        assert kwargs["timeout"] == 300
        assert "shell" not in kwargs
        assert res["success"] is True

    @patch("cve_analyzer.compat.IS_LINUX", True)
    @patch("cve_analyzer.subprocess.run")
    def test_update_failure_hides_apt_output(self, mock_run):
        mock_run.return_value = MagicMock(returncode=100, stdout="", stderr="E: Failed to fetch http://gizli.example/InRelease")
        res = cve_analyzer.update_apt_lists()
        assert res["success"] is False
        assert "gizli.example" not in res["message"]

    @patch("cve_analyzer.compat.IS_LINUX", True)
    @patch("cve_analyzer.subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="apt-get", timeout=300))
    def test_update_timeout(self, _run):
        res = cve_analyzer.update_apt_lists()
        assert res["success"] is False
        assert "zaman aşımı" in res["message"]

    @patch("cve_analyzer.compat.IS_LINUX", True)
    @patch("cve_analyzer.compat.find_cmd", return_value=None)
    @patch("cve_analyzer.subprocess.run")
    def test_apt_get_bulunamadi(self, mock_run, _find):
        assert cve_analyzer.update_apt_lists() == {"success": False, "message": "apt-get bulunamadı."}
        assert cve_analyzer._apt_simulate(["openssl"]) == "apt-get bulunamadı."
        mock_run.assert_not_called()

    @patch("cve_analyzer.compat.IS_LINUX", True)
    @patch("cve_analyzer.compat.find_cmd", side_effect=lambda name: f"/usr/sbin/{name}")
    @patch("cve_analyzer.subprocess.run")
    def test_apt_get_sbin_yolu(self, mock_run, _find):
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        assert cve_analyzer.update_apt_lists()["success"] is True
        args, kwargs = mock_run.call_args
        assert args[0][0] == "apt-get"
        assert kwargs["executable"] == "/usr/sbin/apt-get"
