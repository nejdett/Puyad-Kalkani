from __future__ import annotations

import json
import logging
import math
import os
import re
import subprocess
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from functools import cmp_to_key
from pathlib import Path
from typing import Any, TypeVar, cast

import compat
import database
import httpx

logger = logging.getLogger(__name__)

CVE_DB_FILE: Path = Path(__file__).parent / "cve_database.json"
PACKAGE_ALIASES: dict[str, list[str]] = {
    "glibc": ["libc6"],
    "krb5-libs": ["libk5crypto3", "libkrb5-3", "libgssapi-krb5-2"],
    "nettle": ["libnettle8", "libhogweed6"],
    "openssl": ["libssl3", "openssl"],
}


def _load_cve_db() -> list[dict[str, Any]]:
    if not CVE_DB_FILE.exists():
        return []
    try:
        with open(CVE_DB_FILE, "r", encoding="utf-8") as f:
            data: Any = json.load(f)
            return cast(list[dict[str, Any]], data)
    except (OSError, json.JSONDecodeError):
        return []


_OSV_CACHE: dict[str, tuple[float, list[dict[str, Any]]]] = {}
_CACHE_LOCK: threading.Lock = threading.Lock()
_CACHE_TTL_SECONDS: float = 3600
_CACHE_MAX_ENTRIES: int = 5000

_VULN_CACHE: dict[str, tuple[float, dict[str, Any]]] = {}
_VULN_TTL_SECONDS: float = 3600 * 24

_BATCH_SIZE: int = 250
_DETAIL_WORKERS: int = 8
_DETAIL_TIMEOUT: float = 15.0
_MAX_VULNS_PER_PKG: int = 50
# Önbellekteki eski biçimli (ekosistem süzmesiz) sonuçlar yeniden kullanılmasın
_CACHE_FORMAT: str = "v3"
_APT_LISTS_DIR: Path = Path("/var/lib/apt/lists")
_APT_LISTS_MAX_AGE: float = 24 * 3600


UNSUPPORTED_MESSAGE: str = "Bu dağıtımda CVE analizi desteklenmiyor (yalnızca Debian/Ubuntu ve türevleri)."
_UBUNTU_CODENAMES: dict[str, str] = {
    "xenial": "16.04",
    "bionic": "18.04",
    "focal": "20.04",
    "jammy": "22.04",
    "kinetic": "22.10",
    "lunar": "23.04",
    "mantic": "23.10",
    "noble": "24.04",
    "oracular": "24.10",
    "plucky": "25.04",
    "questing": "25.10",
    "resolute": "26.04",
}
_DEBIAN_CODENAMES: dict[str, str] = {
    "stretch": "9",
    "buster": "10",
    "bullseye": "11",
    "bookworm": "12",
    "trixie": "13",
    "forky": "14",
}
# Kendi deposundan rolling güncellenen dağıtımlar — paket sürümleri Debian kayıtlarıyla eşleşmez
_ROLLING_DISTROS: set[str] = {"kali", "parrot"}


def _parse_os_release(text: str) -> dict[str, str]:
    info: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            info[k.strip().lower()] = v.strip().strip('"').strip("'")
    return info


def get_os_info() -> dict[str, str]:
    for os_release in (Path("/etc/os-release"), Path("/usr/lib/os-release")):
        try:
            return _parse_os_release(os_release.read_text(encoding="utf-8"))
        except OSError:
            continue
    return {}


def _read_debian_version() -> str:
    try:
        return Path("/etc/debian_version").read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def _has_dpkg() -> bool:
    return all(compat.find_cmd(cmd) for cmd in ("dpkg-query", "apt-get", "apt-cache"))


def _debian_release(info: dict[str, str]) -> str | None:
    for key in ("debian_codename", "version_codename"):
        ver = _DEBIAN_CODENAMES.get(info.get(key, "").lower())
        if ver:
            return ver
    dv = _read_debian_version()
    m = re.match(r"^(\d+)(\.|$)", dv)
    if m:
        return m.group(1)
    # testing/unstable "trixie/sid" yazıyor
    return _DEBIAN_CODENAMES.get(dv.split("/", 1)[0].lower())


def detect_distro() -> dict[str, Any]:
    info = get_os_info()
    os_id = info.get("id", "").lower()
    like = info.get("id_like", "").lower().split()
    name = info.get("pretty_name") or info.get("name") or os_id or "bilinmeyen"

    def unsupported(reason: str) -> dict[str, Any]:
        return {"supported": False, "ecosystem": None, "name": name, "reason": reason, "message": UNSUPPORTED_MESSAGE}

    if not _has_dpkg():
        return unsupported("dpkg/apt bulunamadı")
    if os_id in _ROLLING_DISTROS:
        return unsupported("kendi deposunu kullanan rolling dağıtım")

    if os_id == "ubuntu" or "ubuntu" in like:
        if os_id == "ubuntu":
            ver = info.get("version_id", "") or _UBUNTU_CODENAMES.get(info.get("version_codename", "").lower(), "")
        else:
            ver = _UBUNTU_CODENAMES.get(info.get("ubuntu_codename", "").lower(), "")
        if not re.match(r"^\d{2}\.\d{2}$", ver):
            return unsupported("Ubuntu sürümü belirlenemedi")
        lts = ver.endswith(".04") and int(ver[:2]) % 2 == 0
        return {"supported": True, "ecosystem": f"Ubuntu:{ver}{':LTS' if lts else ''}", "name": name, "family": "Ubuntu", "version": ver}

    if os_id in ("debian", "raspbian") or "debian" in like:
        ver = info.get("version_id", "") if os_id in ("debian", "raspbian") else ""
        if not re.match(r"^\d+$", ver):
            ver = _debian_release(info) or ""
        if not ver:
            return unsupported("Debian sürümü belirlenemedi")
        return {"supported": True, "ecosystem": f"Debian:{ver}", "name": name, "family": "Debian", "version": ver}

    return unsupported("dpkg tabanlı bir dağıtım değil")


def _host_ecosystem() -> tuple[str, bool]:
    distro = detect_distro()
    return str(distro["ecosystem"] or ""), bool(distro["supported"])


def _cvss_score_to_severity(score_str: str) -> str:
    try:
        s = float(score_str.strip())
    except (ValueError, TypeError):
        return "medium"
    if s >= 9.0:
        return "critical"
    if s >= 7.0:
        return "high"
    if s >= 4.0:
        return "medium"
    if s > 0:
        return "low"
    return "medium"


def _cvss_vector_to_severity(vector: str, cvss_type: str) -> str:
    try:
        float(vector.strip())
        return _cvss_score_to_severity(vector)
    except (ValueError, TypeError):
        pass

    upper = vector.upper()
    high_hits = upper.count(":H")
    has_network = "AV:N" in upper
    has_low_complexity = "AC:L" in upper

    if cvss_type == "CVSS_V4":
        if high_hits >= 3 and has_network:
            return "critical"
        if high_hits >= 2:
            return "high"
        if high_hits >= 1:
            return "medium"
        return "low"
    if high_hits >= 3:
        return "critical"
    if high_hits >= 2:
        return "high"
    if high_hits >= 1:
        if has_network and has_low_complexity:
            return "high"
        return "medium"
    return "low"


def _extract_severity(vuln: dict[str, Any]) -> tuple[str, str | None]:
    severities: list[dict[str, Any]] = vuln.get("severity", [])
    priority = {"CVSS_V4": 0, "CVSS_V3": 1, "CVSS_V2": 2}
    if not severities:
        return "medium", None

    def rank(s: dict[str, Any]) -> int:
        return priority.get(str(s.get("type", "")), 99)

    severities_sorted = sorted(severities, key=rank)
    for sev in severities_sorted:
        t = str(sev.get("type", ""))
        score = str(sev.get("score", "")).strip()
        if not score:
            continue
        if t == "CVSS_V4":
            return _cvss_vector_to_severity(score, "CVSS_V4"), score
        if t == "CVSS_V3":
            if score.upper().startswith("CVSS:"):
                return _cvss_vector_to_severity(score, "CVSS_V3"), score
            return _cvss_score_to_severity(score), score
        if t == "CVSS_V2":
            return _cvss_score_to_severity(score), score
        try:
            float(score)
            return _cvss_score_to_severity(score), score
        except ValueError:
            continue

    first_score = str(severities_sorted[0].get("score", "")).strip()
    if first_score:
        if first_score.upper().startswith("CVSS:"):
            return _cvss_vector_to_severity(first_score, "CVSS_V3"), first_score
        return _cvss_score_to_severity(first_score), first_score
    return "medium", None


_DIGITS: str = "0123456789"


def _char_order(c: str) -> int:
    if c == "~":
        return -1
    if ("a" <= c <= "z") or ("A" <= c <= "Z"):
        return ord(c)
    return ord(c) + 256


def _cmp_fragment(a: str, b: str) -> int:
    i = j = 0
    while i < len(a) or j < len(b):
        while (i < len(a) and a[i] not in _DIGITS) or (j < len(b) and b[j] not in _DIGITS):
            ac = _char_order(a[i]) if i < len(a) and a[i] not in _DIGITS else 0
            bc = _char_order(b[j]) if j < len(b) and b[j] not in _DIGITS else 0
            if ac != bc:
                return ac - bc
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        first_diff = 0
        while i < len(a) and a[i] in _DIGITS and j < len(b) and b[j] in _DIGITS:
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < len(a) and a[i] in _DIGITS:
            return 1
        if j < len(b) and b[j] in _DIGITS:
            return -1
        if first_diff:
            return first_diff
    return 0


def _split_version(raw: str) -> tuple[int, str, str]:
    ver = raw.strip()
    epoch = 0
    if ":" in ver:
        head, ver = ver.split(":", 1)
        epoch = int(head)
    upstream, sep, revision = ver.rpartition("-")
    if not sep:
        upstream, revision = ver, ""
    if not upstream:
        raise ValueError(f"Geçersiz sürüm: {raw!r}")
    return epoch, upstream, revision


# dpkg'nin verrevcmp algoritması — her karşılaştırma için dpkg süreci açmak yüzlerce pakette çok yavaş
def _deb_cmp(a: str, b: str) -> int:
    ea, ua, ra = _split_version(a)
    eb, ub, rb = _split_version(b)
    if ea != eb:
        return -1 if ea < eb else 1
    return _cmp_fragment(ua, ub) or _cmp_fragment(ra, rb)


def _strip_binnmu(ver: str) -> str:
    return re.sub(r"\+b\d+$", "", ver.strip())


def _accepts_ecosystem(eco: str, target: str) -> bool:
    if ":" in target:
        return eco in (target, f"{target}:LTS")
    return eco == target or (eco.startswith(f"{target}:") and ":Pro:" not in f"{eco}:")


def _evaluate_vuln(src: str, ver: str, vuln: dict[str, Any], ecosystem: str) -> tuple[str, str | None]:
    blocks: list[dict[str, Any]] = []
    for aff in vuln.get("affected", []) or []:
        pkg_info = aff.get("package") or {}
        if str(pkg_info.get("name", "")) == src and _accepts_ecosystem(str(pkg_info.get("ecosystem", "")), ecosystem):
            blocks.append(aff)
    if not blocks:
        return "other", None

    uncertain = False
    for aff in blocks:
        for r in aff.get("ranges", []) or []:
            # GIT/SEMVER aralıkları upstream commit'leri, dpkg sürümüyle kıyaslanamaz
            if r.get("type", "ECOSYSTEM") != "ECOSYSTEM":
                continue
            start: str | None = None
            for ev in r.get("events", []) or []:
                if "introduced" in ev:
                    start = str(ev["introduced"])
                    continue
                end = ev.get("fixed") or ev.get("last_affected")
                if start is None or not end:
                    continue
                try:
                    after_start = start == "0" or _deb_cmp(ver, start) >= 0
                    end_cmp = _deb_cmp(ver, str(end))
                except ValueError:
                    uncertain = True
                    start = None
                    continue
                in_range = end_cmp < 0 if "fixed" in ev else end_cmp <= 0
                if after_start and in_range:
                    return "affected", str(ev["fixed"]) if "fixed" in ev else None
                start = None
            if start is not None:
                try:
                    if start == "0" or _deb_cmp(ver, start) >= 0:
                        return "affected", None
                except ValueError:
                    uncertain = True
    return ("uncertain" if uncertain else "clear"), None


def _distro_urgency(src: str, vuln: dict[str, Any], ecosystem: str) -> str | None:
    for aff in vuln.get("affected", []) or []:
        pkg_info = aff.get("package") or {}
        if str(pkg_info.get("name", "")) == src and _accepts_ecosystem(str(pkg_info.get("ecosystem", "")), ecosystem):
            urgency = (aff.get("ecosystem_specific") or {}).get("urgency")
            if urgency:
                return str(urgency).strip().lower()
    for sev in vuln.get("severity", []) or []:
        if sev.get("type") == "Ubuntu" and sev.get("score"):
            return str(sev["score"]).strip().lower()
    return None


def _get_installed_sources() -> dict[str, dict[str, Any]]:
    sources: dict[str, dict[str, Any]] = {}
    if not compat.IS_LINUX:
        return sources
    try:
        result: subprocess.CompletedProcess[str] = subprocess.run(
            [
                "dpkg-query", "-W", "-f",
                "${db:Status-Status}\t${Package}\t${Version}\t${source:Package}\t${source:Version}\n",
            ],
            executable=compat.need_cmd("dpkg-query"), capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            return sources
        for line in result.stdout.strip().splitlines():
            parts = [p.strip() for p in line.split("\t")]
            if len(parts) < 3 or parts[0] != "installed" or not parts[1]:
                continue
            pkg = parts[1].split(":", 1)[0]
            ver = parts[2]
            src = parts[3] if len(parts) >= 5 else ""
            src_ver = parts[4] if len(parts) >= 5 else ""
            known = bool(src and src_ver)
            entry = sources.setdefault(src or pkg, {"version": src_ver or ver, "binaries": {}, "source_known": known})
            entry["binaries"][pkg] = ver
            if not known:
                entry["source_known"] = False
            elif src_ver != entry["version"]:
                # Kısmi yükseltmede aynı kaynağın ikilileri farklı sürümde olabilir — en eskisi esas
                try:
                    if _deb_cmp(src_ver, entry["version"]) < 0:
                        entry["version"] = src_ver
                except ValueError:
                    entry["source_known"] = False
    except OSError:
        pass
    return sources


def _get_installed_packages() -> dict[str, str]:
    packages: dict[str, str] = {}
    for info in _get_installed_sources().values():
        packages.update(info["binaries"])
    return packages


_T = TypeVar("_T")


def _mem_get(cache: dict[str, tuple[float, _T]], key: str, ttl: float) -> _T | None:
    with _CACHE_LOCK:
        entry = cache.get(key)
        if entry:
            ts, data = entry
            if time.time() - ts < ttl:
                return data
            cache.pop(key, None)
    return None


def _mem_put(cache: dict[str, tuple[float, _T]], key: str, value: _T) -> None:
    with _CACHE_LOCK:
        if len(cache) >= _CACHE_MAX_ENTRIES:
            oldest = sorted(cache.items(), key=lambda kv: kv[1][0])[: _CACHE_MAX_ENTRIES // 5]
            for k, _ in oldest:
                cache.pop(k, None)
        cache[key] = (time.time(), value)


def _cache_get(pkg: str, ver: str) -> list[dict[str, Any]] | None:
    key = f"{pkg}:{ver}"
    hit = _mem_get(_OSV_CACHE, key, _CACHE_TTL_SECONDS)
    if hit is not None:
        return hit

    disk_entry = database.get_cached_package_vulns(pkg, ver)
    if disk_entry is not None:
        with _CACHE_LOCK:
            _OSV_CACHE[key] = (time.time(), disk_entry)
        return disk_entry
    return None


def _cache_set(pkg: str, ver: str, vulns: list[dict[str, Any]]) -> None:
    _mem_put(_OSV_CACHE, f"{pkg}:{ver}", vulns)
    try:
        database.set_cached_package_vulns(pkg, ver, vulns)
    except Exception:
        pass


def _vuln_cache_get(vuln_id: str) -> dict[str, Any] | None:
    hit = _mem_get(_VULN_CACHE, vuln_id, _VULN_TTL_SECONDS)
    if hit is not None:
        return hit

    disk_entry = database.get_cached_vuln_detail(vuln_id)
    if disk_entry is not None:
        with _CACHE_LOCK:
            _VULN_CACHE[vuln_id] = (time.time(), disk_entry)
        return disk_entry
    return None


def _vuln_cache_set(vuln_id: str, data: dict[str, Any]) -> None:
    _mem_put(_VULN_CACHE, vuln_id, data)
    try:
        database.set_cached_vuln_detail(vuln_id, data)
    except Exception:
        pass


def clear_osv_cache() -> None:
    with _CACHE_LOCK:
        _OSV_CACHE.clear()
        _VULN_CACHE.clear()
    try:
        database.clear_cve_caches()
    except Exception:
        pass


def _fetch_vuln_details(vuln_ids: set[str]) -> dict[str, dict[str, Any]]:
    if not vuln_ids:
        return {}

    to_fetch: list[str] = []
    result: dict[str, dict[str, Any]] = {}

    for vid in vuln_ids:
        cached = _vuln_cache_get(vid)
        if cached is not None:
            result[vid] = cached
        else:
            to_fetch.append(vid)

    if not to_fetch:
        return result

    limits = httpx.Limits(
        max_keepalive_connections=_DETAIL_WORKERS + 2,
        max_connections=_DETAIL_WORKERS + 4,
    )

    try:
        with httpx.Client(timeout=_DETAIL_TIMEOUT, limits=limits) as client:
            def _fetch_one(vid: str) -> tuple[str, dict[str, Any] | None]:
                for _ in range(2):
                    try:
                        resp = client.get(f"https://api.osv.dev/v1/vulns/{vid}")
                        if resp.status_code == 200:
                            data: dict[str, Any] = resp.json()
                            _vuln_cache_set(vid, data)
                            return vid, data
                        if resp.status_code == 404:
                            return vid, None
                    except Exception:
                        time.sleep(0.3)
                return vid, None

            with ThreadPoolExecutor(max_workers=_DETAIL_WORKERS) as pool:
                futures = {pool.submit(_fetch_one, vid): vid for vid in to_fetch}
                for fut in as_completed(futures):
                    vid, data = fut.result()
                    if data is not None:
                        result[vid] = data
    except Exception:
        pass

    return result


def _query_osv_batch(
    packages: dict[str, str],
    force: bool = False,
    host_os: str = "linux",
    ecosystem: str | None = None,
) -> list[dict[str, Any]]:
    if not packages:
        return []

    target_ecosystem = ecosystem or _host_ecosystem()[0]

    cached_results: list[dict[str, Any]] = []
    misses: dict[str, str] = {}
    for pkg, ver in packages.items():
        if not force:
            hit = _cache_get(pkg, f"{_CACHE_FORMAT}:{ver}")
            if hit is not None:
                cached_results.extend(hit)
                continue
        misses[pkg] = ver

    if not misses:
        return cached_results

    items = list(misses.items())
    all_vuln_ids_per_pkg: dict[str, list[str]] = {pkg: [] for pkg in misses}

    chunks = [items[i: i + _BATCH_SIZE] for i in range(0, len(items), _BATCH_SIZE)]
    batch_workers = min(len(chunks), 4) or 1

    limits = httpx.Limits(
        max_keepalive_connections=batch_workers + 2,
        max_connections=batch_workers + 4,
    )

    try:
        with httpx.Client(timeout=25.0, limits=limits) as client:
            def _query_chunk(chunk: list[tuple[str, str]]) -> list[tuple[str, list[str]]]:
                queries = [
                    {"package": {"name": pkg, "ecosystem": target_ecosystem}, "version": ver}
                    for pkg, ver in chunk
                ]
                for attempt in range(2):
                    try:
                        resp = client.post(
                            "https://api.osv.dev/v1/querybatch",
                            json={"queries": queries},
                        )
                        if resp.status_code != 200:
                            if attempt == 0:
                                time.sleep(0.5)
                                continue
                            return []
                        data: dict[str, Any] = resp.json()
                        results: list[dict[str, Any]] = data.get("results", [])
                        out: list[tuple[str, list[str]]] = []
                        for idx, res in enumerate(results):
                            if idx >= len(chunk):
                                break
                            pkg_name = chunk[idx][0]
                            vulns = res.get("vulns", [])
                            ids = [str(v.get("id", "")).strip() for v in vulns if v.get("id")]
                            out.append((pkg_name, ids))
                        return out
                    except Exception:
                        if attempt == 0:
                            time.sleep(0.5)
                            continue
                        return []
                return []

            if len(chunks) == 1:
                for pkg, ids in _query_chunk(chunks[0]):
                    all_vuln_ids_per_pkg[pkg] = ids
            else:
                with ThreadPoolExecutor(max_workers=batch_workers) as pool:
                    futures = [pool.submit(_query_chunk, c) for c in chunks]
                    for fut in as_completed(futures):
                        for pkg, ids in fut.result():
                            all_vuln_ids_per_pkg[pkg] = ids
    except Exception:
        return cached_results

    all_ids: set[str] = set()
    for pkg, ids in all_vuln_ids_per_pkg.items():
        for vid in ids[:_MAX_VULNS_PER_PKG]:
            all_ids.add(vid)

    vuln_details = _fetch_vuln_details(all_ids)
    hydrated_results: list[dict[str, Any]] = []

    for pkg, ver in misses.items():
        ids = all_vuln_ids_per_pkg.get(pkg, [])
        pkg_vulns: list[dict[str, Any]] = []

        for vid in ids[:_MAX_VULNS_PER_PKG]:
            vuln = vuln_details.get(vid)
            if not vuln:
                continue

            cve_id: str = str(vuln.get("id", vid))
            state, fixed_ver = _evaluate_vuln(pkg, ver, vuln, target_ecosystem)
            if state == "clear":
                continue
            if state == "other":
                pkg_vulns.append({"package": pkg, "cve_id": cve_id, "match": "other"})
                continue

            aliases: list[str] = vuln.get("aliases", []) or []
            description: str = str(vuln.get("details", "") or vuln.get("summary", "") or "").strip()
            severity, cvss_score = _extract_severity(vuln)
            affected_range = f"< {fixed_ver}" if fixed_ver else "Etkilenen sürüm aralığında"

            pkg_vulns.append({
                "package": pkg,
                "installed_version": ver,
                "fixed_version": fixed_ver or "Mevcut değil",
                "cve_id": cve_id,
                "severity": severity,
                "description": description[:600] if description else "",
                "fix": f"apt install --only-upgrade {pkg}",
                "source": "osv.dev",
                "cvss_score": cvss_score,
                "affected_range": affected_range,
                "aliases": aliases,
                "match": state,
                "distro_urgency": _distro_urgency(pkg, vuln, target_ecosystem),
            })

        _cache_set(pkg, f"{_CACHE_FORMAT}:{ver}", pkg_vulns)
        hydrated_results.extend(pkg_vulns)

    return cached_results + hydrated_results


def _calculate_score(critical: int, high: int, medium: int, low: int, total_packages: int | None = None) -> int:
    if total_packages is None:
        penalty: int = critical * 25 + high * 10 + medium * 5 + low * 2
        return max(0, min(100, 100 - penalty))

    if total_packages <= 0:
        return 100 if (critical + high + medium + low) == 0 else 0

    if (critical + high + medium + low) == 0:
        return 100

    weighted_vulns = critical * 10.0 + high * 5.0 + medium * 2.0 + low * 0.5
    ratio = weighted_vulns / max(total_packages, 50)
    score = round(100.0 * math.exp(-ratio * 2.2))
    return max(1, min(100, int(score)))


def _apt_candidates(pkgs: list[str]) -> dict[str, str | None]:
    pkgs = [p for p in pkgs if re.match(_PKG_NAME_RE, p)]
    if not pkgs:
        return {}
    env = dict(os.environ)
    env["LC_ALL"] = "C"
    try:
        r = subprocess.run(
            ["apt-cache", "policy", *pkgs], executable=compat.need_cmd("apt-cache"),
            capture_output=True, text=True, timeout=60, env=env,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {}
    candidates: dict[str, str | None] = {}
    current: str | None = None
    for line in r.stdout.splitlines():
        if line and not line[0].isspace() and line.rstrip().endswith(":"):
            current = line.rstrip()[:-1].split(":", 1)[0]
        elif current and line.strip().startswith("Candidate:"):
            cand = line.split(":", 1)[1].strip()
            candidates[current] = None if cand in ("", "(none)") else cand
    return candidates


def _classify(vuln: dict[str, Any], info: dict[str, Any] | None, candidates: dict[str, str | None]) -> None:
    binaries: dict[str, str] = (info or {}).get("binaries", {})
    names = sorted(binaries)
    src_ver = str(vuln.get("installed_version", ""))
    # Kendi sürümünü taşıyan ikililer (bsdutils, libldb2) düzeltilmiş kaynak sürümüyle kıyaslanamaz
    comparable = [b for b in names if _strip_binnmu(binaries[b]) == src_ver]
    fixed = vuln.get("fixed_version")
    if not fixed or fixed == "Mevcut değil":
        fixed = None
    cands = [candidates.get(b) for b in comparable]
    known = [c for c in cands if c]

    vuln["binaries"] = names
    vuln["check_binaries"] = comparable
    vuln["fix"] = f"apt-get install --only-upgrade {' '.join(names)}" if names else ""
    vuln["fixed_version"] = fixed or "Mevcut değil"
    vuln["repo_candidate"] = min(known, key=cmp_to_key(_deb_cmp)) if known else None

    if vuln.get("match") == "uncertain":
        level, reason = "review", "Sürüm bilgisi dağıtım kaydıyla karşılaştırılamadı."
    elif info is None or not info.get("source_known", True):
        level, reason = "review", "Kaynak paket bilgisi alınamadı."
    elif not names:
        level, reason = "review", "Bu kaynaktan kurulu ikili paket bulunamadı."
    elif not comparable:
        level, reason = "review", "İkili paket sürümü kaynak paket sürümüyle uyuşmuyor."
    elif fixed is None:
        level, reason = "pending", "Dağıtım açığı kabul ediyor, henüz düzeltme yayınlanmadı."
    elif not all(cands) or any(_deb_cmp(_strip_binnmu(str(c)), fixed) < 0 for c in cands):
        level, reason = "pending", "apt'de düzeltilmiş sürüm yok (paket listeleri eski olabilir: apt update)."
    else:
        level, reason = "verified", "apt'de düzeltilmiş sürüm mevcut."
    if level == "pending":
        section = "stale" if fixed else "unfixed"
    else:
        section = level
    vuln["confidence"] = level
    vuln["confidence_reason"] = reason
    vuln["can_upgrade"] = level == "verified"
    vuln["section"] = section
    # Düzeltmesi yayınlanmamış ya da dağıtımın "unimportant" saydığı kayıtlar skoru boğuyordu
    vuln["scored"] = section in ("verified", "stale") and vuln.get("distro_urgency") != "unimportant"


def run_cve_scan(use_osv: bool = False, server_id: int = 1, force: bool = False) -> dict[str, Any]:
    try:
        ecosystem, supported = _host_ecosystem()
        if not supported:
            distro = detect_distro()
            logger.info("CVE taraması atlandı, dağıtım desteklenmiyor: %s (%s)", distro["name"], distro.get("reason"))
            return {"success": False, "supported": False, "message": UNSUPPORTED_MESSAGE, "distro": distro["name"]}

        if force:
            clear_osv_cache()

        sources = _get_installed_sources()
        if not sources:
            return {
                "success": False,
                "message": (
                    "Paket listesi alınamadı. dpkg-query komutu çalışmadı. "
                    "Bu ortamda dpkg/paket yöneticisi mevcut olmayabilir."
                ),
            }
        binary_count = sum(len(info["binaries"]) for info in sources.values())

        os_info = get_os_info()
        host_os = os_info.get("id", "linux").lower()
        src_versions = {src: str(info["version"]) for src, info in sources.items()}
        raw_vulns = _query_osv_batch(src_versions, force=force, host_os=host_os, ecosystem=ecosystem)

        filtered_other = 0
        dedup: dict[str, dict[str, Any]] = {}
        for v in raw_vulns:
            if v.get("match") == "other":
                filtered_other += 1
                continue
            dedup.setdefault(f"{v.get('package', '')}:{v.get('cve_id', '')}", dict(v))
        found_vulns = list(dedup.values())

        needed = sorted({b for v in found_vulns for b in sources.get(str(v.get("package", "")), {}).get("binaries", {})})
        candidates = _apt_candidates(needed)
        for v in found_vulns:
            _classify(v, sources.get(str(v.get("package", ""))), candidates)

        open_vulns = [v for v in found_vulns if v["scored"]]
        sections = Counter(str(v["section"]) for v in found_vulns)
        verified = sections["verified"]
        pending = sections["stale"] + sections["unfixed"]
        review = sections["review"]
        critical: int = sum(1 for v in open_vulns if v["severity"] == "critical")
        high: int = sum(1 for v in open_vulns if v["severity"] == "high")
        medium: int = sum(1 for v in open_vulns if v["severity"] == "medium")
        low: int = sum(1 for v in open_vulns if v["severity"] == "low")
        upgradable_count: int = len(set(v["package"] for v in found_vulns if v["confidence"] == "verified"))
        score: int = _calculate_score(critical, high, medium, low, total_packages=binary_count)

        scan_results_json: str = json.dumps(found_vulns, ensure_ascii=False)
        with database.get_connection() as conn:
            cursor = conn.execute(
                """INSERT INTO cve_scans
                   (server_id, vulnerability_score, critical_count, high_count,
                    medium_count, low_count, scan_results)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (server_id, score, critical, high, medium, low, scan_results_json),
            )
            scan_id: int | None = cursor.lastrowid
            assert scan_id is not None

        try:
            database.update_server_score(server_id, score)
        except Exception:
            pass

        if found_vulns:
            msg = (
                f"{binary_count} paket tarandı. {verified} doğrulanmış, {sections['stale']} paket listesi "
                f"güncellenince kurulabilecek bulgu var. {sections['unfixed']} bulgu için dağıtım henüz düzeltme "
                f"yayınlamadı, {review} bulgu incelenmeli."
            )
        else:
            msg = f"{binary_count} paket tarandı. Aktif zafiyet bulunamadı."

        return {
            "success": True,
            "scan_id": scan_id,
            "message": msg,
            "summary": {
                "total": len(open_vulns),
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low,
                "score": score,
                "packages_checked": binary_count,
                "packages_matched": len(set(v["package"] for v in found_vulns)),
                "upgradable_packages": upgradable_count,
                "verified": verified,
                "pending": pending,
                "review": review,
                "stale": sections["stale"],
                "unfixed": sections["unfixed"],
                "unimportant": sum(1 for v in found_vulns if v.get("distro_urgency") == "unimportant"),
                "filtered_other_ecosystem": filtered_other,
                "apt_lists": apt_lists_status(),
                "ecosystem": ecosystem,
            },
            "results": found_vulns,
        }

    except Exception:
        logger.exception("CVE taraması başarısız")
        return {"success": False, "message": "CVE taraması tamamlanamadı."}


def get_scan_history(server_id: int | None = None, limit: int = 20) -> list[dict[str, Any]]:
    with database.get_connection() as conn:
        base_q = (
            "SELECT id, server_id, vulnerability_score, critical_count, "
            "high_count, medium_count, low_count, created_at FROM cve_scans"
        )
        if server_id is not None:
            rows = conn.execute(
                f"{base_q} WHERE server_id = ? ORDER BY created_at DESC LIMIT ?",
                (server_id, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                f"{base_q} ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
    return [dict(r) for r in rows]


def get_scan_detail(scan_id: int) -> dict[str, Any] | None:
    with database.get_connection() as conn:
        row = conn.execute("SELECT * FROM cve_scans WHERE id = ?", (scan_id,)).fetchone()
    if not row:
        return None
    result: dict[str, Any] = dict(row)
    if result.get("scan_results"):
        result["scan_results"] = json.loads(result["scan_results"])
    return result


_PKG_NAME_RE: str = r"^[a-zA-Z0-9][a-zA-Z0-9+.-]+$"


def _installed_version(pkg: str, timeout: float) -> str | None:
    try:
        r = subprocess.run(
            ["dpkg-query", "-W", "-f", "${Version}", pkg], executable=compat.need_cmd("dpkg-query"),
            capture_output=True, text=True, timeout=timeout,
        )
    except Exception:
        return None
    return r.stdout.strip() if r.returncode == 0 else None


def _apt_env() -> dict[str, str]:
    env = dict(os.environ)
    env["DEBIAN_FRONTEND"] = "noninteractive"
    env["DEBCONF_NONINTERACTIVE_SEEN"] = "true"
    env["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    return env


# İkinci apt dpkg kilidine takılıp "interrupted" görürse çalışan kurulumun ortasında --configure -a tetiklerdi
_apt_lock: threading.Lock = threading.Lock()


def _apt_upgrade(pkgs: list[str], timeout: float, configure_timeout: float) -> tuple[int, str]:
    with _apt_lock:
        env = _apt_env()
        cmd = [
            "apt-get", "install", "--only-upgrade", "-y",
            "-o", "Dpkg::Options::=--force-confdef",
            "-o", "Dpkg::Options::=--force-confold",
        ] + pkgs
        apt_get = compat.need_cmd("apt-get")
        proc = subprocess.run(cmd, executable=apt_get, capture_output=True, text=True, timeout=timeout, env=env)
        output = proc.stdout.strip() or proc.stderr.strip()
        # Yarım kalmış bir dpkg işlemi apt'yi kilitliyor, önce onu tamamla
        if proc.returncode != 0 and ("--configure -a" in output or "kesintiye" in output or "interrupted" in output):
            subprocess.run(
                ["dpkg", "--configure", "-a"], executable=compat.need_cmd("dpkg"),
                capture_output=True, text=True, timeout=configure_timeout, env=env,
            )
            proc = subprocess.run(cmd, executable=apt_get, capture_output=True, text=True, timeout=timeout, env=env)
            output = proc.stdout.strip() or proc.stderr.strip()
    return proc.returncode, output


def apt_lists_status() -> dict[str, Any]:
    # InRelease dosyalarının mtime'ı sunucunun Last-Modified zamanı; yerel güncelleme anını dizinler gösteriyor
    newest = 0.0
    for d in (_APT_LISTS_DIR, _APT_LISTS_DIR / "partial"):
        try:
            newest = max(newest, d.stat().st_mtime)
        except OSError:
            continue
    if not newest:
        return {"updated_at": None, "age_days": None, "stale": False}
    age = max(0.0, time.time() - newest)
    return {
        "updated_at": datetime.fromtimestamp(newest).isoformat(timespec="seconds"),
        "age_days": int(age // 86400),
        "stale": age > _APT_LISTS_MAX_AGE,
    }


def update_apt_lists() -> dict[str, Any]:
    if not compat.IS_LINUX:
        return {"success": False, "message": "Yalnızca Linux sistemlerde paket listeleri güncellenebilir."}
    try:
        with _apt_lock:
            proc = subprocess.run(
                ["apt-get", "update", "-q"], executable=compat.need_cmd("apt-get"),
                capture_output=True, text=True, timeout=300, env=_apt_env(),
            )
    except compat.CommandNotFound as exc:
        return {"success": False, "message": str(exc)}
    except subprocess.TimeoutExpired:
        logger.warning("apt-get update zaman aşımına uğradı")
        return {"success": False, "message": "Paket listesi güncellemesi zaman aşımına uğradı (300s)."}
    except OSError:
        logger.exception("apt-get update başlatılamadı")
        return {"success": False, "message": "Paket listesi güncelleme komutu çalıştırılamadı."}
    status = apt_lists_status()
    if proc.returncode != 0:
        logger.warning(
            "apt-get update başarısız (kod %s): %s", proc.returncode, (proc.stderr.strip() or proc.stdout.strip())[-2000:],
        )
        return {"success": False, "message": "Paket listeleri güncellenemedi. Ayrıntı sunucu logunda.", "apt_lists": status}
    if proc.stderr.strip():
        logger.warning("apt-get update uyarılarla tamamlandı: %s", proc.stderr.strip()[-2000:])
    else:
        logger.info("apt-get update tamamlandı")
    return {"success": True, "message": "Paket listeleri güncellendi, taramayı yeniden çalıştırabilirsiniz.", "apt_lists": status}


def _latest_findings(pkg: str, server_id: int) -> list[dict[str, Any]]:
    with database.get_connection() as conn:
        row = conn.execute(
            "SELECT scan_results FROM cve_scans WHERE server_id = ? ORDER BY id DESC LIMIT 1",
            (server_id,),
        ).fetchone()
    if not row or not row["scan_results"]:
        return []
    try:
        results: list[dict[str, Any]] = json.loads(row["scan_results"])
    except json.JSONDecodeError:
        return []
    return [r for r in results if r.get("package") == pkg or pkg in (r.get("binaries") or [])]


def _fix_gate(pkg: str, server_id: int) -> tuple[list[str], str | None]:
    findings = _latest_findings(pkg, server_id)
    verified = [f for f in findings if f.get("confidence") == "verified"]
    if not verified:
        if findings:
            return [], f"'{pkg}' için doğrulanmış bulgu yok: {findings[0].get('confidence_reason') or 'eşleşme belirsiz.'}"
        return [], f"'{pkg}' için son taramada doğrulanmış bir bulgu yok, önce tarama yapın."

    binaries = sorted({str(b) for f in verified for b in (f.get("binaries") or []) if re.match(_PKG_NAME_RE, str(b))})
    if not binaries:
        return [], f"'{pkg}' için güncellenecek ikili paket bulunamadı."
    required = max((str(f["fixed_version"]) for f in verified), key=cmp_to_key(_deb_cmp))
    checked = sorted({str(b) for f in verified for b in (f.get("check_binaries") or binaries)} & set(binaries))

    candidates = _apt_candidates(checked)
    for b in checked:
        cand = candidates.get(b)
        if not cand:
            return [], f"'{b}' için apt'de aday sürüm yok, düzeltilmiş sürüm ({required}) kurulamaz."
        if _deb_cmp(_strip_binnmu(cand), required) < 0:
            return [], f"apt'de düzeltilmiş sürüm yok: '{b}' aday sürümü {cand}, gereken en az {required}."
    return binaries, None


def _apt_simulate(pkgs: list[str]) -> str | None:
    env = _apt_env()
    env["LC_ALL"] = "C"
    try:
        proc = subprocess.run(
            ["apt-get", "-s", "install", "--only-upgrade", *pkgs], executable=compat.need_cmd("apt-get"),
            capture_output=True, text=True, timeout=120, env=env,
        )
    except compat.CommandNotFound as exc:
        return str(exc)
    except subprocess.TimeoutExpired:
        logger.warning("apt simülasyonu zaman aşımına uğradı: %s", pkgs)
        return "apt simülasyonu zaman aşımına uğradı, güncelleme yapılmadı."
    except OSError:
        logger.exception("apt simülasyonu başlatılamadı: %s", pkgs)
        return "apt simülasyonu çalıştırılamadı, güncelleme yapılmadı."
    if proc.returncode != 0:
        logger.warning(
            "apt simülasyonu başarısız (kod %s): %s\n%s",
            proc.returncode, pkgs, (proc.stderr.strip() or proc.stdout.strip())[-2000:],
        )
        return "apt simülasyonu başarısız oldu, güncelleme yapılmadı. Ayrıntı sunucu logunda."
    removed = [ln.split()[1] for ln in proc.stdout.splitlines() if ln.startswith("Remv ") and len(ln.split()) > 1]
    if removed:
        logger.warning("apt simülasyonu paket kaldırmayı gerektiriyor, güncelleme iptal: %s", removed)
        shown = ", ".join(removed[:5]) + (f" ve {len(removed) - 5} paket daha" if len(removed) > 5 else "")
        return f"Güncelleme şu paketleri kaldıracağı için iptal edildi: {shown}"
    return None


def _record_fix(server_id: int, pkg: str, status: str, old_v: str, new_v: str, output: str) -> None:
    try:
        with database.get_connection() as conn:
            conn.execute(
                "INSERT INTO cve_fix_history (server_id, package, status, old_version, new_version, output) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (server_id, pkg, status, old_v, new_v, output[:1000]),
            )
    except Exception:
        pass


def _primary_binary(pkg: str, binaries: list[str]) -> str:
    return pkg if pkg in binaries else binaries[0]


def fix_cve_package(package: str, server_id: int = 1) -> dict[str, Any]:
    if not compat.IS_LINUX:
        return {"success": False, "message": "Yalnızca Linux sistemlerde paket güncellemesi yapılabilir."}

    pkg = package.strip().split(":", 1)[0]
    if not re.match(_PKG_NAME_RE, pkg):
        return {"success": False, "message": "Geçersiz paket adı."}

    binaries, reason = _fix_gate(pkg, server_id)
    if reason is None:
        reason = _apt_simulate(binaries)
    if reason is not None:
        _record_fix(server_id, pkg, "rejected", "", "", reason)
        return {"success": False, "upgraded": False, "status": "rejected", "package": pkg, "message": reason}

    primary = _primary_binary(pkg, binaries)
    old_version = _installed_version(primary, 10) or ""
    try:
        returncode, output = _apt_upgrade(binaries, timeout=180, configure_timeout=90)
    except compat.CommandNotFound as exc:
        return {"success": False, "message": str(exc)}
    except subprocess.TimeoutExpired:
        return {"success": False, "message": "Paket güncellemesi zaman aşımına uğradı (180s)."}
    except Exception:
        logger.exception("apt güncellemesi başlatılamadı: %s", pkg)
        return {"success": False, "message": "Paket güncelleme komutu çalıştırılamadı."}

    current = _installed_version(primary, 10)
    new_version = current if current is not None else old_version
    upgraded = (new_version != old_version) and bool(new_version)

    if upgraded:
        try:
            with database.get_connection() as conn:
                conn.execute("DELETE FROM cve_package_cache WHERE pkg_name = ?", (pkg,))
        except Exception:
            pass

    if upgraded:
        status = "upgraded"
        msg = f"'{pkg}' paketi başarıyla güncellendi ({old_version} -> {new_version})."
    elif returncode == 0:
        status = "unchanged"
        msg = f"'{pkg}' için depoda daha yeni bir sürüm bulunamadı veya paket zaten en son sürümde."
    else:
        status = "error"
        msg = f"'{pkg}' paketi güncellenirken hata oluştu."

    _record_fix(server_id, pkg, status, old_version, new_version, output)

    return {
        "success": upgraded or returncode == 0,
        "upgraded": upgraded,
        "status": status,
        "package": pkg,
        "binaries": binaries,
        "old_version": old_version,
        "new_version": new_version,
        "message": msg,
        "output": output[:600],
    }


def fix_cve_batch(packages: list[str], server_id: int = 1) -> dict[str, Any]:
    if not compat.IS_LINUX:
        return {"success": False, "message": "Yalnızca Linux sistemlerde paket güncellemesi yapılabilir."}

    valid_pkgs: list[str] = []
    for p in packages:
        p_clean = str(p).strip().split(":", 1)[0]
        if re.match(_PKG_NAME_RE, p_clean) and p_clean not in valid_pkgs:
            valid_pkgs.append(p_clean)

    if not valid_pkgs:
        return {"success": False, "message": "Güncellenecek geçerli paket bulunamadı."}

    allowed: dict[str, list[str]] = {}
    skipped: list[dict[str, str]] = []
    for pkg in valid_pkgs:
        binaries, reason = _fix_gate(pkg, server_id)
        if reason is None:
            allowed[pkg] = binaries
        else:
            skipped.append({"package": pkg, "status": "skipped", "message": reason})
            _record_fix(server_id, pkg, "rejected", "", "", reason)

    if not allowed:
        return {
            "success": False,
            "skipped": skipped,
            "message": "Doğrulanmış ve depoda düzeltilmiş sürümü olan paket yok, güncelleme yapılmadı.",
        }

    all_binaries = sorted({b for bins in allowed.values() for b in bins})
    sim_error = _apt_simulate(all_binaries)
    if sim_error is not None:
        for pkg in allowed:
            _record_fix(server_id, pkg, "rejected", "", "", sim_error)
        return {"success": False, "skipped": skipped, "message": sim_error}

    primaries = {pkg: _primary_binary(pkg, bins) for pkg, bins in allowed.items()}
    old_versions = {pkg: _installed_version(primaries[pkg], 5) or "" for pkg in allowed}
    try:
        _, output = _apt_upgrade(all_binaries, timeout=300, configure_timeout=120)
    except compat.CommandNotFound as exc:
        return {"success": False, "message": str(exc)}
    except subprocess.TimeoutExpired:
        return {"success": False, "message": "Toplu güncelleme zaman aşımına uğradı (300s)."}
    except Exception:
        logger.exception("Toplu apt güncellemesi başlatılamadı: %s", all_binaries)
        return {"success": False, "message": "Toplu paket güncellemesi başlatılamadı."}

    upgraded: list[dict[str, str]] = []
    unchanged: list[dict[str, str]] = []

    for pkg in allowed:
        old_v = old_versions[pkg]
        current = _installed_version(primaries[pkg], 5)
        new_v = current if current is not None else old_v
        is_upgraded = new_v != old_v and bool(new_v)
        if is_upgraded:
            upgraded.append({"package": pkg, "old_version": old_v, "new_version": new_v})
            try:
                with database.get_connection() as conn:
                    conn.execute("DELETE FROM cve_package_cache WHERE pkg_name = ?", (pkg,))
            except Exception:
                pass
        else:
            unchanged.append({"package": pkg, "old_version": old_v, "new_version": new_v, "version": old_v})
        _record_fix(server_id, pkg, "upgraded" if is_upgraded else "unchanged", old_v, new_v, output)

    results: list[dict[str, Any]] = [
        {
            "package": u["package"],
            "status": "upgraded",
            "old_version": u["old_version"],
            "new_version": u["new_version"],
            "message": f"{u['old_version']} -> {u['new_version']} sürümüne güncellendi.",
        }
        for u in upgraded
    ] + [
        {
            "package": uc["package"],
            "status": "unchanged",
            "old_version": uc["old_version"],
            "new_version": uc["new_version"],
            "message": "Depoda daha yeni bir sürüm yok, paket zaten en son sürümde.",
        }
        for uc in unchanged
    ] + [dict(s) for s in skipped]

    msg = f"{len(upgraded)} paket başarıyla güncellendi."
    if unchanged:
        msg += f" {len(unchanged)} paket için depoda yeni sürüm bulunamadı."
    if skipped:
        msg += f" {len(skipped)} paket doğrulanmadığı için atlandı."

    return {
        "success": True,
        "upgraded": upgraded,
        "unchanged": unchanged,
        "skipped": skipped,
        "results": results,
        "total": len(valid_pkgs),
        "total_requested": len(valid_pkgs),
        "total_upgraded": len(upgraded),
        "upgraded_count": len(upgraded),
        "unchanged_count": len(unchanged),
        "skipped_count": len(skipped),
        "error_count": 0,
        "message": msg,
        "output": output[:600],
    }


def get_cve_fix_history(server_id: int | None = None, limit: int = 50) -> list[dict[str, Any]]:
    with database.get_connection() as conn:
        q = "SELECT id, server_id, package, status, old_version, new_version, output, created_at FROM cve_fix_history"
        if server_id is not None:
            rows = conn.execute(f"{q} WHERE server_id = ? ORDER BY created_at DESC LIMIT ?", (server_id, limit)).fetchall()
        else:
            rows = conn.execute(f"{q} ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]

