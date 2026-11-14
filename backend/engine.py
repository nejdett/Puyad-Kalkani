from __future__ import annotations

import json
import logging
import re
import shlex
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, cast

import compat
from fileutil import atomic_write_json

logger = logging.getLogger(__name__)

RULES_FILE: Path = Path(__file__).parent / "rules.json"
IGNORED_FILE: Path = Path(__file__).parent / "ignored.json"

REQUIRED_RULE_FIELDS: set[str] = {"id", "name", "category", "severity", "check_command", "fix_command", "description"}
RULE_ID_RE = re.compile(r"^[a-z0-9_]+$")
SCAN_SEMAPHORE = threading.Semaphore(1)

ALLOWED_CMD_PREFIXES: list[str] = [
    "grep", "awk", "sed", "find", "stat", "dpkg", "dpkg-reconfigure", "systemctl",
    "ufw", "iptables", "sysctl", "mount", "ss", "chown", "chmod",
    "passwd", "useradd", "usermod", "userdel", "apt-get", "auditctl",
    "journalctl", "python3",
    "echo", "tee", "cp", "printf",
    "xargs", "test", "true", "false", "source",
    "print", "tr", "head", "tail", "cut", "sort", "uniq", "wc",
    "cat",
]

USER_BLOCKED_PREFIXES: set[str] = {
    "python", "python2", "python3", "perl", "ruby", "lua", "php", "node",
    "sh", "bash", "dash", "zsh", "ksh",
    "chown", "chmod", "passwd", "useradd", "usermod", "userdel",
    "cp", "tee", "xargs", "source", "apt-get",
    "nc", "netcat", "ncat", "socat", "rcat",
}

SHELL_BUILTINS: set[str] = {
    "[", "]", "if", "then", "else", "elif", "fi",
    "for", "while", "until", "do", "done", "in",
    "case", "esac", "select", "time", "function",
    "{", "}", "exit",
}

DANGEROUS_PATTERNS: list[str] = [
    r"rm\s+-rf\s+/",
    r"mkfs",
    r"dd\s+if=",
    r":\(\)\{\s*:\|:&\s*\};:",
    r":(){ :|:& };:",
    r"curl\s+.*\|\s*(?:ba)?sh",
    r"wget\s+.*\|\s*(?:ba)?sh",
    r"\b(?:nc|ncat|netcat|socat|rcat)\b",
    r"\bsystem\s*\(",
    r"awk\b.*?\|\s*[\"']?\s*(?:/bin/|/usr/bin/)?(?:ba)?sh\b",
    r"/inet/(?:tcp|udp)/",
    r"\|\s*getline\b",
    r"getline\b.*?\|",
    # Possessive — ters bölü dizisinde üstel geri izlemeyi önlüyor
    r"s([^\w\s\"'\\])(?:\\.|(?!\1).)*+\1(?:\\.|(?!\1).)*+\1[0-9gipmIM]*e[0-9gipmIM]*(?:[\"'\s;)]|$)",
    # GNU sed ters bölüyü de ayraç kabul ediyor, o zaman kaçış yok
    r"s\\[^\\]*+\\[^\\]*+\\[0-9gipmIM]*e[0-9gipmIM]*(?:[\"'\s;)]|$)",
    r"\bsed\b.*?(?:[\"'\s;]|\A)(?:[0-9$,]*\s*)e\s+[^\'\"]",
    r"(?:/systemd/system/|/systemd/user/).*?\.(?:service|timer|socket)",
    r"\bExec(?:Start|Stop|Reload|StartPre|StartPost)\s*=",
    r"(?:sed|echo|printf|cat|tee|cp)\b.*?(?:/etc/cron|/var/spool/cron)",
    r"(?:sed|echo|printf|cat|tee|cp)\b.*?(?:/etc/profile|/etc/bash\.bashrc|/etc/environment|\.bashrc|\.profile|\.bash_profile|/etc/rc\.local|/etc/init\.d/|/etc/ld\.so)",
    r"\bfind\b.*?-(?:exec|execdir|ok|okdir)\b",
    r"-(?:exec|execdir|ok|okdir)\s+",
    r"/dev/(?:tcp|udp)/",
    r"\b(?:mkfifo|mknod)\b",
    r"\b(?:ba)?sh\s+-i\b",
    r"-(?:e|c)\s+[\"']?(?:/bin/|/usr/bin/)?(?:ba)?sh\b",
    r"\b(?:/bin/|/usr/bin/)(?:ba)?sh\b",
    r"\b(?:/bin/|/usr/bin/)(?:zsh|dash|ksh)\b",
    r"\bimport\s+(?:socket|pty)\b",
    r"\b(?:pty\.spawn|socket\.socket)\b",
    r"NOPASSWD\s*:",
    r"\bbase64\s+-d.*?\|\s*(?:ba)?sh\b",
    r"\bopenssl\b.*?\|\s*(?:ba)?sh\b",
]

# Kalıpların bir kısmı karesel, uzunluk sınırı süreyi sınırlı tutuyor
MAX_COMMAND_LENGTH: int = 4096
# bash satır sonunu ";" gibi yorumluyor — doğrulayıcı yalnızca ilk satırı görüyordu
_LINE_BREAK_CHARS: tuple[str, ...] = ("\n", "\r", "\x00")
SHELL_METACHARS: set[str] = {
    "|", ";", ">", "<", ">>", "<<", "`", "$(", "${",
    "2>", "1>", "2>>", "1>>", "2>&1", "1>&1",
}


def _split_shell_segments(command: str) -> list[str]:
    segments: list[str] = []
    cur: list[str] = []
    in_single = False
    in_double = False
    escaped = False
    i = 0
    while i < len(command):
        c = command[i]
        if escaped:
            cur.append(c)
            escaped = False
            i += 1
            continue
        if c == "\\" and not in_single:
            escaped = True
            cur.append(c)
            i += 1
            continue
        if c == "'" and not in_double:
            in_single = not in_single
            cur.append(c)
            i += 1
            continue
        if c == '"' and not in_single:
            in_double = not in_double
            cur.append(c)
            i += 1
            continue
        if in_single or in_double:
            cur.append(c)
            i += 1
            continue
        if command[i:i+2] in ("&&", "||"):
            segments.append("".join(cur).strip())
            cur = []
            i += 2
            continue
        if c in (";", "|", "&"):
            segments.append("".join(cur).strip())
            cur = []
            i += 1
            continue
        cur.append(c)
        i += 1
    if cur:
        segments.append("".join(cur).strip())
    return [s for s in segments if s]


def _extract_first_tokens(command: str) -> list[str]:
    tokens: list[str] = []
    for part in _split_shell_segments(command):
        part = part.strip()
        if not part:
            continue
        try:
            words = shlex.split(part)
        except ValueError:
            words = part.split()
        if not words:
            continue
        if words[0] in ("&&", "||", "!"):
            words = words[1:]
        if words:
            tokens.append(words[0])
    return tokens


def validate_command(command: str) -> tuple[bool, str]:
    if not command or not command.strip():
        return False, "Komut boş olamaz"
    if len(command) > MAX_COMMAND_LENGTH:
        return False, f"Komut en fazla {MAX_COMMAND_LENGTH} karakter olabilir"
    if any(c in command for c in _LINE_BREAK_CHARS):
        return False, "Komutta satır sonu veya NUL karakteri olamaz"
    for pat in DANGEROUS_PATTERNS:
        if re.search(pat, command):
            return False, f"Tehlikeli kalıp: {pat}"
    if command.strip().startswith("python3"):
        return True, "OK"
    for t in _extract_first_tokens(command):
        tc = t.strip("()[]{}'\";:,")
        if not tc:
            continue
        if "=" in tc or "$" in tc:
            continue
        if tc in ALLOWED_CMD_PREFIXES or tc.rstrip(")") in SHELL_BUILTINS:
            continue
        return False, f"İzin verilmeyen komut: {t}"
    return True, "OK"


def _user_first_token_error(first: str, not_allowed_msg: str) -> str | None:
    if first in SHELL_BUILTINS:
        return f"Shell builtin izin verilmez: {first}"
    if first in USER_BLOCKED_PREFIXES:
        return f"Bu komut kullanıcı kurallarında yasak: {first}"
    if first not in ALLOWED_CMD_PREFIXES:
        return f"{not_allowed_msg}: {first}"
    return None


def validate_user_command(command: str) -> tuple[bool, str]:
    if not command or not command.strip():
        return False, "Komut boş olamaz"
    if len(command) > MAX_COMMAND_LENGTH:
        return False, f"Komut en fazla {MAX_COMMAND_LENGTH} karakter olabilir"
    if any(c in command for c in _LINE_BREAK_CHARS):
        return False, "Komutta satır sonu veya NUL karakteri olamaz"

    for pat in DANGEROUS_PATTERNS:
        if re.search(pat, command):
            return False, f"Tehlikeli kalıp: {pat}"

    for mc in SHELL_METACHARS:
        if mc == "|":
            if re.search(r"(?<!\|)\|(?!\|)", command):
                return False, "Shell metacharacter reddedildi: '|' (pipe/redirect/chain)"
            continue
        if mc in command:
            return False, f"Shell metacharacter reddedildi: '{mc}' (pipe/redirect/chain)"

    if "&&" in command or "||" in command:
        chain_segs: list[str] = re.split(r"\s*(?:&&|\|\|)\s*", command)
        if len(chain_segs) > 1:
            for seg in chain_segs:
                seg = seg.strip()
                if not seg:
                    return False, "Boş chain segment'i (&& veya || sonrası)"
                try:
                    seg_tokens: list[str] = shlex.split(seg)
                except ValueError as e:
                    logger.warning("Chain segment'i ayrıştırılamadı: %s", e)
                    return False, "Zincirdeki bir komut ayrıştırılamadı, tırnak ve kaçış karakterlerini kontrol edin."
                if not seg_tokens:
                    return False, "Boş chain segment'i"
                err = _user_first_token_error(seg_tokens[0], "Chain segment'inde izin verilmeyen komut")
                if err:
                    return False, err
            return True, "OK"

    try:
        tokens: list[str] = shlex.split(command)
    except ValueError as e:
        logger.warning("Komut ayrıştırılamadı: %s", e)
        return False, "Komut ayrıştırılamadı, kapanmamış tırnak olabilir."

    if not tokens:
        return False, "Komut boş olamaz"

    err = _user_first_token_error(tokens[0], "İzin verilmeyen komut")
    if err:
        return False, err
    return True, "OK"


def _load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return default


def _save_json(path: Path, data: Any) -> None:
    try:
        atomic_write_json(path, data)
    except OSError:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)


# Dosya yazımı atomik ama oku-değiştir-yaz değil — eşzamanlı iki değişiklikten biri kaybolmasın
_rules_lock: threading.Lock = threading.Lock()


def load_rules() -> list[dict[str, Any]]:
    return cast(list[dict[str, Any]], _load_json(RULES_FILE, []))


def save_rules(rules: list[dict[str, Any]]) -> None:
    _save_json(RULES_FILE, rules)


def load_ignored() -> list[str]:
    return cast(list[str], _load_json(IGNORED_FILE, []))


def save_ignored(ignored: list[str]) -> None:
    _save_json(IGNORED_FILE, ignored)


def run_command(command: str | list[str], timeout: int = 30) -> dict[str, Any]:
    timeout = max(1, min(timeout, 300))
    if isinstance(command, list):
        cmd_str: str = " ".join(command)
        cmd_args: list[str] = command
    else:
        cmd_str = command
        cmd_args = ["/bin/bash", "-c", command]

    valid, msg = validate_command(cmd_str)
    if not valid:
        return {"success": False, "stdout": "", "stderr": f"Güvenlik hatası: {msg}", "returncode": -1}

    if not compat.IS_LINUX:
        return {
            "success": False,
            "stdout": "",
            "stderr": compat.unsupported("Komut çalıştırma"),
            "returncode": -1,
        }

    try:
        result: subprocess.CompletedProcess[str] = subprocess.run(
            cmd_args, shell=False, capture_output=True, text=True, timeout=timeout, env=compat.shell_env()
        )
        return {
            "success": result.returncode == 0,
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
            "returncode": result.returncode,
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "stdout": "TIMEOUT", "stderr": "Komut zaman aşımına uğradı.", "returncode": -1}
    except Exception:
        logger.exception("Komut başlatılamadı")
        return {"success": False, "stdout": "", "stderr": "Komut başlatılamadı.", "returncode": -1}


def _rule_result(rule: dict[str, Any], status: str, output: str) -> dict[str, Any]:
    return {
        "id": rule["id"],
        "name": rule["name"],
        "category": rule["category"],
        "severity": rule["severity"],
        "description": rule["description"],
        "status": status,
        "output": output,
    }


def check_rule(rule: dict[str, Any]) -> dict[str, Any]:
    check_cmd = rule.get("check_command", "")
    if not check_cmd:
        return {
            "id": rule.get("id", "unknown"),
            "name": rule.get("name", ""),
            "category": rule.get("category", ""),
            "severity": rule.get("severity", ""),
            "description": rule.get("description", ""),
            "status": "warning",
            "output": "check_command tanımlı değil",
        }
    result: dict[str, Any] = run_command(check_cmd, timeout=30)
    last_line: str = result["stdout"].strip().splitlines()[-1].strip() if result["stdout"].strip() else ""
    status = "ok" if last_line == "OK" else "warning"
    return _rule_result(rule, status, result["stdout"] or result["stderr"])


def check_single_rule(rule_id: str) -> dict[str, Any] | None:
    rules: list[dict[str, Any]] = load_rules()
    rule: dict[str, Any] | None = next((r for r in rules if r["id"] == rule_id), None)
    return check_rule(rule) if rule else None


def scan_all() -> list[dict[str, Any]]:
    if not SCAN_SEMAPHORE.acquire(blocking=False):
        raise RuntimeError("Başka bir tarama zaten çalışıyor.")
    try:
        rules: list[dict[str, Any]] = load_rules()
        ignored: list[str] = load_ignored()
        active_rules: list[dict[str, Any]] = [r for r in rules if r["id"] not in ignored]
        results_map: dict[str, dict[str, Any]] = {}
        workers = min(4, max(1, len(active_rules)))

        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_rule = {executor.submit(check_rule, rule): rule for rule in active_rules}
            for future in as_completed(future_to_rule):
                rule = future_to_rule[future]
                try:
                    result = future.result()
                except Exception:
                    logger.exception("Kural kontrolü başarısız: %s", rule.get("id"))
                    result = _rule_result(rule, "warning", "Kural kontrolü beklenmeyen bir hatayla durdu.")
                results_map[rule["id"]] = result

        return [results_map[r["id"]] for r in active_rules if r["id"] in results_map]
    finally:
        SCAN_SEMAPHORE.release()


def fix_rule(rule_id: str) -> dict[str, Any]:
    rules: list[dict[str, Any]] = load_rules()
    rule: dict[str, Any] | None = next((r for r in rules if r["id"] == rule_id), None)
    if not rule:
        return {"success": False, "message": f"'{rule_id}' ID'li kural bulunamadı.", "output": ""}

    fix_cmd = rule.get("fix_command", "")
    if not fix_cmd:
        return {"success": False, "message": "fix_command tanımlı değil.", "output": ""}

    result = run_command(fix_cmd, timeout=120)
    return {
        "success": result["success"],
        "message": "Düzeltme başarıyla uygulandı." if result["success"] else "Düzeltme sırasında hata oluştu.",
        "output": result["stdout"] or result["stderr"],
    }


def ignore_rule(rule_id: str) -> dict[str, Any]:
    with _rules_lock:
        rules: list[dict[str, Any]] = load_rules()
        if not any(r["id"] == rule_id for r in rules):
            return {"success": False, "message": f"'{rule_id}' ID'li kural bulunamadı."}
        ignored: list[str] = load_ignored()
        if rule_id not in ignored:
            ignored.append(rule_id)
            save_ignored(ignored)
        return {"success": True, "message": f"'{rule_id}' kuralı görmezden gelinenler listesine eklendi."}


def unignore_rule(rule_id: str) -> dict[str, Any]:
    with _rules_lock:
        ignored: list[str] = load_ignored()
        if rule_id not in ignored:
            return {"success": False, "message": f"'{rule_id}' zaten görmezden gelinmiyor."}
        ignored.remove(rule_id)
        save_ignored(ignored)
        return {"success": True, "message": f"'{rule_id}' kuralı görmezden gelinenler listesinden çıkarıldı."}


def _validate_rule_fields(rule: dict[str, Any]) -> tuple[bool, str]:
    missing = REQUIRED_RULE_FIELDS - set(rule.keys())
    if missing:
        return False, f"Eksik alanlar: {', '.join(sorted(missing))}"
    empty = [k for k in REQUIRED_RULE_FIELDS if not str(rule.get(k, "")).strip()]
    if empty:
        return False, f"Boş alanlar: {', '.join(empty)}"
    if not RULE_ID_RE.match(str(rule.get("id", ""))):
        return False, "ID yalnızca küçük harf, rakam ve alt çizgi içerebilir (a-z0-9_)."
    return True, "OK"


def add_rule(rule: dict[str, Any]) -> dict[str, Any]:
    with _rules_lock:
        ok, msg = _validate_rule_fields(rule)
        if not ok:
            return {"success": False, "message": msg}
        rules: list[dict[str, Any]] = load_rules()
        if any(r["id"] == rule["id"] for r in rules):
            return {"success": False, "message": f"'{rule['id']}' ID'li bir kural zaten mevcut."}

        for field in ["check_command", "fix_command"]:
            valid, err = validate_user_command(str(rule[field]))
            if not valid:
                return {"success": False, "message": f"{field} güvenli değil: {err}"}

        rules.append(rule)
        save_rules(rules)
        return {"success": True, "message": f"'{rule['name']}' kuralı başarıyla eklendi."}


def update_rule(rule_id: str, updates: dict[str, Any]) -> dict[str, Any]:
    with _rules_lock:
        rules: list[dict[str, Any]] = load_rules()
        rule: dict[str, Any] | None = next((r for r in rules if r["id"] == rule_id), None)
        if not rule:
            return {"success": False, "message": f"'{rule_id}' ID'li kural bulunamadı."}

        if "id" in updates and updates["id"] != rule_id:
            if any(r["id"] == updates["id"] for r in rules):
                return {"success": False, "message": f"'{updates['id']}' ID'li bir kural zaten mevcut."}
            if not RULE_ID_RE.match(str(updates["id"])):
                return {"success": False, "message": "ID yalnızca küçük harf, rakam ve alt çizgi içerebilir."}

        for field in ["check_command", "fix_command"]:
            if field in updates and updates[field] is not None:
                valid, msg = validate_user_command(str(updates[field]))
                if not valid:
                    return {"success": False, "message": f"{field} güvenli değil: {msg}"}

        rule.update({k: v for k, v in updates.items() if v is not None})
        save_rules(rules)
        return {"success": True, "message": f"'{rule['name']}' kuralı güncellendi."}


def delete_rule(rule_id: str) -> dict[str, Any]:
    with _rules_lock:
        rules: list[dict[str, Any]] = load_rules()
        new_rules: list[dict[str, Any]] = [r for r in rules if r["id"] != rule_id]
        if len(new_rules) == len(rules):
            return {"success": False, "message": f"'{rule_id}' ID'li kural bulunamadı."}
        save_rules(new_rules)
        return {"success": True, "message": f"'{rule_id}' kuralı başarıyla silindi."}
