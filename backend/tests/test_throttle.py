import sys
import time
from pathlib import Path
from unittest.mock import MagicMock, patch
sys.path.insert(0, str(Path(__file__).parent.parent))
from throttle import DEFAULT_RULES_CONFIG, RateLimiter, RateLimitRule, _categorize_path, _get_client_ip, _get_forwarded_ip

class TestRateLimitRule:

    def test_rule_creation(self):
        rule = RateLimitRule(max_requests=10, window_seconds=60)
        assert rule.max_requests == 10
        assert rule.window_seconds == 60
        assert rule.block_seconds == 300

    def test_rule_with_custom_block(self):
        rule = RateLimitRule(max_requests=5, window_seconds=60, block_seconds=600)
        assert rule.block_seconds == 600

class TestRateLimiterBasic:

    def setup_method(self):
        self.limiter = RateLimiter({})

    def test_first_request_allowed(self):
        allowed, info = self.limiter.check('192.168.1.1', 'api')
        assert allowed is True
        assert info['remaining'] >= 0

    def test_multiple_requests_within_limit(self):
        for _ in range(5):
            allowed, info = self.limiter.check('192.168.1.1', 'api')
            assert allowed is True

    def test_limit_exceeded_blocked(self):
        for _ in range(5):
            self.limiter.check('192.168.1.1', 'auth')
        allowed, info = self.limiter.check('192.168.1.1', 'auth')
        assert allowed is False
        assert info['blocked'] is True
        assert info['retry_after'] > 0

    def test_different_ips_independent(self):
        for _ in range(5):
            self.limiter.check('192.168.1.1', 'auth')
        allowed, info = self.limiter.check('192.168.1.2', 'auth')
        assert allowed is True

    def test_different_categories_independent(self):
        for _ in range(5):
            self.limiter.check('192.168.1.1', 'auth')
        allowed, info = self.limiter.check('192.168.1.1', 'api')
        assert allowed is True

    def test_reset_specific_ip(self):
        for _ in range(5):
            self.limiter.check('192.168.1.1', 'auth')
        self.limiter.reset('192.168.1.1')
        allowed, info = self.limiter.check('192.168.1.1', 'auth')
        assert allowed is True

    def test_reset_all(self):
        for _ in range(5):
            self.limiter.check('192.168.1.1', 'auth')
            self.limiter.check('192.168.1.2', 'auth')
        self.limiter.reset()
        allowed1, _ = self.limiter.check('192.168.1.1', 'auth')
        allowed2, _ = self.limiter.check('192.168.1.2', 'auth')
        assert allowed1 is True
        assert allowed2 is True

    def test_remaining_decreases(self):
        _, info1 = self.limiter.check('192.168.1.1', 'auth')
        _, info2 = self.limiter.check('192.168.1.1', 'auth')
        assert info2['remaining'] < info1['remaining']

    def test_stats_returns_dict(self):
        self.limiter.check('192.168.1.1', 'api')
        stats = self.limiter.get_stats()
        assert isinstance(stats, dict)
        assert '192.168.1.1' in stats

    def test_set_rule(self):
        self.limiter.set_rule('custom', max_requests=3, window_seconds=10)
        for _ in range(3):
            self.limiter.check('192.168.1.1', 'custom')
        allowed, _ = self.limiter.check('192.168.1.1', 'custom')
        assert allowed is False

class TestConfigIntegration:

    def test_reload_from_config_loads_defaults(self):
        limiter = RateLimiter({})
        rules = limiter.get_current_rules()
        assert rules['enabled'] is True
        assert 'auth' in rules['rules']
        assert 'api' in rules['rules']
        assert 'heavy' in rules['rules']
        assert 'export' in rules['rules']

    @patch('config.load_config')
    def test_reload_from_config_custom_values(self, mock_load):
        mock_load.return_value = {'RATE_LIMIT_ENABLED': True, 'RATE_LIMIT_AUTH_MAX': 3, 'RATE_LIMIT_AUTH_WINDOW': 30, 'RATE_LIMIT_AUTH_BLOCK': 600, 'RATE_LIMIT_API_MAX': 200, 'RATE_LIMIT_API_WINDOW': 120}
        limiter = RateLimiter({})
        limiter.reload_from_config()
        rules = limiter.get_current_rules()
        assert rules['rules']['auth']['max_requests'] == 3
        assert rules['rules']['auth']['window_seconds'] == 30
        assert rules['rules']['auth']['block_seconds'] == 600
        assert rules['rules']['api']['max_requests'] == 200
        assert rules['rules']['api']['window_seconds'] == 120

    @patch('config.load_config')
    def test_rate_limiting_disabled(self, mock_load):
        mock_load.return_value = {'RATE_LIMIT_ENABLED': False}
        limiter = RateLimiter({})
        limiter.reload_from_config()
        for _ in range(100):
            allowed, info = limiter.check('192.168.1.1', 'auth')
            assert allowed is True
            assert info.get('disabled') is True

    @patch('config.load_config')
    def test_reload_returns_current_rules(self, mock_load):
        mock_load.return_value = {'RATE_LIMIT_ENABLED': True, 'RATE_LIMIT_AUTH_MAX': 10}
        limiter = RateLimiter({})
        result = limiter.reload_from_config()
        assert 'enabled' in result
        assert 'rules' in result
        assert result['rules']['auth']['max_requests'] == 10

    def test_default_rules_config_has_all_categories(self):
        assert 'auth' in DEFAULT_RULES_CONFIG
        assert 'api' in DEFAULT_RULES_CONFIG
        assert 'heavy' in DEFAULT_RULES_CONFIG
        assert 'export' in DEFAULT_RULES_CONFIG
        assert 'telegram' in DEFAULT_RULES_CONFIG
        for cat, cfg in DEFAULT_RULES_CONFIG.items():
            assert 'max' in cfg
            assert 'window' in cfg
            assert 'block' in cfg

class TestBruteForceProtection:

    def setup_method(self):
        self.limiter = RateLimiter({})

    def test_brute_force_blocked_after_limit(self):
        attacker_ip = '10.0.0.66'
        for i in range(5):
            allowed, info = self.limiter.check(attacker_ip, 'auth')
            assert allowed is True, f'Deneme {i + 1} izin verilmeli'
        allowed, info = self.limiter.check(attacker_ip, 'auth')
        assert allowed is False
        assert info['blocked'] is True
        assert info['retry_after'] >= 300

    def test_brute_force_different_paths_same_ip(self):
        ip = '10.0.0.99'
        for _ in range(3):
            self.limiter.check(ip, 'auth')
        for _ in range(2):
            self.limiter.check(ip, 'auth')
        allowed, _ = self.limiter.check(ip, 'auth')
        assert allowed is False

class TestDosProtection:

    def setup_method(self):
        self.limiter = RateLimiter({})

    def test_api_limit_enforced(self):
        ip = '10.0.0.100'
        for _ in range(120):
            allowed, _ = self.limiter.check(ip, 'api')
            assert allowed is True
        allowed, info = self.limiter.check(ip, 'api')
        assert allowed is False
        assert info['blocked'] is True

    def test_heavy_endpoint_stricter(self):
        ip = '10.0.0.101'
        for _ in range(20):
            self.limiter.check(ip, 'heavy')
        allowed, _ = self.limiter.check(ip, 'heavy')
        assert allowed is False
        allowed, _ = self.limiter.check(ip, 'api')
        assert allowed is True

class TestCategorizePath:

    def test_auth_path(self):
        assert _categorize_path('/api/auth/login') == 'auth'
        assert _categorize_path('/api/auth/change-password') == 'auth'

    def test_case_insensitive_path(self):
        assert _categorize_path('/api/AUTH/login') == 'auth'
        assert _categorize_path('/api/Auth/login') == 'auth'
        assert _categorize_path('/API/SCAN') == 'heavy'

    def test_telegram_paths(self):
        assert _categorize_path('/api/telegram/test') == 'telegram'
        assert _categorize_path('/api/telegram/approve/abc123') == 'telegram'
        assert _categorize_path('/api/telegram/reject/abc123') == 'telegram'
        assert _categorize_path('/api/telegram/pending') == 'telegram'

    def test_heavy_paths(self):
        assert _categorize_path('/api/scan') == 'heavy'
        assert _categorize_path('/api/cve/scan') == 'heavy'
        assert _categorize_path('/api/forensic/trigger') == 'heavy'
        assert _categorize_path('/api/network/topology') == 'heavy'

    def test_export_paths(self):
        assert _categorize_path('/api/report/pdf') == 'export'

    def test_default_api(self):
        assert _categorize_path('/api/config') == 'api'
        assert _categorize_path('/api/servers') == 'api'
        assert _categorize_path('/api/rules') == 'api'

class TestGetClientIp:

    def test_x_forwarded_for(self):
        request = MagicMock()
        request.headers = {'X-Forwarded-For': '1.2.3.4, 5.6.7.8'}
        request.client.host = '127.0.0.1'
        assert _get_client_ip(request) == '127.0.0.1'
        assert _get_forwarded_ip(request) == '5.6.7.8'

    def test_x_forwarded_for_untrusted_spoof(self):
        request = MagicMock()
        request.headers = {'X-Forwarded-For': '1.2.3.4, 5.6.7.8'}
        request.client.host = '203.0.113.99'
        assert _get_client_ip(request) == '203.0.113.99'

    def test_x_forwarded_for_no_client(self):
        request = MagicMock()
        request.headers = {'X-Forwarded-For': '1.2.3.4, 5.6.7.8'}
        request.client = None
        assert _get_client_ip(request) == 'unknown'

    def test_x_real_ip(self):
        request = MagicMock()
        request.headers = {'X-Real-IP': '9.8.7.6'}
        request.client.host = '127.0.0.1'
        assert _get_client_ip(request) == '127.0.0.1'

    def test_x_real_ip_untrusted_spoof(self):
        request = MagicMock()
        request.headers = {'X-Real-IP': '9.8.7.6'}
        request.client.host = '203.0.113.99'
        assert _get_client_ip(request) == '203.0.113.99'

    def test_direct_connection(self):
        request = MagicMock()
        request.headers = {}
        request.client.host = '192.168.1.100'
        assert _get_client_ip(request) == '192.168.1.100'

    def test_unknown_fallback(self):
        request = MagicMock()
        request.headers = {}
        request.client = None
        assert _get_client_ip(request) == 'unknown'

class TestCleanup:

    def test_cleanup_removes_old_entries(self):
        limiter = RateLimiter({})
        limiter.check('192.168.1.1', 'api')
        limiter._last_cleanup = time.time() - 600
        limiter.check('192.168.1.1', 'api')
        stats = limiter.get_stats()
        assert '192.168.1.1' in stats

class TestIntegration:

    def test_full_brute_force_flow(self):
        limiter = RateLimiter({})
        attacker = 'evil.hacker.com'
        for _ in range(4):
            allowed, _ = limiter.check(attacker, 'auth')
            assert allowed is True
        allowed, info = limiter.check(attacker, 'auth')
        assert allowed is True
        assert info['remaining'] == 0
        allowed, info = limiter.check(attacker, 'auth')
        assert allowed is False
        assert info['blocked'] is True
        stats = limiter.get_stats()
        assert attacker in stats
        assert stats[attacker]['auth']['blocked'] is True

    def test_recovery_after_block(self):
        limiter = RateLimiter({})
        ip = '192.168.1.50'
        for _ in range(5):
            limiter.check(ip, 'auth')
        allowed, _ = limiter.check(ip, 'auth')
        assert allowed is False
        limiter.reset(ip)
        allowed, _ = limiter.check(ip, 'auth')
        assert allowed is True

    def test_config_change_takes_effect(self):
        limiter = RateLimiter({})
        for _ in range(5):
            limiter.check('10.0.0.1', 'auth')
        allowed, _ = limiter.check('10.0.0.1', 'auth')
        assert allowed is False
        limiter.set_rule('auth', max_requests=10, window_seconds=60)
        limiter.reset('10.0.0.1')
        for _ in range(9):
            allowed, _ = limiter.check('10.0.0.1', 'auth')
            assert allowed is True
        allowed, info = limiter.check('10.0.0.1', 'auth')
        assert allowed is True
        assert info['remaining'] == 0


def _proxy_app(lim):
    from fastapi import FastAPI
    from throttle import rate_limit_middleware
    app = FastAPI()
    rate_limit_middleware(app)

    @app.get('/api/config')
    def cfg():
        return {}

    @app.post('/api/auth/login')
    def login():
        return {}

    lim.set_rule('api', max_requests=2, window_seconds=60)
    lim.set_rule('auth', max_requests=2, window_seconds=60)
    return app


class TestMiddlewareProxy:

    def _client(self, lim, host):
        from fastapi.testclient import TestClient
        return TestClient(_proxy_app(lim), client=(host, 50000))

    def test_xff_ayri_kova(self):
        lim = RateLimiter({})
        with patch('throttle.limiter', lim):
            c = self._client(lim, '127.0.0.1')
            a = {'X-Forwarded-For': '203.0.113.5'}
            b = {'X-Forwarded-For': '198.51.100.7'}
            for _ in range(2):
                assert c.get('/api/config', headers=a).status_code == 200
            assert c.get('/api/config', headers=a).status_code == 429
            assert c.get('/api/config', headers=b).status_code == 200
        assert '203.0.113.5' in lim.get_stats()
        assert '127.0.0.1' not in lim.get_stats()

    def test_sahte_xff_sol_taraf(self):
        lim = RateLimiter({})
        with patch('throttle.limiter', lim):
            c = self._client(lim, '127.0.0.1')
            for i in range(2):
                h = {'X-Forwarded-For': f'10.9.9.{i}, 203.0.113.5'}
                assert c.get('/api/config', headers=h).status_code == 200
            h = {'X-Forwarded-For': '10.9.9.99, 203.0.113.5'}
            assert c.get('/api/config', headers=h).status_code == 429

    def test_guvenilmeyen_xff_yok_sayilir(self):
        lim = RateLimiter({})
        with patch('throttle.limiter', lim):
            c = self._client(lim, '203.0.113.99')
            for i in range(2):
                h = {'X-Forwarded-For': f'198.51.100.{i}'}
                assert c.get('/api/config', headers=h).status_code == 200
            h = {'X-Forwarded-For': '198.51.100.50'}
            assert c.get('/api/config', headers=h).status_code == 429
        assert list(lim.get_stats()) == ['203.0.113.99']

    def test_yerel_istek_muaf(self):
        lim = RateLimiter({})
        with patch('throttle.limiter', lim):
            c = self._client(lim, '127.0.0.1')
            for _ in range(5):
                assert c.get('/api/config').status_code == 200
            c6 = self._client(lim, '::1')
            for _ in range(5):
                assert c6.get('/api/config').status_code == 200

    def test_dev_proxy_muaf(self):
        lim = RateLimiter({})
        with patch('throttle.limiter', lim):
            c = self._client(lim, '127.0.0.1')
            for xff in ('127.0.0.1', '::ffff:127.0.0.1', '::1'):
                for _ in range(3):
                    assert c.get('/api/config', headers={'X-Forwarded-For': xff}).status_code == 200

    def test_nginx_istegi_muaf_degil(self):
        lim = RateLimiter({})
        with patch('throttle.limiter', lim):
            c = self._client(lim, '127.0.0.1')
            h = {'X-Forwarded-For': '127.0.0.1, 203.0.113.5'}
            for _ in range(2):
                assert c.get('/api/config', headers=h).status_code == 200
            assert c.get('/api/config', headers=h).status_code == 429

    def test_gecersiz_xff_muaf_degil(self):
        lim = RateLimiter({})
        with patch('throttle.limiter', lim):
            c = self._client(lim, '127.0.0.1')
            for _ in range(2):
                assert c.get('/api/config', headers={'X-Forwarded-For': 'abc'}).status_code == 200
            assert c.get('/api/config', headers={'X-Forwarded-For': ''}).status_code == 429

    def test_login_yerelde_de_sinirli(self):
        lim = RateLimiter({})
        with patch('throttle.limiter', lim):
            c = self._client(lim, '127.0.0.1')
            for _ in range(2):
                assert c.post('/api/auth/login').status_code == 200
            assert c.post('/api/auth/login').status_code == 429
            dev = {'X-Forwarded-For': '127.0.0.1'}
            assert c.post('/api/auth/login', headers=dev).status_code == 429
            assert c.get('/api/config').status_code == 200
