import sys
from pathlib import Path

import pytest
from fastapi import HTTPException

sys.path.insert(0, str(Path(__file__).parent.parent))
import auth

DEFAULT_PASSWORD = 'puyad2026'


class TestDefaultPassword:

    def test_creates_credentials_with_default(self):
        assert not auth.CREDS_FILE.exists()
        auth.ensure_credentials()
        assert auth.CREDS_FILE.exists()
        assert 'access_token' in auth.login('admin', DEFAULT_PASSWORD)

    def test_login_without_credentials_file(self):
        assert not auth.CREDS_FILE.exists()
        assert 'access_token' in auth.login('admin', DEFAULT_PASSWORD)

    def test_wrong_password_rejected(self):
        auth.ensure_credentials()
        with pytest.raises(HTTPException) as exc_info:
            auth.login('admin', 'yanlis-parola')
        assert exc_info.value.status_code == 401

    def test_old_password_rejected_after_change(self):
        auth.ensure_credentials()
        auth.change_password('admin', DEFAULT_PASSWORD, 'yeni-parola-123')
        with pytest.raises(HTTPException) as exc_info:
            auth.login('admin', DEFAULT_PASSWORD)
        assert exc_info.value.status_code == 401
        assert 'access_token' in auth.login('admin', 'yeni-parola-123')

    def test_changed_password_kept_on_startup(self):
        auth.ensure_credentials()
        auth.change_password('admin', DEFAULT_PASSWORD, 'yeni-parola-123')
        auth.ensure_credentials()
        assert 'access_token' in auth.login('admin', 'yeni-parola-123')

    def test_login_via_api(self):
        from fastapi.testclient import TestClient

        import main

        client = TestClient(main.app, client=('192.168.99.92', 50000))
        res = client.post('/api/auth/login', json={'username': 'admin', 'password': DEFAULT_PASSWORD})
        assert res.status_code == 200
        assert res.json()['access_token']
