import os
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from unittest.mock import patch
import pytest
sys.path.insert(0, str(Path(__file__).parent.parent))
import auth

TEST_PASSWORD = 'test-parola-123'


def _create_admin():
    auth._save_credentials({'username': 'admin', 'password_hash': auth._hash_password(TEST_PASSWORD), 'created_at': datetime.now().isoformat()})

class TestTokenOperations:

    def test_create_token_returns_string(self):
        token = auth.create_token('admin')
        assert isinstance(token, str)
        assert '.' in token

    def test_create_token_format(self):
        token = auth.create_token('testuser')
        parts = token.split('.')
        assert len(parts) == 2

    def test_verify_valid_token(self):
        original_secret = auth.SECRET_KEY
        auth.SECRET_KEY = 'test-secret-key-for-verify'
        try:
            token = auth.create_token('admin')
            username = auth.verify_token(token)
            assert username == 'admin'
        finally:
            auth.SECRET_KEY = original_secret

    def test_verify_invalid_token(self):
        result = auth.verify_token('invalid.token.here')
        assert result is None

    def test_verify_empty_token(self):
        result = auth.verify_token('')
        assert result is None

    def test_verify_tampered_token(self):
        original_secret = auth.SECRET_KEY
        auth.SECRET_KEY = 'test-secret-for-tamper'
        try:
            token = auth.create_token('admin')
            tampered = token[:-5] + 'XXXXX'
            result = auth.verify_token(tampered)
            assert result is None
        finally:
            auth.SECRET_KEY = original_secret

    def test_verify_expired_token(self):
        original_secret = auth.SECRET_KEY
        auth.SECRET_KEY = 'test-secret-for-expired'
        try:
            with patch.object(auth, 'TOKEN_EXPIRY_HOURS', -1):
                token = auth.create_token('admin')
                result = auth.verify_token(token)
                assert result is None
        finally:
            auth.SECRET_KEY = original_secret

    def test_different_users_different_tokens(self):
        original_secret = auth.SECRET_KEY
        auth.SECRET_KEY = 'test-secret-for-diff'
        try:
            token1 = auth.create_token('user1')
            token2 = auth.create_token('user2')
            assert token1 != token2
        finally:
            auth.SECRET_KEY = original_secret

    def test_revoke_token(self):
        original_secret = auth.SECRET_KEY
        auth.SECRET_KEY = 'test-secret-for-revoke'
        try:
            token = auth.create_token('admin')
            assert auth.verify_token(token) == 'admin'
            assert auth.revoke_token(token) is True
            assert auth.verify_token(token) is None
        finally:
            auth.SECRET_KEY = original_secret

class TestPasswordHashing:

    def test_hash_password_returns_string(self):
        hashed = auth._hash_password('testpassword')
        assert isinstance(hashed, str)
        assert len(hashed) > 0

    def test_hash_password_bcrypt_format(self):
        hashed = auth._hash_password('testpassword')
        assert hashed.startswith('$2')

    def test_hash_password_different_each_time(self):
        h1 = auth._hash_password('testpassword')
        h2 = auth._hash_password('testpassword')
        assert h1 != h2

    def test_hash_password_verify(self):
        import bcrypt
        password = 'testpassword'
        hashed = auth._hash_password(password)
        assert bcrypt.checkpw(password.encode(), hashed.encode())

class TestCredentialManagement:

    def test_load_credentials_returns_dict(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            creds_file = Path(tmpdir) / 'credentials.json'
            with patch.object(auth, 'CREDS_FILE', creds_file):
                creds = auth._load_credentials()
                assert isinstance(creds, dict)
                assert 'username' in creds
                assert 'password_hash' in creds

    def test_default_credentials(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            creds_file = Path(tmpdir) / 'credentials.json'
            with patch.object(auth, 'CREDS_FILE', creds_file):
                creds = auth._load_credentials()
                assert creds['username'] == 'admin'
                assert creds['password_hash'].startswith('$2')

    def test_save_credentials(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            creds_file = Path(tmpdir) / 'credentials.json'
            with patch.object(auth, 'CREDS_FILE', creds_file):
                test_creds = {'username': 'testuser', 'password_hash': auth._hash_password('testpass'), 'created_at': datetime.now().isoformat()}
                auth._save_credentials(test_creds)
                assert creds_file.exists()
                import json
                with open(creds_file) as f:
                    loaded = json.load(f)
                assert loaded['username'] == 'testuser'

class TestLogin:

    def test_login_success(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            creds_file = Path(tmpdir) / 'credentials.json'
            with patch.object(auth, 'CREDS_FILE', creds_file):
                _create_admin()
                result = auth.login('admin', TEST_PASSWORD)
                assert 'access_token' in result
                assert result['token_type'] == 'bearer'
                assert result['username'] == 'admin'

    def test_login_wrong_password(self):
        from fastapi import HTTPException
        with tempfile.TemporaryDirectory() as tmpdir:
            creds_file = Path(tmpdir) / 'credentials.json'
            with patch.object(auth, 'CREDS_FILE', creds_file):
                _create_admin()
                with pytest.raises(HTTPException) as exc_info:
                    auth.login('admin', 'wrongpassword')
                assert exc_info.value.status_code == 401

    def test_login_wrong_username(self):
        from fastapi import HTTPException
        with tempfile.TemporaryDirectory() as tmpdir:
            creds_file = Path(tmpdir) / 'credentials.json'
            with patch.object(auth, 'CREDS_FILE', creds_file):
                _create_admin()
                with pytest.raises(HTTPException) as exc_info:
                    auth.login('wronguser', TEST_PASSWORD)
                assert exc_info.value.status_code == 401

    def test_login_returns_token(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            creds_file = Path(tmpdir) / 'credentials.json'
            with patch.object(auth, 'CREDS_FILE', creds_file):
                original_secret = auth.SECRET_KEY
                auth.SECRET_KEY = 'test-secret-for-login'
                try:
                    _create_admin()
                    result = auth.login('admin', TEST_PASSWORD)
                    username = auth.verify_token(result['access_token'])
                    assert username == 'admin'
                finally:
                    auth.SECRET_KEY = original_secret

class TestChangePassword:

    def test_change_password_success(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            creds_file = Path(tmpdir) / 'credentials.json'
            with patch.object(auth, 'CREDS_FILE', creds_file):
                _create_admin()
                result = auth.change_password('admin', TEST_PASSWORD, 'newpassword123')
                assert result['success'] is True
                result2 = auth.login('admin', 'newpassword123')
                assert 'access_token' in result2

    def test_change_password_wrong_old(self):
        from fastapi import HTTPException
        with tempfile.TemporaryDirectory() as tmpdir:
            creds_file = Path(tmpdir) / 'credentials.json'
            with patch.object(auth, 'CREDS_FILE', creds_file):
                _create_admin()
                with pytest.raises(HTTPException) as exc_info:
                    auth.change_password('admin', 'wrongold', 'newpassword123')
                assert exc_info.value.status_code == 401

    def test_change_password_too_short(self):
        from fastapi import HTTPException
        with tempfile.TemporaryDirectory() as tmpdir:
            creds_file = Path(tmpdir) / 'credentials.json'
            with patch.object(auth, 'CREDS_FILE', creds_file):
                _create_admin()
                with pytest.raises(HTTPException) as exc_info:
                    auth.change_password('admin', TEST_PASSWORD, 'short')
                assert exc_info.value.status_code == 400

    def test_change_password_wrong_username(self):
        from fastapi import HTTPException
        with tempfile.TemporaryDirectory() as tmpdir:
            creds_file = Path(tmpdir) / 'credentials.json'
            with patch.object(auth, 'CREDS_FILE', creds_file):
                _create_admin()
                with pytest.raises(HTTPException) as exc_info:
                    auth.change_password('wronguser', TEST_PASSWORD, 'newpassword123')
                assert exc_info.value.status_code == 401

class TestSecretKey:

    def test_get_secret_returns_string(self):
        original_secret = auth.SECRET_KEY
        auth.SECRET_KEY = None
        try:
            with patch.dict(os.environ, {'PUYAD_SECRET_KEY': 'test-secret-env-key'}):
                secret = auth._get_secret()
                assert isinstance(secret, str)
                assert len(secret) > 0
        finally:
            auth.SECRET_KEY = original_secret

    def test_secret_key_consistent(self):
        original_secret = auth.SECRET_KEY
        auth.SECRET_KEY = None
        try:
            with patch.dict(os.environ, {'PUYAD_SECRET_KEY': 'consistent-key-456'}):
                s1 = auth._get_secret()
                auth.SECRET_KEY = None
                s2 = auth._get_secret()
                assert s1 == s2
        finally:
            auth.SECRET_KEY = original_secret

class TestIntegration:

    def test_full_auth_flow(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            creds_file = Path(tmpdir) / 'credentials.json'
            with patch.object(auth, 'CREDS_FILE', creds_file):
                original_secret = auth.SECRET_KEY
                auth.SECRET_KEY = 'test-secret-for-full-flow'
                try:
                    _create_admin()
                    login_result = auth.login('admin', TEST_PASSWORD)
                    token = login_result['access_token']
                    username = auth.verify_token(token)
                    assert username == 'admin'
                    auth.change_password('admin', TEST_PASSWORD, 'newsecurepass123')
                    assert auth.verify_token(token) is None
                    login_result2 = auth.login('admin', 'newsecurepass123')
                    assert 'access_token' in login_result2
                finally:
                    auth.SECRET_KEY = original_secret

    def test_token_expiry_flow(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            creds_file = Path(tmpdir) / 'credentials.json'
            with patch.object(auth, 'CREDS_FILE', creds_file):
                original_secret = auth.SECRET_KEY
                auth.SECRET_KEY = 'test-secret-for-expiry'
                try:
                    _create_admin()
                    token = auth.create_token('admin')
                    assert auth.verify_token(token) == 'admin'
                    with patch.object(auth, 'TOKEN_EXPIRY_HOURS', -1):
                        expired_token = auth.create_token('admin')
                        assert auth.verify_token(expired_token) is None
                finally:
                    auth.SECRET_KEY = original_secret


def test_legacy_sha256_hash_checked() -> None:
    import hashlib

    stored = hashlib.sha256(b"eski-parola").hexdigest()
    assert auth._check_password(stored, "eski-parola") is True
    assert auth._check_password(stored, "yanlis") is False
    assert auth._check_password("bozuk-ğ", "yanlis") is False


def test_logout_survives_restart(tmp_path, monkeypatch):
    import importlib

    from fastapi.testclient import TestClient

    import main

    monkeypatch.setenv("PUYAD_SECRET_KEY", "restart-testi-icin-sabit-anahtar")
    monkeypatch.setattr(auth, "SECRET_KEY", None)
    client = TestClient(main.app, client=("192.168.99.91", 50000))
    old = auth.create_token(auth._load_credentials()["username"])
    hdrs = {"Authorization": f"Bearer {old}"}
    assert client.get("/api/auth/me", headers=hdrs).status_code == 200
    assert client.post("/api/auth/logout", headers=hdrs).status_code == 200
    assert client.get("/api/auth/me", headers=hdrs).status_code == 401

    creds_file, key_file = auth.CREDS_FILE, auth.SECRET_KEY_FILE
    reloaded = importlib.reload(auth)
    try:
        monkeypatch.setattr(reloaded, "CREDS_FILE", creds_file)
        monkeypatch.setattr(reloaded, "SECRET_KEY_FILE", key_file)
        assert not hasattr(reloaded, "_revoked_jti")
        assert reloaded.verify_token(old) is None
        fresh = reloaded.create_token(reloaded._load_credentials()["username"])
        assert reloaded.verify_token(fresh) is not None
    finally:
        importlib.reload(auth)


def test_logout_requires_valid_token():
    assert auth.revoke_token("bozuk.token") is False
    assert "sessions_valid_after" not in auth._load_credentials()


@pytest.mark.parametrize("sig", ["ğ" * 64, "A" * 64, "0" * 63, "0" * 65, " " + "0" * 63])
def test_malformed_signature_rejected_before_compare(sig, monkeypatch):
    called = []
    monkeypatch.setattr(auth._hmac, "compare_digest", lambda a, b: called.append(1) or False)
    payload_b64 = auth.create_token("admin").split(".")[0]
    assert auth.verify_token(f"{payload_b64}.{sig}") is None
    assert called == []


def test_non_ascii_signature_returns_401():
    from fastapi.testclient import TestClient

    import main

    client = TestClient(main.app, raise_server_exceptions=False)
    payload_b64 = auth.create_token("admin").split(".")[0]
    token = f"{payload_b64}.{'é' * 64}".encode("latin-1")
    for method, url in (("GET", "/api/auth/me"), ("POST", "/api/auth/logout")):
        res = client.request(method, url, headers={b"Authorization": b"Bearer " + token})
        assert res.status_code == 401
