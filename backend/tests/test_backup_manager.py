from __future__ import annotations
import os
from pathlib import Path
import shutil
import sys
import tempfile
from unittest.mock import patch
import pytest
sys.path.insert(0, str(Path(__file__).parent.parent))
import backup_manager
import database

class TestBackupManager:

    @pytest.fixture(autouse=True)
    def setup_test_env(self):
        self.temp_dir = tempfile.mkdtemp(prefix='puyad_snap_test_')
        self.snap_dir = Path(self.temp_dir) / 'snapshots'
        self.snap_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = Path(self.temp_dir) / 'test_history.db'
        with patch.object(database, 'DB_FILE', self.db_path):
            database.init_db()
        with patch.object(backup_manager, 'SNAPSHOT_DIR', self.snap_dir), patch.object(database, 'DB_FILE', self.db_path):
            yield
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_sanitize_label(self):
        assert backup_manager._sanitize_label('') == 'manual'
        assert backup_manager._sanitize_label('test_backup-1.0') == 'test_backup-1.0'
        assert backup_manager._sanitize_label('../../etc/passwd') == '______etc_passwd'
        assert backup_manager._sanitize_label('A' * 100) == 'A' * 40
        assert backup_manager._sanitize_label('Güvenlik@Yedek#2026') == 'G_venlik_Yedek_2026'

    def test_relative_posix(self):
        base = Path('/etc')
        item = Path('/etc/nginx/nginx.conf')
        assert backup_manager._relative_posix(item, base) == 'nginx/nginx.conf'
        unrelated = Path('/var/log/syslog')
        assert backup_manager._relative_posix(unrelated, base) is None

    def test_create_snapshot_unsupported_os(self):
        with patch('compat.IS_LINUX', False):
            res = backup_manager.create_snapshot('test')
            assert res['success'] is False
            assert 'yalnızca linux sistemlerde destekleniyor' in res['message'].lower()

    def test_create_and_list_snapshot(self):
        dummy_src = Path(self.temp_dir) / 'dummy_etc'
        dummy_src.mkdir()
        (dummy_src / 'test.conf').write_text('setting=1')
        with patch('compat.IS_LINUX', True), patch.object(backup_manager, 'SNAPSHOT_DIR', self.snap_dir), patch.object(backup_manager, 'BACKUP_PATHS', [str(dummy_src)]), patch.object(database, 'DB_FILE', self.db_path):
            res = backup_manager.create_snapshot('my_test_backup')
            assert res['success'] is True
            snap_id = res['snapshot_id']
            assert Path(res['path']).exists()
            snaps = backup_manager.list_snapshots()
            assert len(snaps) >= 1
            assert any((s['id'] == snap_id for s in snaps))

    def test_delete_snapshot_path_traversal(self):
        with patch.object(database, 'DB_FILE', self.db_path):
            res = backup_manager.delete_snapshot('../../etc/shadow')
            assert res['success'] is False
            assert 'Geçersiz snapshot ID' in res['message']

    def test_delete_snapshot_not_found(self):
        with patch.object(database, 'DB_FILE', self.db_path):
            res = backup_manager.delete_snapshot('non-existent-uuid')
            assert res['success'] is False
            assert 'Snapshot bulunamadı' in res['message']

    def test_delete_snapshot_success(self):
        dummy_src = Path(self.temp_dir) / 'dummy_etc'
        dummy_src.mkdir(exist_ok=True)
        (dummy_src / 'test.conf').write_text('setting=1')
        with patch('compat.IS_LINUX', True), patch.object(backup_manager, 'SNAPSHOT_DIR', self.snap_dir), patch.object(backup_manager, 'BACKUP_PATHS', [str(dummy_src)]), patch.object(database, 'DB_FILE', self.db_path):
            res = backup_manager.create_snapshot('to_be_deleted')
            snap_id = res['snapshot_id']
            snap_file = Path(res['path'])
            assert snap_file.exists()
            del_res = backup_manager.delete_snapshot(snap_id)
            assert del_res['success'] is True
            assert not snap_file.exists()
            snaps = backup_manager.list_snapshots()
            assert not any((s['id'] == snap_id for s in snaps))

    def test_rollback_snapshot_validation(self):
        with patch.object(database, 'DB_FILE', self.db_path):
            res = backup_manager.rollback_snapshot('../invalid')
            assert res['success'] is False
            res2 = backup_manager.rollback_snapshot('12345678-1234-1234-1234-123456789abc')
            assert res2['success'] is False
            assert 'Snapshot bulunamadı' in res2['message']
