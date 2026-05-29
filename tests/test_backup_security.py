"""Backup snapshots use owner-only temp files; the DB file is created 0600.

The on-disk snapshot is a full copy of the DB (Fernet-encrypted secrets +
session key), so it must not sit in a predictable, world-readable /tmp name.
"""
import glob
import os


def test_stream_to_browser_uses_secure_tmp_and_cleans_up(tmp_db):
    import backup
    before = set(glob.glob("/tmp/socbackup-*"))
    data, filename, size = backup.stream_to_browser("config")
    assert data[:16] == b"SQLite format 3\x00"   # valid sqlite snapshot
    assert filename.endswith(".sqlite") and "config" in filename
    assert size > 0
    after = set(glob.glob("/tmp/socbackup-*"))
    assert after == before, f"leftover temp files: {after - before}"


def test_secure_tmp_is_owner_only(tmp_db):
    import backup
    p = backup._secure_tmp()
    try:
        mode = os.stat(p).st_mode & 0o777
        assert mode == 0o600, oct(mode)
    finally:
        p.unlink()


def test_db_file_perms_restricted(tmp_db):
    import database
    os.chmod(database.DB_PATH, 0o644)
    database.init_db()
    mode = os.stat(database.DB_PATH).st_mode & 0o777
    assert mode == 0o600, oct(mode)
