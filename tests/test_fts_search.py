"""Trigram FTS alert search: substring parity with LIKE, trigger maintenance,
resumable backfill, readiness gating, and injection-safe query construction.

The trigram tokenizer gives true substring matching, so switching search from
LIKE to FTS must not change which alerts are returned (a security tool must not
silently drop matches). These tests assert exact parity on the same DB.
"""
import pytest

import database as db


def _mk(wid, full_log="", desc="", agent="web01", ts="2026-06-10T00:00:00",
        rule="5710", level=5, ip="10.0.0.5"):
    db.insert_alert({"wazuh_id": wid, "timestamp": ts, "agent_name": agent,
                     "agent_ip": ip, "rule_id": rule, "rule_level": level,
                     "rule_description": desc, "rule_groups": [],
                     "full_log": full_log, "location": "loc", "raw": {}})


def _like_ids(term):
    like = f"%{term}%"
    with db.conn() as c:
        return {r["id"] for r in c.execute(
            "SELECT id FROM alerts WHERE full_log LIKE ? OR rule_description LIKE ? "
            "OR agent_name LIKE ?", (like, like, like))}


def _search_ids(term):
    rows, _ = db.query_alerts(search=term, statuses=None, limit=100000)
    return {r["id"] for r in rows}


# ---- readiness + trigger ----

def test_fresh_db_ready_and_trigger_indexes(tmp_db):
    # Fresh DB: target=0 → ready immediately; the AFTER INSERT trigger indexes
    # everything from then on.
    assert db.fts_is_ready()
    _mk("w1", full_log="Failed password for root via openssh", desc="sshd auth fail")
    db._FTS_READY_CACHE = False
    # Infix match: 'ssh' must find 'openssh' (trigram substring, == LIKE).
    assert _search_ids("ssh") == _like_ids("ssh") == {1}


def test_status_shape(tmp_db):
    s = db.fts_status()
    assert s["available"] and s["ready"]


# ---- substring parity (the core guarantee) ----

def test_substring_parity(tmp_db):
    _mk("w1", full_log="sshd: Accepted password for root from 10.0.0.9")
    _mk("w2", full_log="Out of memory: killed openssh-server", desc="kernel oom")
    _mk("w3", full_log="sudo: pam_unix authentication failure", agent="db01")
    db._FTS_READY_CACHE = False
    for term in ["ssh", "openssh", "memory", "10.0.0", "authentication", "root",
                 "db01", "Accepted", "xyznotpresent"]:
        assert _search_ids(term) == _like_ids(term), term


def test_short_query_uses_like_fallback(tmp_db):
    _mk("w1", full_log="ab cd")          # 'ab' is 2 chars → below trigram floor
    db._FTS_READY_CACHE = False
    assert _search_ids("ab") == _like_ids("ab") == {1}


def test_special_chars_do_not_break_query(tmp_db):
    # FTS5 query operators / quotes in the search must be treated as literal text.
    _mk("w1", full_log='he said "hello" AND (goodbye) OR maybe*')
    db._FTS_READY_CACHE = False
    for term in ['"hello"', "AND (goodbye)", "maybe*", '"', "OR may"]:
        assert _search_ids(term) == _like_ids(term), repr(term)


def test_match_literal_escapes_quotes():
    assert db._fts_match_literal('foo') == '"foo"'
    assert db._fts_match_literal('a"b') == '"a""b"'


# ---- backfill of pre-existing rows ----

def _simulate_unindexed_backlog(c):
    """Drop the trigger + clear the index + reset the watermark so the existing
    alerts look like a pre-FTS backlog needing a backfill."""
    c.execute("DROP TRIGGER IF EXISTS alerts_fts_ai")
    # Contentless FTS5 rejects plain DELETE (the very property that lets us skip
    # a delete trigger); use the 'delete-all' command to clear the index.
    c.execute("INSERT INTO alerts_fts(alerts_fts) VALUES('delete-all')")
    c.execute("UPDATE fts_state SET value=(SELECT COALESCE(MAX(id),0) FROM alerts) WHERE key='target'")
    c.execute("UPDATE fts_state SET value=0 WHERE key='high_water'")


def test_backfill_indexes_existing_rows(tmp_db):
    for i in range(25):
        _mk(f"w{i}", full_log=f"event number {i} sshd openssh")
    with db.conn() as c:
        _simulate_unindexed_backlog(c)
    db._FTS_READY_CACHE = False
    assert not db.fts_is_ready()                 # backlog present → not ready
    res = db.fts_backfill_step(batch=10)
    assert res["done"]
    assert db.fts_is_ready()
    assert _search_ids("openssh") == _like_ids("openssh")
    assert len(_search_ids("openssh")) == 25


def test_backfill_resumable(tmp_db):
    for i in range(50):
        _mk(f"w{i}", full_log=f"line {i} authentication failed")
    with db.conn() as c:
        _simulate_unindexed_backlog(c)
        target = db._fts_state_get(c, "target")
    db._FTS_READY_CACHE = False
    # First bounded pass: a few rows, not done.
    r1 = db.fts_backfill_step(batch=10, max_batches=2)
    assert not r1["done"] and r1["indexed"] == 20
    hw1 = r1["high_water"]
    # "Restart": clear the in-process ready cache; watermark persists in the DB.
    db._FTS_READY_CACHE = False
    with db.conn() as c:
        assert db._fts_state_get(c, "high_water") == hw1
    # Resume to completion.
    while not db.fts_backfill_step(batch=10, max_batches=2)["done"]:
        pass
    db._FTS_READY_CACHE = False
    assert db.fts_is_ready()
    with db.conn() as c:
        assert db._fts_state_get(c, "high_water") >= target
    assert len(_search_ids("authentication")) == 50


def test_search_falls_back_to_like_when_not_ready(tmp_db, monkeypatch):
    # While the backfill is incomplete, search must still return correct results
    # via LIKE (no dropped matches in the meantime).
    _mk("w1", full_log="pending openssh row")
    with db.conn() as c:
        _simulate_unindexed_backlog(c)           # index empty, not ready
    db._FTS_READY_CACHE = False
    assert not db.fts_is_ready()
    # FTS index is empty, but the LIKE fallback still finds the row.
    assert _search_ids("openssh") == {1}


def test_backfill_no_double_index_for_new_rows(tmp_db):
    # New rows (id > target) are trigger-indexed; the backfill only covers
    # (0, target]. They must not be indexed twice. Keep the trigger live here.
    _mk("w1", full_log="old row openssh")        # id=1
    with db.conn() as c:
        c.execute("INSERT INTO alerts_fts(alerts_fts) VALUES('delete-all')")
        c.execute("UPDATE fts_state SET value=1 WHERE key='target'")   # target = w1's id
        c.execute("UPDATE fts_state SET value=0 WHERE key='high_water'")
    _mk("w2", full_log="new row openssh")        # id=2 > target → trigger indexes it
    db._FTS_READY_CACHE = False
    db.fts_backfill_step(batch=10)               # backfill covers (0,1] → w1 only
    db._FTS_READY_CACHE = False
    # Each row appears exactly once for 'openssh' (no duplicate rowids).
    rows, total = db.query_alerts(search="openssh", statuses=None, limit=100)
    ids = [r["id"] for r in rows]
    assert sorted(ids) == [1, 2] and len(ids) == len(set(ids)) and total == 2
