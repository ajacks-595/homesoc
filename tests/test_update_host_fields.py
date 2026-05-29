"""update_host_fields allowlists its interpolated column names (SAST follow-up)."""
import database as db


def test_update_host_fields_allowlists_columns(tmp_db):
    db.upsert_host("10.0.0.9", "h9", "router", "notes")
    hid = db.get_host_by_ip("10.0.0.9")["id"]
    # hostname is allowed; agent_status is a real column but NOT in the allowlist
    db.update_host_fields(hid, hostname="renamed", agent_status="HACKED")
    row = db.get_host(hid)
    assert row["hostname"] == "renamed"          # allowed field written
    assert row["agent_status"] != "HACKED"       # non-allowlisted field ignored


def test_update_host_fields_noop_when_all_filtered(tmp_db):
    db.upsert_host("10.0.0.9", "h9", "router", "notes")
    hid = db.get_host_by_ip("10.0.0.9")["id"]
    db.update_host_fields(hid, bogus="x")         # nothing allowed → no-op, no error
    assert db.get_host(hid)["hostname"] == "h9"
