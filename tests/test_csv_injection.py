"""CSV/formula injection is neutralised in the alert export (M2, CWE-1236)."""
import csv
import io

import pytest

import app as app_module


@pytest.fixture
def client(tmp_db, monkeypatch):
    monkeypatch.setenv("SOC_DB_PATH", tmp_db)
    monkeypatch.setenv("SOC_POLLERS", "systemd")
    from app import create_app
    a = create_app()
    a.config["TESTING"] = True
    with a.test_client() as c:
        c.post("/setup", data={"username": "admin", "password": "supersecret"})
        yield c


def test_csv_safe_helper():
    assert app_module._csv_safe("=1+1") == "'=1+1"
    assert app_module._csv_safe("+1") == "'+1"
    assert app_module._csv_safe("-1") == "'-1"
    assert app_module._csv_safe("@SUM(A1)") == "'@SUM(A1)"
    assert app_module._csv_safe("\tx") == "'\tx"
    # benign values are untouched
    assert app_module._csv_safe("sshd: failed login") == "sshd: failed login"
    assert app_module._csv_safe(10) == "10"
    assert app_module._csv_safe(None) == ""


def test_export_neutralises_formula_in_full_log(client):
    import database as db
    db.insert_alert({
        "wazuh_id": "x1", "timestamp": "2026-06-04T00:00:00",
        "agent_name": "h1", "rule_id": "100", "rule_level": 5,
        "rule_description": "=HYPERLINK(\"http://evil\")",
        "full_log": "=cmd|'/c calc'!A1",
    })
    r = client.get("/api/alerts/export")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    rows = list(csv.reader(io.StringIO(body)))
    data_row = rows[1]
    # rule_description (idx 5) and full_log (idx 8) must be quote-prefixed
    assert data_row[5].startswith("'="), data_row[5]
    assert data_row[8].startswith("'="), data_row[8]
