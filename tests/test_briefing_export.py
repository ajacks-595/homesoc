"""Briefing export: self-contained HTML (sanitized) + raw markdown download (F8)."""
import pytest

import database as db


@pytest.fixture
def auth_client(tmp_db, monkeypatch):
    monkeypatch.setenv("SOC_DB_PATH", tmp_db)
    monkeypatch.setenv("SOC_POLLERS", "systemd")
    from app import create_app
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as c:
        c.post("/setup", data={"username": "admin", "password": "supersecret"})
        yield c


_CONTENT = "# Daily\n\nSome **bold** text.\n\n<script>alert(1)</script>\n"


def _make():
    return db.upsert_briefing("2026-05-29", "daily", _CONTENT, "/tmp/b.md", "clean")


def test_export_markdown_is_raw(auth_client):
    bid = _make()
    r = auth_client.get(f"/api/briefings/{bid}/export?format=md")
    assert r.status_code == 200
    assert "text/markdown" in r.headers["Content-Type"]
    assert "attachment" in r.headers.get("Content-Disposition", "")
    # markdown source is downloaded verbatim (not HTML-rendered)
    assert b"# Daily" in r.data and b"<script>alert(1)</script>" in r.data


def test_export_html_is_sanitized_standalone_doc(auth_client):
    bid = _make()
    r = auth_client.get(f"/api/briefings/{bid}/export?format=html")
    assert r.status_code == 200
    assert "text/html" in r.headers["Content-Type"]
    body = r.get_data(as_text=True)
    assert "<!doctype html>" in body.lower()
    assert "<title>" in body.lower()
    assert "<strong>bold</strong>" in body          # markdown rendered
    assert "<script>alert(1)</script>" not in body  # nh3-sanitized


def test_export_bad_format_400(auth_client):
    assert auth_client.get(f"/api/briefings/{_make()}/export?format=pdf").status_code == 400


def test_export_missing_404(auth_client):
    assert auth_client.get("/api/briefings/99999/export").status_code == 404
