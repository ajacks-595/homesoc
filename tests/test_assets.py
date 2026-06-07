"""CVE asset tracker Phase 1: asset register CRUD + Vigil import."""
import pytest

import database as db


def test_asset_crud(tmp_db):
    aid = db.asset_insert("nginx (proxy)", vendor="nginx", product="nginx",
                          version="1.27.3", category="service",
                          exposure="internet", criticality="high",
                          cpe="cpe:2.3:a:nginx:nginx:1.27.3")
    a = db.asset_get(aid)
    assert a["name"] == "nginx (proxy)" and a["exposure"] == "internet"
    assert a["source"] == "manual"

    db.update_asset_fields(aid, version="1.27.4", notes="updated")
    a = db.asset_get(aid)
    assert a["version"] == "1.27.4" and a["notes"] == "updated"

    # column allowlist: unknown / dangerous keys are dropped silently
    db.update_asset_fields(aid, source="hax", id=999, **{"name=x; --": "y"})
    assert db.asset_get(aid)["source"] == "manual"

    db.asset_delete(aid)
    assert db.asset_get(aid) is None


def test_asset_name_unique(tmp_db):
    db.asset_insert("Proxmox VE")
    import sqlite3
    with pytest.raises(sqlite3.IntegrityError):
        db.asset_insert("Proxmox VE")


def test_asset_enum_checks(tmp_db):
    import sqlite3
    with pytest.raises(sqlite3.IntegrityError):
        db.asset_insert("bad", category="spaceship")
    with pytest.raises(sqlite3.IntegrityError):
        db.asset_insert("bad2", exposure="moon")


def test_assets_list_ordering(tmp_db):
    db.asset_insert("zz-lan-low", exposure="lan", criticality="low")
    db.asset_insert("aa-internet-high", exposure="internet", criticality="high")
    db.asset_insert("mm-isolated-high", exposure="isolated", criticality="high")
    names = [a["name"] for a in db.assets_list()]
    assert names == ["aa-internet-high", "zz-lan-low", "mm-isolated-high"]


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


def test_assets_api_crud(auth_client):
    r = auth_client.post("/api/assets", json={
        "name": "UniFi OS", "vendor": "Ubiquiti", "product": "UniFi OS",
        "version": "5.1.10", "category": "network_device",
        "exposure": "lan", "criticality": "high"})
    assert r.get_json()["success"]
    aid = r.get_json()["data"]["id"]

    r = auth_client.post("/api/assets", json={"name": "UniFi OS"})
    assert not r.get_json()["success"]          # duplicate name

    r = auth_client.post("/api/assets", json={"name": "x", "category": "nope"})
    assert not r.get_json()["success"]          # invalid enum -> 400 not 500

    r = auth_client.patch(f"/api/assets/{aid}", json={"version": "5.1.12"})
    assert r.get_json()["data"]["version"] == "5.1.12"

    r = auth_client.get("/api/assets")
    assert len(r.get_json()["data"]) == 1

    r = auth_client.delete(f"/api/assets/{aid}")
    assert r.get_json()["success"]
    assert auth_client.get("/api/assets").get_json()["data"] == []


def test_vulns_config_admin_only_and_secret_masking(auth_client):
    # admin (first user) can read+write
    r = auth_client.post("/api/vulns/config", json={
        "vigil_url": "http://10.0.0.188:8400", "vigil_api_key": "sekrit",
        "bookstack_url": "https://bs.example.com", "book_id": 247})
    body = r.get_json()
    assert body["success"]
    # secrets never come back — only presence booleans
    assert "vigil_api_key" not in body["data"]
    assert body["data"]["vigil_api_key_set"] is True
    assert body["data"]["vigil_url"] == "http://10.0.0.188:8400"

    # empty-string secret on update means "keep existing"
    r = auth_client.post("/api/vulns/config", json={"vigil_api_key": ""})
    assert r.get_json()["data"]["vigil_api_key_set"] is True

    import vulntrack
    assert vulntrack.get_config()["vigil_api_key"] == "sekrit"


def test_vigil_import_creates_drafts(auth_client, monkeypatch):
    import vulntrack

    monkeypatch.setattr(vulntrack, "vigil_fetch_integrations", lambda: [
        {"id": "proxmox-main", "name": "Proxmox", "type": "proxmox",
         "summary": "2 nodes up"},
        {"id": "nas", "name": "Synology", "type": "synology", "summary": None},
        {"id": "bs", "name": "BookStack", "type": "http", "summary": "200 OK"},
    ])
    r = auth_client.post("/api/assets/import-vigil")
    d = r.get_json()["data"]
    assert d["imported"] == 3

    rows = {a["name"]: a for a in (dict(x) for x in __import__("database").assets_list())}
    assert rows["Proxmox"]["category"] == "hypervisor"
    assert rows["Synology"]["category"] == "os"
    assert rows["BookStack"]["category"] == "service"
    assert rows["Proxmox"]["source"] == "vigil"
    assert rows["Proxmox"]["product"] is None      # draft: needs filling in

    # idempotent: second import skips everything
    r = auth_client.post("/api/assets/import-vigil")
    d = r.get_json()["data"]
    assert d["imported"] == 0 and d["skipped"] == 3


def test_vigil_import_unconfigured_is_clean_error(auth_client):
    r = auth_client.post("/api/assets/import-vigil")
    body = r.get_json()
    assert not body["success"]
    assert "not configured" in body["error"]
