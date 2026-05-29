"""OSINT providers must not 500 on a non-JSON 200 body (WAF/captcha/gateway)."""
import osint


class _Resp:
    def __init__(self, status=200, text="<html>blocked</html>", payload=None, raise_json=False):
        self.status_code = status
        self.text = text
        self._payload = payload
        self._raise = raise_json

    def json(self):
        if self._raise:
            raise ValueError("Expecting value")   # what requests raises on bad JSON
        return self._payload


def _force_key(monkeypatch):
    monkeypatch.setattr(osint, "_key", lambda s: "k")


def test_virustotal_non_json_200(monkeypatch):
    _force_key(monkeypatch)
    monkeypatch.setattr(osint.requests, "get", lambda *a, **k: _Resp(raise_json=True))
    r = osint.virustotal("8.8.8.8", force_refresh=True)
    assert r["success"] is False and "invalid JSON" in r["error"]


def test_abuseipdb_non_json_200(monkeypatch):
    _force_key(monkeypatch)
    monkeypatch.setattr(osint.requests, "get", lambda *a, **k: _Resp(raise_json=True))
    r = osint.abuseipdb("8.8.8.8", force_refresh=True)
    assert r["success"] is False and "invalid JSON" in r["error"]


def test_urlscan_non_json_200(monkeypatch):
    _force_key(monkeypatch)
    monkeypatch.setattr(osint.requests, "get", lambda *a, **k: _Resp(raise_json=True))
    r = osint.urlscan("example.com", force_refresh=True)
    assert r["success"] is False and "invalid JSON" in r["error"]


def test_virustotal_valid_json_still_parses(tmp_db, monkeypatch):
    _force_key(monkeypatch)
    payload = {"data": {"attributes": {"last_analysis_stats": {"malicious": 1, "harmless": 70}}}}
    monkeypatch.setattr(osint.requests, "get", lambda *a, **k: _Resp(payload=payload))
    r = osint.virustotal("8.8.8.8", force_refresh=True)
    assert r["success"] is True
    assert r["data"]["malicious"] == 1
