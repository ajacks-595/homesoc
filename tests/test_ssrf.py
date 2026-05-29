"""SSRF guard for outbound webhook delivery (notifications.validate_webhook_url)."""
import socket

import notifications as nf


def _gai(ip):
    return lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, 80))]


def test_scheme_must_be_http():
    assert not nf.validate_webhook_url("ftp://example.com/x")[0]
    assert not nf.validate_webhook_url("javascript:alert(1)")[0]
    assert not nf.validate_webhook_url("file:///etc/passwd")[0]
    assert not nf.validate_webhook_url("")[0]


def test_missing_host():
    assert not nf.validate_webhook_url("http://")[0]


def test_blocks_loopback_linklocal_metadata_unspecified():
    # literal IPs → getaddrinfo resolves them offline, no network needed
    for u in ("http://127.0.0.1:8080/x", "http://[::1]/x",
              "http://169.254.169.254/latest/meta-data/", "http://0.0.0.0/x"):
        ok, why = nf.validate_webhook_url(u)
        assert not ok, (u, why)


def test_allows_public_host(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _gai("93.184.216.34"))
    ok, why = nf.validate_webhook_url("https://example.com/hooks/abc")
    assert ok, why


def test_blocks_when_name_resolves_to_metadata(monkeypatch):
    # DNS-rebind-ish: a benign-looking name pointing at the metadata IP
    monkeypatch.setattr(socket, "getaddrinfo", _gai("169.254.169.254"))
    ok, why = nf.validate_webhook_url("http://totally-fine.example.com/x")
    assert not ok
    assert "169.254.169.254" in why


def test_private_lan_allowed_by_default():
    # HomeSOC commonly posts to a self-hosted Mattermost on the LAN
    assert nf.validate_webhook_url("http://10.0.0.213:8065/hooks/x")[0]
    assert nf.validate_webhook_url("http://192.168.1.10/hooks/x")[0]
    assert nf.validate_webhook_url("http://172.16.5.5/hooks/x")[0]


def test_private_blocked_when_disabled(monkeypatch):
    monkeypatch.setattr(nf, "_ALLOW_PRIVATE", False)
    assert not nf.validate_webhook_url("http://10.0.0.213:8065/hooks/x")[0]
    # ...but public still allowed
    monkeypatch.setattr(socket, "getaddrinfo", _gai("93.184.216.34"))
    assert nf.validate_webhook_url("https://chat.example.com/x")[0]


def test_ip_is_blocked_unit():
    assert nf._ip_is_blocked("127.0.0.1")
    assert nf._ip_is_blocked("169.254.169.254")
    assert nf._ip_is_blocked("224.0.0.1")        # multicast
    assert nf._ip_is_blocked("not-an-ip")         # unparseable → block
    assert not nf._ip_is_blocked("8.8.8.8")
    assert not nf._ip_is_blocked("10.0.0.1")      # private allowed by default
