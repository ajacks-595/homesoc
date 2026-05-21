"""Smoke tests for ai.py — IOC extraction, cross-log enrichment.

These don't invoke the Claude CLI (no live API calls); they test the
local pre-processing logic.
"""


def test_extract_iocs_finds_external_ips():
    import ai
    alert = {
        "data": {
            "srcip": "185.213.175.176",
            "dstip": "10.0.0.1",   # RFC1918 — should be skipped
        },
    }
    iocs = ai._extract_iocs(alert)
    assert "185.213.175.176" in iocs["ipv4"]
    assert "10.0.0.1" not in iocs["ipv4"]


def test_extract_iocs_finds_domains():
    import ai
    alert = {
        "data": {
            "domain": "evil.example.com",
            "host": "another.example.org",
        },
    }
    iocs = ai._extract_iocs(alert)
    assert "evil.example.com" in iocs["domain"]


def test_extract_iocs_finds_hashes():
    import ai
    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    alert = {"data": {"md5": md5, "sha256": sha256}}
    iocs = ai._extract_iocs(alert)
    assert md5 in iocs["hash"]
    assert sha256 in iocs["hash"]


def test_extract_iocs_handles_nested():
    import ai
    alert = {
        "data": {
            "nested": {
                "deeper": {
                    "ip": "1.1.1.1",
                },
            },
        },
    }
    iocs = ai._extract_iocs(alert)
    assert "1.1.1.1" in iocs["ipv4"]
