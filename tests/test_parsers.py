"""Smoke tests for parsers.py — briefing extraction, IOC detection, alert parsing."""
import json
from pathlib import Path

import parsers


def test_detect_ioc_type_ipv4():
    assert parsers.detect_ioc_type("8.8.8.8") == "ipv4"
    assert parsers.detect_ioc_type("185.213.175.176") == "ipv4"


def test_detect_ioc_type_domain():
    assert parsers.detect_ioc_type("evil.example.com") == "domain"
    assert parsers.detect_ioc_type("a.b.c.d.example.org") == "domain"


def test_detect_ioc_type_hashes():
    assert parsers.detect_ioc_type("d41d8cd98f00b204e9800998ecf8427e") == "md5"
    assert parsers.detect_ioc_type("a" * 40) == "sha1"
    assert parsers.detect_ioc_type("b" * 64) == "sha256"


def test_detect_ioc_type_url():
    assert parsers.detect_ioc_type("https://example.com/path") == "url"
    assert parsers.detect_ioc_type("http://1.2.3.4:8080/x") == "url"


def test_detect_ioc_type_unknown():
    assert parsers.detect_ioc_type("not an ioc") == "unknown"
    assert parsers.detect_ioc_type("") == "unknown"


def test_briefing_action_extraction():
    sample = """
# Daily Briefing 2026-01-01

## Recommended Actions

**P1**
- Investigate the suspicious login from 1.2.3.4

**P2**
- Patch CVE-2026-XXXXX on cloudron
- Review the new sudoers entry

**P3**
- Tune the noisy rule 12345
"""
    actions = parsers.extract_recommended_actions(sample)
    priorities = [a["priority"] for a in actions]
    assert priorities.count("P1") == 1
    assert priorities.count("P2") == 2
    assert priorities.count("P3") == 1
    assert any("1.2.3.4" in a["description"] for a in actions)


def test_briefing_assessment():
    no_actions = []
    p3_only = [{"priority": "P3", "description": "x"}]
    p2_present = [{"priority": "P2", "description": "y"}]
    p1_present = [{"priority": "P1", "description": "z"}]

    assert parsers.assess_briefing(no_actions) == "clean"
    assert parsers.assess_briefing(p3_only) == "clean"
    assert parsers.assess_briefing(p2_present) == "notable"
    assert parsers.assess_briefing(p1_present) == "action_required"


def test_briefing_date_from_filename():
    assert parsers.briefing_date_from_filename(Path("2026-05-21.md")) == ("2026-05-21", "daily")
    assert parsers.briefing_date_from_filename(Path("weekly-2026-05-21.md")) == ("2026-05-21", "weekly")


def test_wazuh_alert_parsing():
    line = json.dumps({
        "timestamp": "2026-05-21T12:34:56.789+0000",
        "rule": {"id": "1234", "level": 7, "description": "Test alert",
                 "groups": ["test", "smoke"]},
        "agent": {"id": "001", "name": "host-a", "ip": "10.0.0.1"},
        "id": "wzh-id-1",
        "full_log": "the log line",
        "location": "/var/log/test.log",
    })
    parsed = parsers.parse_wazuh_alert_line(line)
    assert parsed["rule_id"] == "1234"
    assert parsed["rule_level"] == 7
    assert parsed["agent_name"] == "host-a"
    assert parsed["agent_ip"] == "10.0.0.1"
    assert parsed["wazuh_id"] == "wzh-id-1"
    assert parsed["timestamp"] == "2026-05-21T12:34:56"


def test_wazuh_alert_invalid_lines_skipped():
    bad = parsers.parse_wazuh_alert_line("not json")
    assert bad is None
    empty = parsers.parse_wazuh_alert_line("")
    assert empty is None


def test_context_md_parsing():
    sample = """
# My Network

| IP | Hostname | Role | Notes |
|---|---|---|---|
| 10.0.0.1 | router | Gateway | Main router |
| 10.0.0.2 | nas    | Storage | Synology |
"""
    hosts = parsers.parse_context_md(sample)
    assert len(hosts) == 2
    assert hosts[0]["ip"] == "10.0.0.1"
    assert hosts[0]["hostname"] == "router"
    assert hosts[1]["role"] == "Storage"


def test_adguard_line_parsing():
    lines = [
        '{"T":"2026-05-21T12:00:00Z","QH":"example.com","QT":"A","IP":"10.0.0.10","Result":{"IsFiltered":false},"Elapsed":12345}',
        '{"T":"2026-05-21T12:00:01Z","QH":"blocked.example.com","QT":"A","IP":"10.0.0.10","Result":{"IsFiltered":true},"Elapsed":1234}',
        "not json",
        "",
    ]
    parsed = parsers.parse_adguard_lines(lines)
    assert len(parsed) == 2
    assert parsed[0]["qh"] == "example.com"
    assert parsed[0]["blocked"] is False
    assert parsed[1]["blocked"] is True
