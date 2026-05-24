"""Tests for the local_rules.xml suppression helpers in wazuh.py.

The key property: insert_into_group() and remove_rule_from_xml() are exact
inverses, so the FP manager (web UI + MCP) can add and delete suppressions
without the file drifting whitespace on each cycle. These are pure string
functions — no DB or SSH needed.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET

import wazuh

# A realistic, normalised local_rules.xml: comment header, one detection rule
# and one suppression rule, each block separated by a single blank line, with a
# blank line before </group>. Mirrors the real Wazuh manager layout.
NORMALISED = (
    "<!-- Local rules -->\n"
    "\n"
    "<!-- Modify it at your will. -->\n"
    '<group name="local,syslog,sshd,">\n'
    "\n"
    '  <rule id="100001" level="5">\n'
    "    <if_sid>5716</if_sid>\n"
    "    <description>sshd: auth failed from 1.1.1.1.</description>\n"
    "  </rule>\n"
    "\n"
    '  <rule id="100190" level="0">\n'
    "    <if_sid>19007</if_sid>\n"
    "    <description>SCA individual finding suppressed</description>\n"
    "  </rule>\n"
    "\n"
    "</group>\n"
)


def _valid(xml: str) -> None:
    """Raises if the fragment isn't well-formed (wrapped so multiple top-level
    nodes parse)."""
    ET.fromstring(f"<root>{xml}</root>")


def _add(xml: str, parent="533", desc="netstat churn", agent=None) -> tuple[str, str]:
    rid = wazuh.next_local_rule_id(xml)
    snippet = wazuh.build_suppression(parent, agent, desc, rid)
    return wazuh.insert_into_group(xml, snippet), rid


def test_add_then_remove_is_byte_exact():
    added, rid = _add(NORMALISED)
    _valid(added)
    assert f'rule id="{rid}"' in added
    restored = wazuh.remove_rule_from_xml(added, rid)
    assert restored == NORMALISED, "add followed by remove must restore the file exactly"


def test_added_rule_is_blank_line_separated():
    added, rid = _add(NORMALISED)
    # exactly one blank line before the new rule and before </group>
    assert f'</rule>\n\n  <rule id="{rid}"' in added
    assert "</rule>\n\n</group>\n" in added
    # no triple newline anywhere
    assert "\n\n\n" not in added


def test_drifted_file_self_heals_then_is_stable():
    """Starting from a file that lost its blank line before </group> (the old
    bug's output), one add/remove cycle heals it to the normalised form, and
    further cycles are byte-stable."""
    drifted = NORMALISED.replace("</rule>\n\n</group>", "</rule>\n</group>")
    assert drifted != NORMALISED

    added, rid = _add(drifted)
    healed = wazuh.remove_rule_from_xml(added, rid)
    assert healed == NORMALISED

    # second cycle on the healed file is a perfect round-trip
    added2, rid2 = _add(healed)
    assert wazuh.remove_rule_from_xml(added2, rid2) == healed


def test_remove_middle_rule_leaves_single_blank_line():
    added1, rid1 = _add(NORMALISED)             # 100191
    added2, rid2 = _add(added1)                 # 100192 (appended after 100191)
    _valid(added2)
    # remove the middle one (rid1); spacing around the gap stays single-blank
    pruned = wazuh.remove_rule_from_xml(added2, rid1)
    _valid(pruned)
    assert "\n\n\n" not in pruned
    assert f'rule id="{rid1}"' not in pruned
    assert f'rule id="{rid2}"' in pruned
    # removing the last one too returns to the original
    assert wazuh.remove_rule_from_xml(pruned, rid2) == NORMALISED


def test_remove_nonexistent_rule_is_noop():
    assert wazuh.remove_rule_from_xml(NORMALISED, "999999") == NORMALISED


def test_scaffold_when_no_group_present():
    snippet = wazuh.build_suppression("5710", None, "x", "100000")
    built = wazuh.insert_into_group("", snippet)
    _valid(built)
    assert 'rule id="100000"' in built
    assert "\n\n\n" not in built
    # removing it leaves a (valid, empty) group
    emptied = wazuh.remove_rule_from_xml(built, "100000")
    _valid(emptied)
    assert 'rule id="100000"' not in emptied


def test_agent_scoped_round_trip():
    added, rid = _add(NORMALISED, parent="5710", desc="ssh noise", agent="host-a")
    _valid(added)
    assert 'name="agent.name">host-a<' in added
    assert wazuh.remove_rule_from_xml(added, rid) == NORMALISED
