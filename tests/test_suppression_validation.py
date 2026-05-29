"""build_suppression must reject non-numeric rule ids (XML-injection guard).

parent_rule_id/new_rule_id are interpolated into local_rules.xml unescaped, so
a crafted rule_id like '5710"><rule id="9..."' could inject XML. They are now
hard-constrained to integers (Wazuh rule IDs always are).
"""
import pytest

import wazuh


def test_rejects_xml_injection_payload():
    payload = '5710</if_sid><description>x</description></rule><rule id="199999" level="15"><if_sid>5710'
    with pytest.raises(ValueError):
        wazuh.build_suppression(payload, None, "evil", "100001")


@pytest.mark.parametrize("bad", ["51&0", "5<10", "abc", "", "100 001", "10;rm", '5"', None])
def test_rejects_non_numeric_parent(bad):
    with pytest.raises(ValueError):
        wazuh.build_suppression(bad, None, "x", "100001")


def test_rejects_non_numeric_new_rid():
    with pytest.raises(ValueError):
        wazuh.build_suppression("5710", None, "x", "10000x")


def test_numeric_parent_ok_and_round_trips():
    snip = wazuh.build_suppression("5710", None, "noisy auth rule", "100001")
    assert "<if_sid>5710</if_sid>" in snip
    assert 'rule id="100001"' in snip
    parsed = wazuh.parse_existing_suppressions(snip)
    assert parsed and parsed[0]["rule_id"] == "5710"


def test_agent_scoped_ok():
    snip = wazuh.build_suppression("5710", "host-a", "desc", "100002")
    assert '<field name="agent.name">host-a</field>' in snip
    # description metachars are still escaped
    snip2 = wazuh.build_suppression("5710", None, "a < b & c", "100003")
    assert "&lt;" in snip2 and "&amp;" in snip2
