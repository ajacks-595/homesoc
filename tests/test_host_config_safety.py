"""host_config SSH-field validation (argument-injection guard at storage time).

Regression test for the host_config_test probe that previously built an ssh
argv without assert_safe_ssh, and for the new central guard in
config.host_config_set.
"""
import pytest

import wazuh


def test_assert_safe_host_config_allows_good_and_empty():
    # empty values are allowed (mean "unset / use default")
    wazuh.assert_safe_host_config({
        "wazuh_host": "10.0.0.213", "wazuh_user": "wazuh",
        "claudedev_host": "siem.local", "ssh_key_path": "/home/dev/.ssh/k",
        "adguard_host": "", "adguard_user": "",
        # command-path fields are not SSH options → not constrained here
        "siem_scripts_dir": "/opt/siem/scripts", "claude_cli_path": "/usr/local/bin/claude",
    })


@pytest.mark.parametrize("cfg", [
    {"wazuh_host": "-oProxyCommand=evil"},
    {"claudedev_host": "-oProxyCommand=touch /tmp/pwn"},
    {"wazuh_user": "-oProxyCommand=x"},
    {"adguard_user": "root;rm -rf /"},
    {"ssh_key_path": "-oProxyCommand=x"},
    {"wazuh_host": "host with space"},
    {"adguard_host": "evil$(whoami)"},
])
def test_assert_safe_host_config_rejects_injection(cfg):
    with pytest.raises(ValueError):
        wazuh.assert_safe_host_config(cfg)


def test_host_config_set_rejects_unsafe(tmp_db):
    import config
    with pytest.raises(ValueError):
        config.host_config_set({"wazuh_host": "-oProxyCommand=evil"})
    # nothing unsafe should have been persisted
    assert config.host_config().get("wazuh_host", "") != "-oProxyCommand=evil"


def test_host_config_set_accepts_safe(tmp_db):
    import config
    config.host_config_set({"wazuh_host": "10.0.0.213", "wazuh_user": "wazuh"})
    assert config.host_config().get("wazuh_host") == "10.0.0.213"
