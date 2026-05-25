"""Tests for the SSH argument-injection guard in wazuh._ssh_argv / assert_safe_ssh.

The host/user/key come from the GUI-editable host_config, and land in the ssh
argv before "--", so a value starting with "-" would be parsed by ssh as an
option (e.g. -oProxyCommand=...). These tests assert such values are rejected.
"""
from __future__ import annotations

import pytest

import wazuh


def test_valid_components_build_expected_argv():
    argv = wazuh._ssh_argv("10.0.0.213", "wazuh", ["hostname"], key="/home/dev/.ssh/k")
    assert argv[0] == "ssh"
    assert "wazuh@10.0.0.213" in argv
    # the remote command is isolated after "--"
    assert argv[-2:] == ["--", "hostname"] or argv[argv.index("--") + 1:] == ["hostname"]
    # hostnames with dots/hyphens and ipv6 colons are allowed
    wazuh.assert_safe_ssh("nas-01.lan", "back-up_user", "/opt/dashboard/.ssh/id_ed25519")
    wazuh.assert_safe_ssh("fe80::1", "root", "~/.ssh/id")


@pytest.mark.parametrize("host", [
    "-oProxyCommand=touch /tmp/pwned",
    "-Fmalicious",
    "host;rm -rf",
    "host name",          # whitespace
    "host$(whoami)",
])
def test_malicious_host_rejected(host):
    with pytest.raises(ValueError):
        wazuh._ssh_argv(host, "wazuh", ["hostname"], key="/home/dev/.ssh/k")


@pytest.mark.parametrize("user", [
    "-oProxyCommand=evil",
    "-l",
    "user;evil",
    "us er",
])
def test_malicious_user_rejected(user):
    with pytest.raises(ValueError):
        wazuh._ssh_argv("10.0.0.213", user, ["hostname"], key="/home/dev/.ssh/k")


def test_malicious_key_rejected():
    with pytest.raises(ValueError):
        wazuh._ssh_argv("10.0.0.213", "wazuh", ["hostname"], key="-oProxyCommand=evil")


def test_assert_safe_ssh_is_public_and_strict():
    # used by backup.py for the NAS scp target
    wazuh.assert_safe_ssh("10.0.0.2", "admin", "/home/dev/.ssh/nas")
    with pytest.raises(ValueError):
        wazuh.assert_safe_ssh("-oProxyCommand=x", "admin", "/home/dev/.ssh/nas")
