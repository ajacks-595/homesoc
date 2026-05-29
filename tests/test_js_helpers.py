"""Run the node-based JS helper assertions (XSS-defense functions in main.js).

Skipped automatically if `node` isn't on PATH, so the Python-only CI still
passes; runs the real assertions wherever node is available (local dev, and CI
images that include node).
"""
import shutil
import subprocess
from pathlib import Path

import pytest

_NODE = shutil.which("node")
_TEST = Path(__file__).parent / "js" / "helpers.test.mjs"


@pytest.mark.skipif(_NODE is None, reason="node not installed")
def test_js_security_helpers():
    cp = subprocess.run([_NODE, str(_TEST)], capture_output=True, text=True, timeout=60)
    print(cp.stdout)
    print(cp.stderr)
    assert cp.returncode == 0, "JS helper assertions failed:\n" + cp.stdout + cp.stderr
