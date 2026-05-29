"""poller_status() returns a locked deep-copy snapshot, not the live dict (B5)."""
import threading

import sync


def test_poller_status_returns_deep_copy():
    snap = sync.poller_status()
    assert set(snap["state"].keys()) == {"alerts", "dns", "agents", "briefings"}
    # mutating the returned snapshot must not affect module state
    snap["state"]["alerts"]["last_result"] = "TAMPERED"
    assert sync._poller_state["alerts"]["last_result"] != "TAMPERED"


def test_poller_status_concurrent_smoke():
    stop = threading.Event()

    def writer():
        i = 0
        while not stop.is_set():
            i += 1
            with sync._poller_lock:
                sync._poller_state["alerts"]["last_result"] = {"n": i}

    t = threading.Thread(target=writer, daemon=True)
    t.start()
    try:
        for _ in range(300):
            s = sync.poller_status()
            assert "alerts" in s["state"]      # consistent shape, no torn read/crash
    finally:
        stop.set()
        t.join(timeout=2)
