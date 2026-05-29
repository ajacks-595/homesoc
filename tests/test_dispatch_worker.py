"""AI enrichment + webhook delivery run off the alerts-poller critical path
via a background dispatch worker, with a synchronous fallback (B3)."""
import json
import threading

import sync


def test_enqueue_runs_synchronously_without_worker(monkeypatch):
    sync._dispatch_worker_thread = None   # ensure no worker (one-shot mode)
    called = []
    monkeypatch.setattr(sync, "_dispatch_new_alerts", lambda ids: called.append(set(ids)))
    sync._enqueue_dispatch({"a", "b"})
    assert called == [{"a", "b"}]         # ran inline, not lost


def test_enqueue_uses_worker_when_running(monkeypatch):
    called, ev = [], threading.Event()

    def fake(ids):
        called.append(set(ids))
        ev.set()

    monkeypatch.setattr(sync, "_dispatch_new_alerts", fake)
    sync._start_dispatch_worker()
    try:
        sync._enqueue_dispatch({"x", "y"})
        assert ev.wait(timeout=5), "worker did not process the batch"
        sync._dispatch_q.join()
        assert called == [{"x", "y"}]
    finally:
        sync._dispatch_q.put(None)        # stop sentinel
        if sync._dispatch_worker_thread:
            sync._dispatch_worker_thread.join(timeout=5)
        sync._dispatch_worker_thread = None


def test_sync_recent_alerts_hands_off_to_enqueue(tmp_db, monkeypatch):
    import wazuh
    alert = json.dumps({
        "id": "987654", "timestamp": "2026-05-29T12:00:00.000+0000",
        "rule": {"id": 5710, "level": 12, "description": "test"},
        "agent": {"name": "host-a", "ip": "10.0.0.1"},
        "full_log": "x", "location": "/var/log/x",
    })
    monkeypatch.setattr(wazuh, "fetch_alerts_tail", lambda **k: alert)
    enq = []
    monkeypatch.setattr(sync, "_enqueue_dispatch", lambda ids: enq.append(set(ids)))
    res = sync.sync_recent_alerts()
    assert res["inserted"] == 1
    assert enq == [{"987654"}]   # dispatch handed off, not run inline in the poller
