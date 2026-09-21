"""
Queue-aware load test. Fires real Wazuh alert samples at /alerts/save
(the real production ingestion path) as fast as Locust's concurrency allows.
Ingestion should succeed near-instantly regardless of load — that's the
claim to verify. Classification throughput is now bounded by the 15/min
queue worker, so it's measured SEPARATELY (see queue_drain_monitor.py),
not as part of this Locust run.

Usage:
    locust -f locustfile.py --host http://192.168.80.129:8001
"""
import glob
import json
import random
import time
import uuid

from locust import HttpUser, task, between, events

ALERT_SAMPLES_DIR = "./alert_samples/*.json"

_samples = []


@events.test_start.add_listener
def load_samples(environment, **kwargs):
    global _samples
    paths = glob.glob(ALERT_SAMPLES_DIR)
    if not paths:
        raise RuntimeError(f"No alert samples at {ALERT_SAMPLES_DIR}.")
    for p in paths:
        with open(p) as f:
            _samples.append(json.load(f))
    print(f"Loaded {len(_samples)} real Wazuh alert samples")


def _mutate(alert: dict) -> dict:
    a = json.loads(json.dumps(alert))
    a["id"] = str(uuid.uuid4())
    a.setdefault("timestamp", time.strftime("%Y-%m-%dT%H:%M:%S%z"))
    return a


class IngestionLoad(HttpUser):
    """Only exercises the real production write path: /alerts/save.
    Classification is handled asynchronously by the queue worker and is
    NOT triggered directly here — that would bypass the real system design
    (the old locustfile.py's classify_and_save task hitting /classify
    directly has been removed, since it no longer reflects how alerts
    actually flow through the system)."""
    wait_time = between(0.02, 0.1)  # aggressive — this is what we're stress-testing

    @task(5)
    def save_alert(self):
        alert = _mutate(random.choice(_samples))
        with self.client.post("/alerts/save", json=alert, catch_response=True) as resp:
            if resp.status_code not in (200, 201):
                resp.failure(f"/alerts/save failed: {resp.status_code} {resp.text[:200]}")
            else:
                resp.success()

    @task(1)
    def read_alerts_paginated(self):
        with self.client.get("/alerts", params={"limit": 20}, catch_response=True,
                              name="/alerts (read)") as resp:
            if resp.status_code != 200:
                resp.failure(f"Read path degraded: {resp.status_code}")
            else:
                resp.success()
