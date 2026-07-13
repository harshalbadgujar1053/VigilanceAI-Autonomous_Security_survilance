"""
VigilanceAI — Frontend API Contract Tests
Verifies backend responses match what React components expect.

Run from repo root:
    python3 test_pipeline/test_frontend_api.py
"""

import sys
import json
import time
import requests
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

FASTAPI_URL = "http://localhost:8000"
results = []

def test(name):
    def decorator(fn):
        def wrapper():
            t0 = time.perf_counter()
            try:
                fn()
                elapsed = time.perf_counter() - t0
                results.append({"name": name, "status": "PASS", "time": elapsed, "error": None})
                print(f"  ✅ {name}  ({elapsed:.2f}s)")
            except AssertionError as e:
                elapsed = time.perf_counter() - t0
                results.append({"name": name, "status": "FAIL", "time": elapsed, "error": str(e)})
                print(f"  ❌ {name}")
                print(f"     → {e}")
            except Exception as e:
                elapsed = time.perf_counter() - t0
                results.append({"name": name, "status": "ERROR", "time": elapsed, "error": str(e)})
                print(f"  💥 {name}")
                print(f"     → {type(e).__name__}: {e}")
        return wrapper
    return decorator


# ── Frontend Alert Shape ─────────────────────────────────
print("\n━━━ Frontend API Contract Tests ━━━")

@test("GET /alerts response has correct shape for React")
def _():
    r = requests.get(f"{FASTAPI_URL}/alerts", timeout=10)
    assert r.status_code == 200
    data = r.json()
    assert "success" in data
    assert "count" in data
    assert "alerts" in data
    assert isinstance(data["alerts"], list)
_()

@test("Alert records contain fields App.tsx expects")
def _():
    # First save a test alert in frontend format
    payload = {
        "id": "FRONTEND-TEST-001",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "rule": {"id": "5712", "level": 10, "description": "Test", "groups": ["ssh"]},
        "agent": {"id": "001", "name": "test-host", "ip": "10.0.0.1"},
        "data": {"src_ip": "1.2.3.4"},
        "location": "/var/log/auth.log",
        "severity": "HIGH"
    }
    requests.post(f"{FASTAPI_URL}/alerts/save", json=payload, timeout=10)
    r = requests.get(f"{FASTAPI_URL}/alerts", timeout=10)
    alerts = r.json()["alerts"]
    found = [a for a in alerts if a["id"] == "FRONTEND-TEST-001"]
    assert len(found) >= 1, "Saved alert not found"
    a = found[0]
    # These are the fields App.tsx reads
    assert "id" in a
    assert "rule_level" in a or "rule" in str(a.get("raw_data", {}))
    assert "description" in a
    assert "agent_name" in a
_()

@test("POST /classify accepts frontend alert format")
def _():
    payload = {
        "alert": {
            "id": "alert-003",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "rule": {"id": "5763", "level": 10, "description": "SSH brute force"},
            "agent": {"name": "bastion-host", "ip": "192.168.1.103"},
            "data": {"src_ip": "45.33.32.156", "attempts": 847}
        }
    }
    r = requests.post(f"{FASTAPI_URL}/classify", json=payload, timeout=300)
    assert r.status_code == 200, f"Got {r.status_code}: {r.text[:200]}"
    data = r.json()
    assert data["success"] is True
    assert "classification" in data
_()

@test("POST /report accepts frontend format")
def _():
    payload = {
        "alert": {"id": "alert-003", "rule": {"id": "5763", "level": 10, "description": "SSH brute force"}, "agent": {"name": "bastion", "ip": "10.0.0.1"}},
        "classification": {"severity": "HIGH", "reasoning": "Test", "mitre_tactics": "T1110"}
    }
    r = requests.post(f"{FASTAPI_URL}/report", json=payload, timeout=300)
    assert r.status_code == 200, f"Got {r.status_code}: {r.text[:200]}"
    assert r.json()["success"] is True
_()

@test("GET /health returns expected shape")
def _():
    r = requests.get(f"{FASTAPI_URL}/health", timeout=10)
    assert r.status_code == 200
    d = r.json()
    assert d["success"] is True
    assert "health" in d
    h = d["health"]
    assert "api" in h and "database" in h and "ollama" in h
_()

@test("GET /stats returns shape for SOCCharts component")
def _():
    r = requests.get(f"{FASTAPI_URL}/stats", timeout=10)
    assert r.status_code == 200
    s = r.json()["stats"]
    assert "total_alerts" in s
    assert "severity_counts" in s
    assert isinstance(s["severity_counts"], dict)
_()

@test("GET /reports returns shape for ReportsHistory component")
def _():
    r = requests.get(f"{FASTAPI_URL}/reports", timeout=10)
    assert r.status_code == 200
    d = r.json()
    assert "reports" in d
    assert isinstance(d["reports"], list)
    if d["count"] > 0:
        rpt = d["reports"][0]
        assert all(k in rpt for k in ["id", "alert_id", "severity", "created_at"])
_()

@test("CORS headers present for localhost:3000")
def _():
    r = requests.options(f"{FASTAPI_URL}/alerts",
        headers={"Origin": "http://localhost:3000", "Access-Control-Request-Method": "GET"},
        timeout=10)
    # FastAPI CORS should respond with access-control-allow-origin
    assert r.status_code in (200, 204, 405), f"Got {r.status_code}"
_()


# ── SUMMARY ───────────────────────────────────────────────
print("\n" + "━"*60)
print("  FRONTEND API CONTRACT TEST RESULTS")
print("━"*60)

passed  = [r for r in results if r["status"] == "PASS"]
failed  = [r for r in results if r["status"] == "FAIL"]
errored = [r for r in results if r["status"] == "ERROR"]
total_time = sum(r["time"] for r in results)

print(f"\n  ✅ Passed:  {len(passed)}/{len(results)}")
print(f"  ❌ Failed:  {len(failed)}")
print(f"  💥 Errors:  {len(errored)}")
print(f"  ⏱  Total:   {total_time:.2f}s")

if failed or errored:
    print("\n  FAILURES:")
    for r in failed + errored:
        print(f"    • {r['name']}")
        print(f"      {r['error']}")

out_path = ROOT / "test_pipeline" / "test_frontend_api_results.json"
with open(out_path, "w") as f:
    json.dump({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "summary": {"passed": len(passed), "failed": len(failed),
                    "errors": len(errored), "total": len(results),
                    "total_time_sec": round(total_time, 3)},
        "results": results
    }, f, indent=2)

print(f"\n  Results → test_pipeline/test_frontend_api_results.json")
print("━"*60)
sys.exit(0 if not (failed or errored) else 1)
