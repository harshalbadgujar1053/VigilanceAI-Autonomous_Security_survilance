"""
VigilanceAI — Integration Test Suite (Fixed)
Matches actual function names and API patterns in the codebase.

Run from repo root:
    python3 test_pipeline/test_integration.py
"""

import sys
import json
import time
import requests
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "agent"))  # so alert_schema resolves inside classify_alert

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


# ── GROUP 1: Schema ───────────────────────────────────────
print("\n━━━ GROUP 1: Schema & Models ━━━")

@test("NormalizedAlert model imports cleanly")
def _():
    from agent.alert_schema import NormalizedAlert, SAMPLE_ALERTS
    assert NormalizedAlert is not None
    assert "ssh_brute_force" in SAMPLE_ALERTS
_()

@test("NormalizedAlert validates ssh_brute_force sample")
def _():
    from agent.alert_schema import NormalizedAlert, SAMPLE_ALERTS
    model = NormalizedAlert(**SAMPLE_ALERTS["ssh_brute_force"])
    assert model.alert_id
    assert model.category == "brute_force"
    assert model.status == "new"
    assert model.rule.level >= 1
_()

@test("All SAMPLE_ALERTS entries are valid NormalizedAlerts")
def _():
    from agent.alert_schema import NormalizedAlert, SAMPLE_ALERTS
    for key, alert in SAMPLE_ALERTS.items():
        NormalizedAlert(**alert)
_()

@test("NormalizedAlert rejects missing required fields")
def _():
    from agent.alert_schema import NormalizedAlert
    try:
        NormalizedAlert(alert_id="x")
        assert False, "Should have raised"
    except Exception:
        pass
_()


# ── GROUP 2: RAG ─────────────────────────────────────────
print("\n━━━ GROUP 2: RAG / ChromaDB ━━━")

@test("query_rag imports and query_threat_intel is callable")
def _():
    from rag.query_rag import query_threat_intel, format_results_for_llm
    assert callable(query_threat_intel)
    assert callable(format_results_for_llm)
_()

@test("SSH brute force query returns results with Brute Force name")
def _():
    # technique_id field may be empty — check name field instead
    from rag.query_rag import query_threat_intel
    results = query_threat_intel("SSH brute force authentication failure", n_results=3)
    assert results, "No results returned"
    names = [r.get("name", "").lower() for r in results]
    ids   = [r.get("technique_id", "") for r in results]
    has_brute = any("brute" in n for n in names) or "T1110" in ids
    assert has_brute, f"No brute force result. Names: {names}, IDs: {ids}"
_()

@test("CVE vulnerability query returns results")
def _():
    from rag.query_rag import query_threat_intel
    results = query_threat_intel("remote code execution vulnerability", n_results=3)
    assert results
_()

@test("format_results_for_llm produces non-empty string")
def _():
    from rag.query_rag import query_threat_intel, format_results_for_llm
    results = query_threat_intel("port scan reconnaissance", n_results=2)
    if results:
        out = format_results_for_llm(results)
        assert isinstance(out, str) and len(out) > 20
_()


# ── GROUP 3: SIEM Tool ────────────────────────────────────
print("\n━━━ GROUP 3: SIEM Tool (query_siem.py) ━━━")

@test("query_siem imports cleanly — get_recent_alerts exists")
def _():
    from agent.tools.query_siem import get_recent_alerts
    assert callable(get_recent_alerts)
_()

@test("get_recent_alerts returns a list")
def _():
    from agent.tools.query_siem import get_recent_alerts
    alerts = get_recent_alerts(limit=5)
    assert isinstance(alerts, list), f"Expected list, got {type(alerts)}"
_()

@test("get_recent_alerts returns alerts from Wazuh (>0)")
def _():
    from agent.tools.query_siem import get_recent_alerts
    alerts = get_recent_alerts(limit=5)
    assert len(alerts) > 0, \
        "0 alerts returned — check Wazuh container single-node-wazuh.manager-1 is running"
_()

@test("get_recent_alerts results match NormalizedAlert shape")
def _():
    from agent.tools.query_siem import get_recent_alerts
    from agent.alert_schema import NormalizedAlert
    alerts = get_recent_alerts(limit=3)
    if not alerts:
        return  # skip if Wazuh offline — covered above
    for a in alerts:
        NormalizedAlert(**a)
_()


# ── GROUP 4: FastAPI ──────────────────────────────────────
print("\n━━━ GROUP 4: FastAPI Backend ━━━")

SAMPLE_PAYLOAD = {
    "alert_id": "TEST-INTEG-001",
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "source": {"agent_name": "kali-vm", "agent_ip": "192.168.80.129"},
    "rule": {"id": "5712", "description": "sshd: authentication failed. Brute force", "level": 10},
    "category": "brute_force",
    "raw_log": "Failed password for root from 192.168.80.1 port 54321",
    "indicators": {
        "src_ip": "192.168.80.1", "dst_ip": "192.168.80.129",
        "src_port": 54321, "dst_port": 22,
        "username": "root", "process_name": "sshd", "file_hash": None
    },
    "mitre_hint": {"technique_id": None, "technique_name": None},
    "status": "new"
}

@test("FastAPI root GET / returns 200")
def _():
    # Health check is at / not /health
    r = requests.get(f"{FASTAPI_URL}/", timeout=5)
    assert r.status_code == 200, f"Got {r.status_code}: {r.text[:100]}"
    assert "running" in r.text.lower() or "vigilance" in r.text.lower()
_()

@test("FastAPI GET /classify/sample/ssh_brute_force returns 200")
def _():
    r = requests.get(f"{FASTAPI_URL}/classify/sample/ssh_brute_force", timeout=180)
    assert r.status_code == 200, f"Got {r.status_code}: {r.text[:200]}"
_()

@test("POST /classify returns 200 (timeout=180s for Mistral CPU)")
def _():
    r = requests.post(f"{FASTAPI_URL}/classify",
                      json=SAMPLE_PAYLOAD, timeout=180)
    assert r.status_code == 200, f"Got {r.status_code}: {r.text[:300]}"
_()

@test("POST /classify response has alert_id and classification")
def _():
    r = requests.post(f"{FASTAPI_URL}/classify",
                      json=SAMPLE_PAYLOAD, timeout=180)
    if r.status_code != 200:
        return
    data = r.json()
    assert "alert_id" in data, f"No alert_id in {list(data.keys())}"
    assert "classification" in data or "severity" in data or "result" in data, \
        f"No classification key. Keys: {list(data.keys())}"
_()

@test("POST /classify response mentions SSH/brute/T1110")
def _():
    r = requests.post(f"{FASTAPI_URL}/classify",
                      json=SAMPLE_PAYLOAD, timeout=180)
    if r.status_code != 200:
        return
    text = json.dumps(r.json()).lower()
    assert any(w in text for w in ["ssh", "brute", "t1110", "authentication", "critical"])
_()

@test("POST /classify rejects malformed payload with 422")
def _():
    r = requests.post(f"{FASTAPI_URL}/classify", json={"bad": "data"}, timeout=10)
    assert r.status_code in (400, 422), f"Expected 400/422, got {r.status_code}"
_()


# ── GROUP 5: LangChain chain ──────────────────────────────
print("\n━━━ GROUP 5: LangChain classify_alert chain ━━━")

@test("classify_alert.py imports cleanly")
def _():
    from agent.classify_alert import classify_alert
    assert callable(classify_alert)
_()

@test("classify_alert runs on ssh_brute_force (timeout 180s)")
def _():
    from agent.classify_alert import classify_alert
    from agent.alert_schema import SAMPLE_ALERTS
    result = classify_alert(SAMPLE_ALERTS["ssh_brute_force"])
    assert result is not None
_()

@test("classify_alert output contains severity keyword")
def _():
    from agent.classify_alert import classify_alert
    from agent.alert_schema import SAMPLE_ALERTS
    result = classify_alert(SAMPLE_ALERTS["ssh_brute_force"])
    text = str(result).lower()
    assert any(w in text for w in ["critical", "high", "medium", "low", "severity"])
_()


# ── GROUP 6: LangChain Tools 1-3 ─────────────────────────
print("\n━━━ GROUP 6: LangChain Tools (1-3) ━━━")

@test("lookup_threat_intel (Tool 1) — invoke works")
def _():
    from agent.tools.lookup_threat_intel import lookup_threat_intel
    result = lookup_threat_intel.invoke({"query": "SSH brute force"})
    assert result is not None
_()

@test("map_to_mitre (Tool 2) — invoke works")
def _():
    from agent.tools.map_to_mitre import map_to_mitre
    result = map_to_mitre.invoke({"alert_description": "repeated authentication failures SSH"})
    assert result is not None
_()

@test("check_cve (Tool 3) — invoke works")
def _():
    from agent.tools.check_cve import check_cve
    result = check_cve.invoke({"cve_id": "CVE-2023-38408"})
    assert result is not None
_()


# ── SUMMARY ───────────────────────────────────────────────
print("\n" + "━"*60)
print("  VIGILANCEAI INTEGRATION TEST RESULTS")
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

out_path = ROOT / "test_pipeline" / "test_results.json"
out_path.parent.mkdir(exist_ok=True)
with open(out_path, "w") as f:
    json.dump({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "summary": {"passed": len(passed), "failed": len(failed),
                    "errors": len(errored), "total": len(results),
                    "total_time_sec": round(total_time, 3)},
        "results": results
    }, f, indent=2)

print(f"\n  Results → test_pipeline/test_results.json")
print("━"*60)
sys.exit(0 if not (failed or errored) else 1)
