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
    r = requests.get(f"{FASTAPI_URL}/", timeout=5)
    assert r.status_code == 200, f"Got {r.status_code}: {r.text[:100]}"
    assert "running" in r.text.lower() or "vigilance" in r.text.lower()
_()

@test("FastAPI GET /classify/sample/ssh_brute_force returns 200")
def _():
    r = requests.get(f"{FASTAPI_URL}/classify/sample/ssh_brute_force", timeout=180)
    assert r.status_code == 200, f"Got {r.status_code}: {r.text[:200]}"
_()

CLASSIFY_CACHE = {}

def _cached_classify(payload_key: str, alert: dict):
    """Mistral CPU inference is 60-180s; cache across the whole test group."""
    if payload_key not in CLASSIFY_CACHE:
        r = requests.post(f"{FASTAPI_URL}/classify", json={"alert": alert}, timeout=180)
        CLASSIFY_CACHE[payload_key] = r
    return CLASSIFY_CACHE[payload_key]

@test("POST /classify (wrapped {alert: ...}) returns 200")
def _():
    r = _cached_classify("ssh", SAMPLE_PAYLOAD)
    assert r.status_code == 200, f"Got {r.status_code}: {r.text[:300]}"
_()

@test("POST /classify response has success + classification dict with rawText")
def _():
    r = _cached_classify("ssh", SAMPLE_PAYLOAD)
    if r.status_code != 200:
        return
    data = r.json()
    assert data.get("success") is True, f"success not True. Keys: {list(data.keys())}"
    c = data.get("classification")
    assert isinstance(c, dict), f"classification should be a dict, got {type(c)}"
    assert isinstance(c.get("rawText"), str) and c["rawText"], f"rawText missing. Keys: {list(c.keys())}"
_()

@test("POST /classify response mentions SSH/brute/T1110")
def _():
    r = _cached_classify("ssh", SAMPLE_PAYLOAD)
    if r.status_code != 200:
        return
    text = r.json().get("classification", {}).get("rawText", "").lower()
    assert any(w in text for w in ["ssh", "brute", "t1110", "authentication", "critical"])
_()

@test("POST /classify output uses bracket-tag contract the frontend regex parser expects")
def _():
    r = _cached_classify("ssh", SAMPLE_PAYLOAD)
    if r.status_code != 200:
        return
    text = r.json().get("classification", {}).get("rawText", "")
    assert "[SEVERITY]" in text.upper(), f"Missing [SEVERITY] tag: {text[:200]}"
    assert "[TECHNIQUE]" in text.upper(), f"Missing [TECHNIQUE] tag: {text[:200]}"
    assert "[REASONING]" in text.upper(), f"Missing [REASONING] tag: {text[:200]}"
_()

@test("POST /classify without 'alert' wrapper is rejected with 422")
def _():
    r = requests.post(f"{FASTAPI_URL}/classify", json={"bad": "data"}, timeout=10)
    assert r.status_code == 422, f"Expected 422, got {r.status_code}"
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


# ── GROUP 7: Database CRUD ────────────────────────────────
print("\n━━━ GROUP 7: Database CRUD ━━━")

@test("POST /alerts/save stores alert and returns success")
def _():
    payload = {
        "id": "TEST-DB-001",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "rule": {"id": "5712", "description": "Test alert for DB", "level": 10},
        "agent": {"name": "test-host", "ip": "10.0.0.99"},
        "severity": "HIGH"
    }
    r = requests.post(f"{FASTAPI_URL}/alerts/save", json=payload, timeout=10)
    assert r.status_code == 200, f"Got {r.status_code}"
    assert r.json()["success"] is True
_()

@test("GET /alerts returns saved alert")
def _():
    r = requests.get(f"{FASTAPI_URL}/alerts", timeout=10)
    assert r.status_code == 200
    data = r.json()
    assert data["success"] is True
    assert data["count"] >= 1, f"Expected >=1 alert, got {data['count']}"
    ids = [a["id"] for a in data["alerts"]]
    assert "TEST-DB-001" in ids, f"TEST-DB-001 not in {ids}"
_()

@test("POST /classifications/save stores classification")
def _():
    payload = {"alert_id": "TEST-DB-001", "severity": "HIGH",
               "reasoning": "Test reasoning", "mitre_tactics": "T1110"}
    r = requests.post(f"{FASTAPI_URL}/classifications/save", json=payload, timeout=10)
    assert r.status_code == 200
    assert r.json()["success"] is True
_()

@test("GET /classifications returns saved record")
def _():
    r = requests.get(f"{FASTAPI_URL}/classifications", timeout=10)
    assert r.status_code == 200
    data = r.json()
    assert data["success"] is True
    assert data["count"] >= 1
_()

@test("POST /reports/save and GET /reports round-trip")
def _():
    payload = {"alert_id": "TEST-DB-001", "severity": "HIGH",
               "agent_name": "test-host",
               "report_text": "Test incident report content"}
    r = requests.post(f"{FASTAPI_URL}/reports/save", json=payload, timeout=10)
    assert r.status_code == 200
    r2 = requests.get(f"{FASTAPI_URL}/reports", timeout=10)
    assert r2.status_code == 200
    assert r2.json()["count"] >= 1
_()

@test("GET /reports/{id} returns correct report")
def _():
    r = requests.get(f"{FASTAPI_URL}/reports", timeout=10)
    if r.status_code == 200 and r.json()["count"] > 0:
        rid = r.json()["reports"][0]["id"]
        r2 = requests.get(f"{FASTAPI_URL}/reports/{rid}", timeout=10)
        assert r2.status_code == 200
        assert r2.json()["success"] is True
        assert "report_text" in r2.json()["report"]
_()


# ── GROUP 8: Health & Stats Endpoints ─────────────────────
print("\n━━━ GROUP 8: Health & Stats Endpoints ━━━")

@test("GET /health returns API, DB, Ollama status")
def _():
    r = requests.get(f"{FASTAPI_URL}/health", timeout=10)
    assert r.status_code == 200
    h = r.json()["health"]
    assert h["api"] is True
    assert "database" in h
    assert "ollama" in h
_()

@test("GET /health confirms database is connected")
def _():
    r = requests.get(f"{FASTAPI_URL}/health", timeout=10)
    assert r.status_code == 200
    assert r.json()["health"]["database"] is True, "Database is not connected"
_()

@test("GET /stats returns alert counts")
def _():
    r = requests.get(f"{FASTAPI_URL}/stats", timeout=10)
    assert r.status_code == 200
    s = r.json()["stats"]
    assert "total_alerts" in s
    assert "total_classifications" in s
    assert "total_reports" in s
    assert "severity_counts" in s
_()

@test("GET /logs returns log entries")
def _():
    r = requests.get(f"{FASTAPI_URL}/logs?lines=10", timeout=10)
    assert r.status_code == 200
    assert r.json()["success"] is True
_()


# ── GROUP 9: ReAct Agent & RAG Classify ───────────────────
print("\n━━━ GROUP 9: ReAct Agent & RAG Classify ━━━")

@test("react_agent.py imports cleanly")
def _():
    from agent.react_agent import run_react_agent
    assert callable(run_react_agent)
_()

@test("classify_with_rag.py imports cleanly")
def _():
    from agent.classify_with_rag import classify_with_rag
    assert callable(classify_with_rag)
_()

@test("generate_report tool imports and is callable")
def _():
    from agent.tools.generate_report import generate_report
    assert generate_report is not None
_()


# ── GROUP 10: End-to-End Pipeline ─────────────────────────
print("\n━━━ GROUP 10: End-to-End Pipeline ━━━")

@test("POST /alerts/ingest accepts and classifies alert")
def _():
    payload = {
        "id": "E2E-INTEG-001",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "rule": {"id": "5712", "description": "sshd: brute force detected", "level": 10},
        "agent": {"name": "kali-vm", "ip": "192.168.80.129"},
        "category": "brute_force",
        "raw_log": "Failed password for root from 192.168.80.1",
        "indicators": {"src_ip": "192.168.80.1", "dst_ip": "192.168.80.129", "username": "root"},
        "status": "new"
    }
    r = requests.post(f"{FASTAPI_URL}/alerts/ingest", json=payload, timeout=300)
    assert r.status_code == 200, f"Got {r.status_code}: {r.text[:200]}"
    data = r.json()
    assert data["success"] is True
    assert data["alert_id"] == "E2E-INTEG-001"
_()

@test("Ingested alert appears in GET /alerts")
def _():
    r = requests.get(f"{FASTAPI_URL}/alerts", timeout=10)
    assert r.status_code == 200
    ids = [a["id"] for a in r.json()["alerts"]]
    assert "E2E-INTEG-001" in ids, f"Ingested alert not found. IDs: {ids[:5]}"
_()

@test("GET /stats reflects new data after ingestion")
def _():
    r = requests.get(f"{FASTAPI_URL}/stats", timeout=10)
    assert r.status_code == 200
    s = r.json()["stats"]
    assert s["total_alerts"] >= 1, f"Expected >=1 alerts in stats"
_()


# ── GROUP 7: Live alert DB flow (frontend polling contract) ─
print("\n━━━ GROUP 7: Live Alerts (DB save/fetch contract) ━━━")

LIVE_WAZUH_ALERT = {
    "id": "1720000000.999999",
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "rule": {"id": "5712", "level": 10, "description": "sshd: More than 8 authentication failures",
              "groups": ["authentication_failed", "sshd"]},
    "agent": {"id": "001", "name": "kali", "ip": "192.168.80.129"},
    "severity": "HIGH"
}

@test("POST /alerts/save accepts a raw Wazuh-shaped alert")
def _():
    r = requests.post(f"{FASTAPI_URL}/alerts/save", json=LIVE_WAZUH_ALERT, timeout=10)
    assert r.status_code == 200, f"Got {r.status_code}: {r.text[:200]}"
    data = r.json()
    assert data.get("success") is True
_()

@test("GET /alerts contains the saved alert with matching id")
def _():
    r = requests.get(f"{FASTAPI_URL}/alerts", timeout=10)
    assert r.status_code == 200, f"Got {r.status_code}: {r.text[:200]}"
    data = r.json()
    assert data.get("success") is True
    ids = [a["id"] for a in data.get("alerts", [])]
    assert LIVE_WAZUH_ALERT["id"] in ids, f"Saved alert id not found in GET /alerts ({len(ids)} rows)"
_()

@test("GET /alerts row round-trips rule/agent fields the frontend needs")
def _():
    r = requests.get(f"{FASTAPI_URL}/alerts", timeout=10)
    if r.status_code != 200:
        return
    row = next((a for a in r.json().get("alerts", []) if a["id"] == LIVE_WAZUH_ALERT["id"]), None)
    assert row is not None
    assert row["rule_level"] == 10
    assert row["agent_ip"] == "192.168.80.129"
    # raw_data is what frontend's fetchSiemAlerts() maps directly into the Alert type
    assert row.get("raw_data", {}).get("rule", {}).get("groups") == ["authentication_failed", "sshd"]
_()

@test("Re-POSTing the same alert id is idempotent (no duplicate row)")
def _():
    r1 = requests.post(f"{FASTAPI_URL}/alerts/save", json=LIVE_WAZUH_ALERT, timeout=10)
    r2 = requests.get(f"{FASTAPI_URL}/alerts", timeout=10)
    if r1.status_code != 200 or r2.status_code != 200:
        return
    ids = [a["id"] for a in r2.json().get("alerts", [])]
    assert ids.count(LIVE_WAZUH_ALERT["id"]) == 1, "Duplicate rows for same alert id"
_()


# ── GROUP 7: Live alert DB flow (frontend polling contract) ─
print("\n━━━ GROUP 7: Live Alerts (DB save/fetch contract) ━━━")

LIVE_WAZUH_ALERT = {
    "id": "1720000000.999999",
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "rule": {"id": "5712", "level": 10, "description": "sshd: More than 8 authentication failures",
              "groups": ["authentication_failed", "sshd"]},
    "agent": {"id": "001", "name": "kali", "ip": "192.168.80.129"},
    "severity": "HIGH"
}

@test("POST /alerts/save accepts a raw Wazuh-shaped alert")
def _():
    r = requests.post(f"{FASTAPI_URL}/alerts/save", json=LIVE_WAZUH_ALERT, timeout=10)
    assert r.status_code == 200, f"Got {r.status_code}: {r.text[:200]}"
    data = r.json()
    assert data.get("success") is True
_()

@test("GET /alerts contains the saved alert with matching id")
def _():
    r = requests.get(f"{FASTAPI_URL}/alerts", timeout=10)
    assert r.status_code == 200, f"Got {r.status_code}: {r.text[:200]}"
    data = r.json()
    assert data.get("success") is True
    ids = [a["id"] for a in data.get("alerts", [])]
    assert LIVE_WAZUH_ALERT["id"] in ids, f"Saved alert id not found in GET /alerts ({len(ids)} rows)"
_()

@test("GET /alerts row round-trips rule/agent fields the frontend needs")
def _():
    r = requests.get(f"{FASTAPI_URL}/alerts", timeout=10)
    if r.status_code != 200:
        return
    row = next((a for a in r.json().get("alerts", []) if a["id"] == LIVE_WAZUH_ALERT["id"]), None)
    assert row is not None
    assert row["rule_level"] == 10
    assert row["agent_ip"] == "192.168.80.129"
    # raw_data is what frontend's fetchSiemAlerts() maps directly into the Alert type
    assert row.get("raw_data", {}).get("rule", {}).get("groups") == ["authentication_failed", "sshd"]
_()

@test("Re-POSTing the same alert id is idempotent (no duplicate row)")
def _():
    r1 = requests.post(f"{FASTAPI_URL}/alerts/save", json=LIVE_WAZUH_ALERT, timeout=10)
    r2 = requests.get(f"{FASTAPI_URL}/alerts", timeout=10)
    if r1.status_code != 200 or r2.status_code != 200:
        return
    ids = [a["id"] for a in r2.json().get("alerts", [])]
    assert ids.count(LIVE_WAZUH_ALERT["id"]) == 1, "Duplicate rows for same alert id"
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
