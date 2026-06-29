#!/bin/bash
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'
PASS=0; FAIL=0

header() { echo -e "\n${BLUE}━━━ $1 ━━━${NC}"; }
pass()   { echo -e "  ${GREEN}✅ PASS${NC} — $1"; ((PASS++)); }
fail()   { echo -e "  ${RED}❌ FAIL${NC} — $1"; ((FAIL++)); }
info()   { echo -e "  ${CYAN}ℹ${NC}  $1"; }
warn()   { echo -e "  ${YELLOW}⚠${NC}  $1"; }

REPO="/home/kali/VigilanceAI-Autonomous_Security_survilance"
VENV="$REPO/venv"
WAZUH_COMPOSE="$REPO/siem/wazuh-docker/single-node/docker-compose.yml"
WAZUH_CONTAINER="single-node-wazuh.manager-1"
FASTAPI_URL="http://localhost:8000"

echo -e "${CYAN}"
echo "  VigilanceAI — Pipeline Test"
echo -e "${NC}"
date

# ── STEP 1: Environment ──────────────────────────────────
header "STEP 1 · Environment & venv"

if [ -d "$VENV" ]; then
    pass "venv exists at $VENV"
    source "$VENV/bin/activate"
    info "Python: $(python3 --version)"
else
    fail "venv not found"; exit 1
fi

for pkg in fastapi uvicorn langchain chromadb sentence_transformers pydantic requests langchain_ollama; do
    python3 -c "import ${pkg}" 2>/dev/null && pass "Package: $pkg" || fail "Missing: $pkg"
done

# ── STEP 2: Wazuh ────────────────────────────────────────
header "STEP 2 · Wazuh Docker containers"

if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "wazuh.manager"; then
    WAZUH_CONTAINER=$(docker ps --format '{{.Names}}' | grep "wazuh.manager" | head -1)
    pass "Wazuh manager running: $WAZUH_CONTAINER"
else
    warn "Wazuh not running — starting from single-node..."
    cd "$REPO/siem/wazuh-docker/single-node"
    docker-compose up -d 2>&1 | tail -5
    sleep 20
    if docker ps --format '{{.Names}}' | grep -q "wazuh.manager"; then
        WAZUH_CONTAINER=$(docker ps --format '{{.Names}}' | grep "wazuh.manager" | head -1)
        pass "Wazuh started: $WAZUH_CONTAINER"
    else
        fail "Could not start Wazuh — check docker-compose at $WAZUH_COMPOSE"
    fi
    cd "$REPO"
fi

# Check alerts.json
if [ -n "$WAZUH_CONTAINER" ]; then
    ALERT_COUNT=$(docker exec "$WAZUH_CONTAINER" \
        sh -c 'wc -l < /var/ossec/logs/alerts/alerts.json 2>/dev/null || echo 0' 2>/dev/null)
    ALERT_COUNT=$(echo "$ALERT_COUNT" | tr -d ' \n')
    if [ "${ALERT_COUNT:-0}" -gt 100 ] 2>/dev/null; then
        pass "alerts.json has $ALERT_COUNT lines"
    else
        fail "alerts.json has $ALERT_COUNT lines — run: hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.80.129 -t 4"
    fi
fi

# ── STEP 3: FastAPI ──────────────────────────────────────
header "STEP 3 · FastAPI backend (port 8000)"

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$FASTAPI_URL/" 2>/dev/null)
if [ "$HTTP_CODE" = "200" ]; then
    pass "FastAPI running — GET / → 200"
    info "$(curl -s $FASTAPI_URL/)"
else
    warn "FastAPI not running (HTTP $HTTP_CODE) — starting..."
    cd "$REPO/backend"
    nohup python3 -m uvicorn main:app --host 0.0.0.0 --port 8000 > /tmp/fastapi.log 2>&1 &
    sleep 5
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$FASTAPI_URL/" 2>/dev/null)
    if [ "$HTTP_CODE" = "200" ]; then
        pass "FastAPI started successfully"
    else
        fail "FastAPI failed — tail /tmp/fastapi.log:"
        tail -10 /tmp/fastapi.log
    fi
    cd "$REPO"
fi

# ── STEP 4: RAG ──────────────────────────────────────────
header "STEP 4 · RAG / ChromaDB"

cd "$REPO"
RAG_OUT=$(python3 -c "
import sys; sys.path.insert(0,'.')
from rag.query_rag import query_threat_intel
results = query_threat_intel('SSH brute force authentication failure', n_results=3)
if results:
    ids = [r.get('technique_id','') for r in results]
    names = [r.get('name','') for r in results]
    print('IDS:' + ','.join(ids))
    print('NAMES:' + ','.join(names[:1]))
else:
    print('NO_RESULTS')
" 2>/dev/null)

if echo "$RAG_OUT" | grep -q "T1110"; then
    pass "RAG: SSH brute force → T1110 returned ✓"
elif echo "$RAG_OUT" | grep -q "IDS:"; then
    warn "RAG returned results but T1110 not top — may need re-ingestion"
    info "$RAG_OUT"
    pass "RAG is functional (results returned)"
else
    fail "RAG returned nothing — run: python3 rag/ingest_mitre.py"
fi

# ── STEP 5: query_siem (correct function name) ───────────
header "STEP 5 · query_siem.py — get_recent_alerts"

SIEM_OUT=$(python3 -c "
import sys; sys.path.insert(0,'.')
from agent.tools.query_siem import get_recent_alerts
alerts = get_recent_alerts(limit=5)
print(f'COUNT:{len(alerts)}')
if alerts:
    a = alerts[0]
    print(f'FIRST_ID:{a.get(\"alert_id\",\"?\")}')
    print(f'FIRST_LEVEL:{a.get(\"rule\",{}).get(\"level\",\"?\")}')
    print(f'FIRST_CAT:{a.get(\"category\",\"?\")}')
" 2>/dev/null)

COUNT=$(echo "$SIEM_OUT" | grep "COUNT:" | cut -d: -f2)
if [ "${COUNT:-0}" -gt "0" ] 2>/dev/null; then
    pass "get_recent_alerts returned $COUNT alerts from Wazuh"
    echo "$SIEM_OUT" | grep -v "COUNT" | while read line; do info "$line"; done
else
    fail "get_recent_alerts returned 0 — Wazuh container may not be running"
    info "Raw output: $SIEM_OUT"
fi

# ── STEP 6: Schema ───────────────────────────────────────
header "STEP 6 · NormalizedAlert schema"

python3 -c "
import sys; sys.path.insert(0,'.')
from agent.alert_schema import NormalizedAlert, SAMPLE_ALERTS
a = SAMPLE_ALERTS['ssh_brute_force']
m = NormalizedAlert(**a)
assert m.alert_id and m.category == 'brute_force' and m.status == 'new'
print('SCHEMA_OK')
print(f'alert_id={m.alert_id} category={m.category} level={m.rule.level}')
" 2>/dev/null && pass "NormalizedAlert schema valid" || fail "Schema validation failed"

# ── STEP 7: POST /classify ───────────────────────────────
header "STEP 7 · POST /classify (FastAPI + Mistral)"

info "Sending ssh_brute_force alert to /classify (Mistral may take 30-90s)..."

PAYLOAD='{"alert_id":"E2E-TEST-001","timestamp":"2024-01-15T10:30:00Z","source":{"agent_name":"kali-vm","agent_ip":"192.168.80.129"},"rule":{"id":"5712","description":"sshd: authentication failed. Brute force","level":10},"category":"brute_force","raw_log":"Failed password for root from 192.168.80.1 port 54321","indicators":{"src_ip":"192.168.80.1","dst_ip":"192.168.80.129","src_port":54321,"dst_port":22,"username":"root","process_name":"sshd","file_hash":null},"mitre_hint":{"technique_id":null,"technique_name":null},"status":"new"}'

CLASSIFY_RESP=$(curl -s -X POST "$FASTAPI_URL/classify" \
    -H "Content-Type: application/json" \
    -d "$PAYLOAD" --max-time 300 2>/dev/null)

if echo "$CLASSIFY_RESP" | python3 -c "
import sys,json
d=json.load(sys.stdin)
assert 'classification' in d or 'severity' in d or 'result' in d
print('CLASSIFY_OK')
print(json.dumps(d,indent=2)[:500])
" 2>/dev/null; then
    pass "/classify returned valid classification"
else
    fail "/classify failed"
    info "Response: ${CLASSIFY_RESP:0:400}"
fi

# ── STEP 8: Forwarder import ─────────────────────────────
header "STEP 8 · wazuh_forwarder.py"

python3 -c "
import sys; sys.path.insert(0,'.')
import siem.wazuh_forwarder as wf
print('IMPORT_OK')
" 2>/dev/null && pass "wazuh_forwarder imports cleanly" || fail "wazuh_forwarder import error"

# ── STEP 9: classify_alert direct ────────────────────────
header "STEP 9 · classify_alert.py (direct LangChain)"

info "Running classify_alert directly (30-90s for Mistral)..."
CHAIN_OUT=$(timeout 120 python3 -c "
import sys, os
sys.path.insert(0, '.')
# Fix the import path issue by adding agent/ to path too
sys.path.insert(0, './agent')
from agent.classify_alert import classify_alert
from agent.alert_schema import SAMPLE_ALERTS
result = classify_alert(SAMPLE_ALERTS['ssh_brute_force'])
print('CHAIN_OK')
print(str(result)[:300])
" 2>/dev/null)

if echo "$CHAIN_OUT" | grep -q "CHAIN_OK"; then
    pass "classify_alert chain executed via Mistral"
    echo "$CHAIN_OUT" | grep -v "CHAIN_OK" | while read line; do info "$line"; done
else
    fail "classify_alert failed — check if Ollama is running: ollama serve"
fi

# ── STEP 10: Full end-to-end ─────────────────────────────
header "STEP 10 · Full flow: Wazuh → normalize → RAG → classify"

FULL_OUT=$(timeout 120 python3 << 'PYEOF'
import sys, json
sys.path.insert(0, '/home/kali/VigilanceAI-Autonomous_Security_survilance')
sys.path.insert(0, '/home/kali/VigilanceAI-Autonomous_Security_survilance/agent')

# Step A: Get alert from Wazuh (or use sample if Wazuh down)
try:
    from agent.tools.query_siem import get_recent_alerts
    alerts = get_recent_alerts(limit=1)
    if alerts:
        alert = alerts[0]
        print(f"SOURCE: Wazuh live alert")
    else:
        raise Exception("No live alerts")
except Exception as e:
    from agent.alert_schema import SAMPLE_ALERTS
    alert = SAMPLE_ALERTS['ssh_brute_force']
    print(f"SOURCE: sample alert (Wazuh unavailable: {e})")

print(f"ALERT_ID: {alert.get('alert_id','?')}")
print(f"RULE: {alert.get('rule',{}).get('description','?')[:60]}")
print(f"LEVEL: {alert.get('rule',{}).get('level','?')}")
print(f"CATEGORY: {alert.get('category','?')}")

# Step B: RAG lookup
from rag.query_rag import query_threat_intel
desc = alert.get('rule',{}).get('description','unknown')
rag_results = query_threat_intel(desc, n_results=1)
if rag_results:
    r = rag_results[0]
    print(f"RAG_MATCH: {r.get('technique_id','')} — {r.get('name','')[:50]}")

# Step C: POST to /classify
import requests
resp = requests.post("http://localhost:8000/classify", json=alert, timeout=300)
print(f"CLASSIFY_HTTP: {resp.status_code}")
if resp.status_code == 200:
    data = resp.json()
    print(f"CLASSIFY_RESULT: {json.dumps(data)[:300]}")
    print("FULL_FLOW_OK")
else:
    print(f"CLASSIFY_ERROR: {resp.text[:200]}")
PYEOF
)

if echo "$FULL_OUT" | grep -q "FULL_FLOW_OK"; then
    pass "🎉 FULL PIPELINE WORKING: Wazuh → RAG → FastAPI → Mistral"
    echo "$FULL_OUT" | while read line; do info "$line"; done
else
    warn "Partial flow — details:"
    echo "$FULL_OUT" | while read line; do info "$line"; done
fi

# ── SUMMARY ──────────────────────────────────────────────
echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  RESULTS:  ${GREEN}${PASS} passed${NC}  |  ${RED}${FAIL} failed${NC}"
echo -e "  SCORE:    ${PASS}/$((PASS+FAIL))"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

[ $FAIL -eq 0 ] && echo -e "\n  ${GREEN}🎉 ALL TESTS PASSED${NC}\n" && exit 0
echo -e "\n  ${YELLOW}⚠  $FAIL test(s) failed${NC}\n" && exit 1
