"""
wazuh_forwarder.py — Phase 3: Wazuh → FastAPI Live Alert Bridge
----------------------------------------------------------------
Project: VigilanceAI — Autonomous Security Surveillance

Tails Wazuh's alerts.json file in real time and forwards each new
alert to FastAPI /classify endpoint after normalizing it
into the NormalizedAlert schema.

This closes the real-time loop:
  Wazuh detects attack → alerts.json → this script → FastAPI /classify
  → LangChain ReAct agent → incident report → React dashboard

Run:
    python3 siem/wazuh_forwarder.py --run

Run in background:
    nohup python3 siem/wazuh_forwarder.py --run > siem/forwarder.log 2>&1 &

Stop:
    kill $(cat siem/forwarder.pid)
"""

import json
import os
import sys
import time
import subprocess
import signal
import logging
import threading
from datetime import datetime, timezone

try:
    import requests as _requests_lib
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

import urllib.request
import urllib.error

# ─────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────
FASTAPI_BASE               = "http://localhost:8000"
FASTAPI_CLASSIFY_ENDPOINT  = f"{FASTAPI_BASE}/classify"

WAZUH_MANAGER_CONTAINER = "single-node-wazuh.manager-1"
WAZUH_ALERTS_FILE       = "/var/ossec/logs/alerts/alerts.json"

POLL_INTERVAL   = 5    # seconds between file checks
MIN_ALERT_LEVEL = 5    # only forward at this level or above
MISTRAL_TIMEOUT = 180  # seconds — Mistral on CPU can take up to 3 min

SKIP_RULE_IDS = {"533", "531", "510"}

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_FILE = os.path.join(BASE_DIR, "siem", "forwarder.log")
PID_FILE = os.path.join(BASE_DIR, "siem", "forwarder.pid")

# ─────────────────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOG_FILE, mode="a")
    ]
)
log = logging.getLogger("wazuh_forwarder")

# ─────────────────────────────────────────────────────────
# GRACEFUL SHUTDOWN
# ─────────────────────────────────────────────────────────
_running = True

def _handle_signal(signum, frame):
    global _running
    log.info("Shutdown signal received — stopping forwarder...")
    _running = False

signal.signal(signal.SIGINT,  _handle_signal)
signal.signal(signal.SIGTERM, _handle_signal)

# ─────────────────────────────────────────────────────────
# NORMALIZATION
# ─────────────────────────────────────────────────────────
def _infer_category(groups: list, description: str) -> str:
    groups_lower = [g.lower() for g in groups]
    desc_lower   = description.lower()
    if any(g in groups_lower for g in ["authentication_failed", "authentication_failures", "sshd"]):
        return "brute_force"
    if any(g in groups_lower for g in ["rootcheck", "rootkit", "trojan"]):
        return "malware"
    if any(g in groups_lower for g in ["recon", "scan", "nmap"]):
        return "reconnaissance"
    if any(g in groups_lower for g in ["privilege_escalation", "sudo"]):
        return "privilege_escalation"
    if "brute" in desc_lower or "authentication fail" in desc_lower:
        return "brute_force"
    if "rootkit" in desc_lower or "hidden" in desc_lower:
        return "malware"
    if "scan" in desc_lower or "port" in desc_lower:
        return "reconnaissance"
    return "other"


def normalize_alert(raw: dict) -> dict:
    agent  = raw.get("agent", {})
    rule   = raw.get("rule",  {})
    data   = raw.get("data",  {})
    mitre  = rule.get("mitre", {})
    technique_ids   = mitre.get("id",        [])
    technique_names = mitre.get("technique", [])
    groups   = rule.get("groups", [])
    category = _infer_category(groups, rule.get("description", ""))
    src_ip   = data.get("srcip")  or data.get("src_ip")
    dst_ip   = data.get("dstip")  or agent.get("ip")
    username = data.get("dstuser") or data.get("srcuser") or data.get("user")
    return {
        "alert_id":  raw.get("id", f"wazuh-{int(time.time())}"),
        "timestamp": raw.get("timestamp", datetime.now(timezone.utc).isoformat()),
        "source": {
            "agent_name": agent.get("name", "unknown"),
            "agent_ip":   agent.get("ip",   "unknown")
        },
        "rule": {
            "id":          str(rule.get("id", "0")),
            "description": rule.get("description", "Unknown"),
            "level":       int(rule.get("level", 0))
        },
        "category": category,
        "raw_log":  raw.get("full_log", raw.get("message", ""))[:500],
        "indicators": {
            "src_ip":       src_ip,
            "dst_ip":       dst_ip,
            "src_port":     None,
            "dst_port":     None,
            "username":     username,
            "process_name": data.get("process", None),
            "file_hash":    data.get("md5", data.get("sha256", None))
        },
        "mitre_hint": {
            "technique_id":   technique_ids[0]   if technique_ids   else None,
            "technique_name": technique_names[0] if technique_names else None
        },
        "status": "new"
    }


def should_forward(raw: dict) -> bool:
    rule    = raw.get("rule", {})
    level   = int(rule.get("level", 0))
    rule_id = str(rule.get("id", "0"))
    if level < MIN_ALERT_LEVEL:
        return False
    if rule_id in SKIP_RULE_IDS:
        return False
    return True

# ─────────────────────────────────────────────────────────
# FASTAPI FORWARDING  — runs in a background thread
# so the poll loop never blocks waiting for Mistral
# ─────────────────────────────────────────────────────────
_pending_lock  = threading.Lock()
_pending_count = 0

def _post_alert_thread(normalized: dict):
    """
    Called in a daemon thread. POSTs one alert to FastAPI/classify
    and logs the Mistral response when it arrives (up to 3 min later).
    """
    global _pending_count
    alert_id = normalized["alert_id"]
    desc     = normalized["rule"]["description"][:50]
    level    = normalized["rule"]["level"]
    payload  = json.dumps(normalized).encode("utf-8")

    log.info(f"  ↑ QUEUED  [{level:2d}] {desc} (alert {alert_id})")

    # Use requests library if available (better error messages),
    # otherwise fall back to urllib
    try:
        if REQUESTS_AVAILABLE:
            import requests
            resp = requests.post(
                FASTAPI_CLASSIFY_ENDPOINT,
                data=payload,
                headers={"Content-Type": "application/json"},
                timeout=MISTRAL_TIMEOUT
            )
            if resp.status_code == 200:
                data = resp.json()
                classification = data.get("classification", str(data))[:200]
                log.info(f"  ✅ CLASSIFIED [{level:2d}] {desc}")
                log.info(f"     → {classification}")
            else:
                log.warning(f"  ⚠ FastAPI returned HTTP {resp.status_code}: {resp.text[:100]}")
        else:
            req = urllib.request.Request(
                FASTAPI_CLASSIFY_ENDPOINT,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=MISTRAL_TIMEOUT) as r:
                data = json.loads(r.read().decode())
                classification = data.get("classification", str(data))[:200]
                log.info(f"  ✅ CLASSIFIED [{level:2d}] {desc}")
                log.info(f"     → {classification}")

    except Exception as e:
        log.warning(f"  ✗ POST failed for {alert_id}: {e}")
    finally:
        with _pending_lock:
            _pending_count -= 1


def forward_async(normalized: dict):
    """Launch a background thread to POST the alert — never blocks."""
    global _pending_count
    with _pending_lock:
        _pending_count += 1
    t = threading.Thread(target=_post_alert_thread, args=(normalized,), daemon=True)
    t.start()


# ─────────────────────────────────────────────────────────
# FASTAPI HEALTH CHECK
# ─────────────────────────────────────────────────────────
def _check_fastapi_available() -> bool:
    try:
        if REQUESTS_AVAILABLE:
            import requests
            r = requests.get(f"{FASTAPI_BASE}/", timeout=3)
            return r.status_code == 200
        else:
            req = urllib.request.Request(f"{FASTAPI_BASE}/")
            with urllib.request.urlopen(req, timeout=3) as r:
                return r.status == 200
    except Exception:
        return False


# ─────────────────────────────────────────────────────────
# ALERT FILE READER
# ─────────────────────────────────────────────────────────
def _get_current_line_count() -> int:
    try:
        result = subprocess.run(
            ["docker", "exec", WAZUH_MANAGER_CONTAINER,
             "wc", "-l", WAZUH_ALERTS_FILE],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            return int(result.stdout.strip().split()[0])
    except Exception:
        pass
    return 0


def _read_new_lines(from_line: int) -> list:
    try:
        result = subprocess.run(
            ["docker", "exec", WAZUH_MANAGER_CONTAINER,
             "tail", "-n", f"+{from_line + 1}", WAZUH_ALERTS_FILE],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            return []
        alerts = []
        for line in result.stdout.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                alerts.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return alerts
    except Exception as e:
        log.warning(f"Error reading alerts file: {e}")
        return []


# ─────────────────────────────────────────────────────────
# MAIN LOOP
# ─────────────────────────────────────────────────────────
def run_forwarder():
    log.info("=" * 60)
    log.info("  VigilanceAI — Wazuh Alert Forwarder")
    log.info(f"  Wazuh container : {WAZUH_MANAGER_CONTAINER}")
    log.info(f"  FastAPI endpoint: {FASTAPI_CLASSIFY_ENDPOINT}")
    log.info(f"  Min alert level : {MIN_ALERT_LEVEL}")
    log.info(f"  Poll interval   : {POLL_INTERVAL}s")
    log.info(f"  Mistral timeout : {MISTRAL_TIMEOUT}s (non-blocking)")
    log.info("=" * 60)

    with open(PID_FILE, "w") as f:
        f.write(str(os.getpid()))

    if _check_fastapi_available():
        log.info("✓ FastAPI backend is reachable")
    else:
        log.warning("⚠ FastAPI not reachable — start: python3 -m uvicorn backend.main:app --port 8000")

    current_line = _get_current_line_count()
    log.info(f"✓ Bookmarked alerts.json at line {current_line}")
    log.info("  Watching for new alerts... (classifications arrive asynchronously)")
    log.info("")

    forwarded = 0
    skipped   = 0

    while _running:
        try:
            new_count = _get_current_line_count()
            if new_count > current_line:
                new_alerts = _read_new_lines(current_line)
                for raw in new_alerts:
                    if should_forward(raw):
                        normalized = normalize_alert(raw)
                        forward_async(normalized)   # ← non-blocking
                        forwarded += 1
                    else:
                        skipped += 1
                current_line = new_count
                if new_alerts:
                    log.info(f"  Stats: {forwarded} queued | {skipped} skipped "
                             f"| {_pending_count} awaiting Mistral response")
            time.sleep(POLL_INTERVAL)
        except Exception as e:
            log.error(f"Forwarder loop error: {e}")
            time.sleep(POLL_INTERVAL)

    # Wait for in-flight requests
    log.info(f"Stopping — waiting for {_pending_count} in-flight requests...")
    for _ in range(60):
        if _pending_count == 0:
            break
        time.sleep(1)

    log.info(f"Forwarder stopped. Queued: {forwarded} | Skipped: {skipped}")
    if os.path.exists(PID_FILE):
        os.remove(PID_FILE)


# ─────────────────────────────────────────────────────────
# TEST MODE
# ─────────────────────────────────────────────────────────
def run_test():
    print("\n" + "=" * 60)
    print("  VigilanceAI — Wazuh Forwarder Test Mode")
    print("=" * 60)

    print("\n[Test 1] Reading alerts from Wazuh container...")
    line_count = _get_current_line_count()
    print(f"  ✓ alerts.json has {line_count} lines")
    start_line = max(0, line_count - 5)
    recent = _read_new_lines(start_line)
    print(f"  ✓ Read {len(recent)} recent alerts")

    print("\n[Test 2] Normalizing and filtering alerts...")
    to_forward = []
    for raw in recent:
        if should_forward(raw):
            normalized = normalize_alert(raw)
            to_forward.append(normalized)
            print(f"  → WOULD FORWARD: [{normalized['rule']['level']:2d}] "
                  f"{normalized['rule']['description'][:55]}")
            print(f"    Category: {normalized['category']} | Agent: {normalized['source']['agent_name']}")
        else:
            rule = raw.get("rule", {})
            print(f"  ✗ SKIPPED: [{rule.get('level',0):2d}] "
                  f"{rule.get('description','Unknown')[:55]}")

    print("\n[Test 3] Checking FastAPI availability...")
    if _check_fastapi_available():
        print("  ✓ FastAPI reachable at localhost:8000")
        if to_forward:
            print(f"\n[Test 4] Forwarding first alert asynchronously...")
            print(f"  → Sending to /classify (Mistral may take 60-180s on CPU)...")
            # Synchronous for test mode so we can show the result
            payload = json.dumps(to_forward[0]).encode("utf-8")
            try:
                if REQUESTS_AVAILABLE:
                    import requests
                    resp = requests.post(
                        FASTAPI_CLASSIFY_ENDPOINT,
                        data=payload,
                        headers={"Content-Type": "application/json"},
                        timeout=MISTRAL_TIMEOUT
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        print(f"  ✓ Classification received:")
                        print(f"    {data.get('classification','')[:300]}")
                    else:
                        print(f"  ✗ HTTP {resp.status_code}: {resp.text[:100]}")
                else:
                    req = urllib.request.Request(
                        FASTAPI_CLASSIFY_ENDPOINT,
                        data=payload,
                        headers={"Content-Type": "application/json"},
                        method="POST"
                    )
                    with urllib.request.urlopen(req, timeout=MISTRAL_TIMEOUT) as r:
                        data = json.loads(r.read().decode())
                        print(f"  ✓ Classification: {data.get('classification','')[:300]}")
            except Exception as e:
                print(f"  ✗ Failed: {e}")
    else:
        print("  ✗ FastAPI not reachable — start uvicorn first")

    print("\n" + "=" * 60)
    print("  To run live: python3 siem/wazuh_forwarder.py --run")
    print("=" * 60)


if __name__ == "__main__":
    if "--run" in sys.argv:
        run_forwarder()
    else:
        run_test()
