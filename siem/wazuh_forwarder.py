"""
wazuh_forwarder.py — Phase 3: Wazuh → FastAPI Live Alert Bridge
----------------------------------------------------------------
Project: VigilanceAI — Autonomous Security Surveillance

Tails Wazuh's alerts.json file in real time and forwards each new
alert to Neeraj's FastAPI /classify endpoint after normalizing it
into the NormalizedAlert schema.

This closes the real-time loop:
  Wazuh detects attack → alerts.json → this script → FastAPI /classify
  → LangChain ReAct agent → incident report → React dashboard

How it works:
  1. Reads current line count of alerts.json (bookmark)
  2. Every POLL_INTERVAL seconds, reads any new lines added
  3. Normalizes each raw Wazuh alert into NormalizedAlert format
  4. Filters out low-level noise (netstat, rootcheck below level 5)
  5. POSTs to FastAPI /classify endpoint
  6. Logs result to console and to siem/forwarder.log

Run:
    cd ~/VigilanceAI-Autonomous_Security_survilance
    source venv/bin/activate
    python3 siem/wazuh_forwarder.py

Run in background:
    nohup python3 siem/wazuh_forwarder.py > siem/forwarder.log 2>&1 &

Stop:
    kill $(cat siem/forwarder.pid)

Prerequisites:
    - Wazuh Docker stack running (docker-compose up -d)
    - Neeraj's FastAPI running on port 8000 (uvicorn main:app)
"""

import json
import os
import sys
import time
import subprocess
import urllib.request
import urllib.error
import signal
import logging
from datetime import datetime, timezone

# ─────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────
FASTAPI_BASE = "http://localhost:8000"
FASTAPI_CLASSIFY_ENDPOINT = f"{FASTAPI_BASE}/classify"
FASTAPI_INGEST_ENDPOINT = f"{FASTAPI_BASE}/alerts/ingest"

WAZUH_MANAGER_CONTAINER = "wazuh-docker-wazuh.manager-1"
WAZUH_ALERTS_FILE = "/var/ossec/logs/alerts/alerts.json"

POLL_INTERVAL = 5       # seconds between checks for new alerts
MIN_ALERT_LEVEL = 5     # only forward alerts at this level or above
                        # (filters out routine netstat/rootcheck noise)

# Noisy rule IDs to skip even if above MIN_ALERT_LEVEL
SKIP_RULE_IDS = {
    "533",   # netstat port change — too frequent
    "531",   # disk space — not security relevant for demo
    "510",   # rootcheck generic — too noisy
}

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_FILE = os.path.join(BASE_DIR, "siem", "forwarder.log")
PID_FILE = os.path.join(BASE_DIR, "siem", "forwarder.pid")

# ─────────────────────────────────────────────────────────
# LOGGING SETUP
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

signal.signal(signal.SIGINT, _handle_signal)
signal.signal(signal.SIGTERM, _handle_signal)

# ─────────────────────────────────────────────────────────
# ALERT NORMALIZATION
# Same logic as query_siem.py — kept in sync with alert_schema.md
# ─────────────────────────────────────────────────────────
def _infer_category(groups: list, description: str) -> str:
    groups_lower = [g.lower() for g in groups]
    desc_lower = description.lower()

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
    """Convert raw Wazuh alert JSON to NormalizedAlert schema."""
    agent = raw.get("agent", {})
    rule = raw.get("rule", {})
    data = raw.get("data", {})

    mitre = rule.get("mitre", {})
    technique_ids = mitre.get("id", [])
    technique_names = mitre.get("technique", [])

    groups = rule.get("groups", [])
    category = _infer_category(groups, rule.get("description", ""))

    src_ip = data.get("srcip") or data.get("src_ip")
    dst_ip = data.get("dstip") or agent.get("ip")
    username = data.get("dstuser") or data.get("srcuser") or data.get("user")

    return {
        "alert_id": raw.get("id", f"wazuh-{int(time.time())}"),
        "timestamp": raw.get("timestamp", datetime.now(timezone.utc).isoformat()),
        "source": {
            "agent_name": agent.get("name", "unknown"),
            "agent_ip": agent.get("ip", "unknown")
        },
        "rule": {
            "id": str(rule.get("id", "0")),
            "description": rule.get("description", "Unknown"),
            "level": int(rule.get("level", 0))
        },
        "category": category,
        "raw_log": raw.get("full_log", raw.get("message", ""))[:500],
        "indicators": {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": None,
            "dst_port": None,
            "username": username,
            "process_name": data.get("process", None),
            "file_hash": data.get("md5", data.get("sha256", None))
        },
        "mitre_hint": {
            "technique_id": technique_ids[0] if technique_ids else None,
            "technique_name": technique_names[0] if technique_names else None
        },
        "status": "new"
    }


def should_forward(raw: dict) -> bool:
    """
    Decide whether this alert is worth forwarding to the agent.
    Filters out routine noise so the agent only sees real threats.
    """
    rule = raw.get("rule", {})
    level = int(rule.get("level", 0))
    rule_id = str(rule.get("id", "0"))

    # Skip low-level alerts
    if level < MIN_ALERT_LEVEL:
        return False

    # Skip known noisy rules
    if rule_id in SKIP_RULE_IDS:
        return False

    return True


# ─────────────────────────────────────────────────────────
# FASTAPI FORWARDING
# ─────────────────────────────────────────────────────────
def _check_fastapi_available() -> bool:
    """Check if FastAPI backend is reachable."""
    try:
        req = urllib.request.Request(
            f"{FASTAPI_BASE}/",
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            return resp.status == 200
    except Exception:
        return False


def forward_to_fastapi(normalized_alert: dict) -> bool:
    """
    POST a normalized alert to FastAPI.
    Tries /alerts/ingest first (stores alert), then /classify (classify only).

    Returns True if successfully forwarded.
    """
    payload = json.dumps(normalized_alert).encode("utf-8")

    # Try /alerts/ingest first (Member 3's endpoint for storing + classifying)
    for endpoint in [FASTAPI_INGEST_ENDPOINT, FASTAPI_CLASSIFY_ENDPOINT]:
        try:
            req = urllib.request.Request(
                endpoint,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                response_data = json.loads(resp.read().decode())
                severity = response_data.get("severity", "UNKNOWN")
                log.info(
                    f"→ FORWARDED [{normalized_alert['rule']['level']:2d}] "
                    f"{normalized_alert['rule']['description'][:50]} "
                    f"| Severity: {severity}"
                )
                return True

        except urllib.error.HTTPError as e:
            if e.code == 404:
                continue  # try next endpoint
            log.warning(f"FastAPI HTTP {e.code} for {endpoint}")
            return False
        except Exception as e:
            log.warning(f"FastAPI unreachable at {endpoint}: {e}")
            return False

    return False


# ─────────────────────────────────────────────────────────
# ALERT FILE READER
# ─────────────────────────────────────────────────────────
def _get_current_line_count() -> int:
    """Get current line count of alerts.json via docker exec."""
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
    """
    Read lines from alerts.json starting at from_line.
    Returns list of raw alert dicts.
    """
    try:
        result = subprocess.run(
            ["docker", "exec", WAZUH_MANAGER_CONTAINER,
             "tail", f"-n", f"+{from_line + 1}", WAZUH_ALERTS_FILE],
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
    """
    Main polling loop — watches alerts.json and forwards new alerts.
    """
    log.info("=" * 60)
    log.info("  VigilanceAI — Wazuh Alert Forwarder")
    log.info(f"  Wazuh container: {WAZUH_MANAGER_CONTAINER}")
    log.info(f"  FastAPI endpoint: {FASTAPI_CLASSIFY_ENDPOINT}")
    log.info(f"  Min alert level: {MIN_ALERT_LEVEL}")
    log.info(f"  Poll interval: {POLL_INTERVAL}s")
    log.info("=" * 60)

    # Write PID file for easy process management
    with open(PID_FILE, "w") as f:
        f.write(str(os.getpid()))

    # Check FastAPI availability
    if _check_fastapi_available():
        log.info("✓ FastAPI backend is reachable")
    else:
        log.warning("⚠ FastAPI backend not reachable at localhost:8000")
        log.warning("  Alerts will be collected but forwarding will fail")
        log.warning("  Start FastAPI: cd backend && uvicorn main:app --reload")

    # Bookmark current position in alerts file
    current_line = _get_current_line_count()
    log.info(f"✓ Bookmarked alerts.json at line {current_line}")
    log.info("  Watching for new alerts...")
    log.info("")

    forwarded_count = 0
    skipped_count = 0
    error_count = 0

    while _running:
        try:
            new_line_count = _get_current_line_count()

            if new_line_count > current_line:
                new_alerts = _read_new_lines(current_line)

                for raw in new_alerts:
                    if should_forward(raw):
                        normalized = normalize_alert(raw)
                        success = forward_to_fastapi(normalized)
                        if success:
                            forwarded_count += 1
                        else:
                            error_count += 1
                            # Log the alert locally even if forwarding failed
                            log.info(
                                f"  [LOCAL] [{raw.get('rule', {}).get('level', 0):2d}] "
                                f"{raw.get('rule', {}).get('description', 'Unknown')[:60]}"
                            )
                    else:
                        skipped_count += 1

                current_line = new_line_count

                if new_alerts:
                    log.info(
                        f"  Stats: {forwarded_count} forwarded | "
                        f"{skipped_count} skipped | {error_count} errors"
                    )

            time.sleep(POLL_INTERVAL)

        except Exception as e:
            log.error(f"Forwarder loop error: {e}")
            time.sleep(POLL_INTERVAL)

    # Cleanup
    log.info(f"\nForwarder stopped. Total: {forwarded_count} forwarded, "
             f"{skipped_count} skipped, {error_count} errors")
    if os.path.exists(PID_FILE):
        os.remove(PID_FILE)


# ─────────────────────────────────────────────────────────
# STANDALONE TEST (one-shot, doesn't loop)
# ─────────────────────────────────────────────────────────
def run_test():
    """
    Test mode — reads last 5 alerts, normalizes them, and
    attempts to forward one to FastAPI. Doesn't loop.
    """
    print("\n" + "=" * 60)
    print("  VigilanceAI — Wazuh Forwarder Test Mode")
    print("=" * 60)

    # Test 1: Read alerts file
    print("\n[Test 1] Reading alerts from Wazuh container...")
    line_count = _get_current_line_count()
    print(f"  ✓ alerts.json has {line_count} lines")

    start_line = max(0, line_count - 5)
    recent = _read_new_lines(start_line)
    print(f"  ✓ Read {len(recent)} recent alerts")

    # Test 2: Normalize and filter
    print("\n[Test 2] Normalizing and filtering alerts...")
    to_forward = []
    for raw in recent:
        if should_forward(raw):
            normalized = normalize_alert(raw)
            to_forward.append(normalized)
            print(f"  → WOULD FORWARD: [{normalized['rule']['level']:2d}] "
                  f"{normalized['rule']['description'][:55]}")
            print(f"    Category: {normalized['category']} | "
                  f"Agent: {normalized['source']['agent_name']}")
        else:
            rule = raw.get("rule", {})
            print(f"  ✗ SKIPPED: [{rule.get('level', 0):2d}] "
                  f"{rule.get('description', 'Unknown')[:55]}"
                  f" (rule {rule.get('id', '?')})")

    # Test 3: FastAPI check
    print("\n[Test 3] Checking FastAPI availability...")
    if _check_fastapi_available():
        print("  ✓ FastAPI is reachable at localhost:8000")

        if to_forward:
            print(f"\n[Test 4] Forwarding first qualifying alert...")
            success = forward_to_fastapi(to_forward[0])
            if success:
                print("  ✓ Alert forwarded successfully")
            else:
                print("  ✗ Forwarding failed — check FastAPI logs")
        else:
            print("\n[Test 4] No qualifying alerts to forward")
            print("  Run: hydra -l testvictim -P /usr/share/wordlists/rockyou.txt")
            print("       ssh://192.168.80.129 -t 4")
            print("  Then re-run this test to see alerts forwarded")
    else:
        print("  ✗ FastAPI not reachable at localhost:8000")
        print("  Start it: cd backend && uvicorn main:app --reload --port 8000")

    print("\n" + "=" * 60)
    print("  Test complete.")
    print("  To run the live forwarder: python3 siem/wazuh_forwarder.py --run")
    print("=" * 60)


if __name__ == "__main__":
    if "--run" in sys.argv:
        run_forwarder()
    else:
        run_test()
