"""
query_siem.py — Phase 3: Tool 4 — Wazuh SIEM Query Tool
---------------------------------------------------------
Project: VigilanceAI — Autonomous Security Surveillance

LangChain @tool that the ReAct agent calls to fetch real Wazuh alerts.
The agent uses this to pull context about an alert being investigated,
find related alerts from the same source IP, or check recent activity
on a specific agent.

Two data sources (primary → fallback):
  1. Wazuh REST API (https://localhost:55000) — live, real-time alerts
  2. Wazuh alerts.json file (via Docker exec) — file-based fallback
     if API token expires or network is unreachable

Wazuh API credentials (from docker-compose.yml):
  Username: wazuh-wui
  Password: MyS3cr37P450r.*-
  Endpoint: https://localhost:55000
"""

import json
import os
import sys
import subprocess
import urllib.request
import urllib.error
import urllib.parse
import ssl
from datetime import datetime, timezone
from typing import Optional

# LangChain tool decorator
try:
    from langchain_core.tools import tool
except ImportError:
    # Fallback for older LangChain versions
    from langchain.tools import tool

# ─────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────
WAZUH_API_BASE = "https://localhost:55000"
WAZUH_API_USER = "wazuh-wui"
WAZUH_API_PASS = "MyS3cr37P450r.*-"

# Docker container name for file-based fallback
WAZUH_MANAGER_CONTAINER = "single-node-wazuh.manager-1"
WAZUH_ALERTS_FILE = "/var/ossec/logs/alerts/alerts.json"

# SSL context — disable verification for self-signed Wazuh certs
SSL_CONTEXT = ssl.create_default_context()
SSL_CONTEXT.check_hostname = False
SSL_CONTEXT.verify_mode = ssl.CERT_NONE

# Token cache — avoid re-authenticating on every call
_cached_token = None
_token_expiry = None


# ─────────────────────────────────────────────────────────
# AUTHENTICATION
# ─────────────────────────────────────────────────────────
def _get_jwt_token() -> Optional[str]:
    """
    Authenticate with Wazuh API and return a JWT token.
    Caches the token until it expires (default 900s / 15 min).

    Returns:
        JWT token string, or None if authentication fails
    """
    global _cached_token, _token_expiry

    # Return cached token if still valid
    now = datetime.now(timezone.utc).timestamp()
    if _cached_token and _token_expiry and now < _token_expiry - 60:
        return _cached_token

    url = f"{WAZUH_API_BASE}/security/user/authenticate?raw=true"

    # Basic auth header
    import base64
    credentials = base64.b64encode(
        f"{WAZUH_API_USER}:{WAZUH_API_PASS}".encode()
    ).decode()

    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Basic {credentials}",
            "Content-Type": "application/json"
        }
    )

    try:
        with urllib.request.urlopen(req, context=SSL_CONTEXT, timeout=10) as resp:
            token = resp.read().decode().strip()
            _cached_token = token
            # Wazuh tokens expire in 900s by default
            _token_expiry = now + 900
            return token
    except Exception as e:
        print(f"[warn] Wazuh API auth failed: {e}")
        return None


# ─────────────────────────────────────────────────────────
# WAZUH API CALLS
# ─────────────────────────────────────────────────────────
def _api_get(endpoint: str, params: dict = None) -> Optional[dict]:
    """
    Make an authenticated GET request to the Wazuh API.

    Args:
        endpoint: API path, e.g. "/agents" or "/security/events"
        params: Query parameters dict

    Returns:
        Parsed JSON response dict, or None on failure
    """
    token = _get_jwt_token()
    if not token:
        return None

    url = f"{WAZUH_API_BASE}{endpoint}"
    if params:
        url += "?" + urllib.parse.urlencode(params)

    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
    )

    try:
        with urllib.request.urlopen(req, context=SSL_CONTEXT, timeout=15) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        print(f"[warn] API request failed: HTTP {e.code} for {endpoint}")
        return None
    except Exception as e:
        print(f"[warn] API request error: {e}")
        return None


# ─────────────────────────────────────────────────────────
# NORMALIZATION — Raw Wazuh alert → NormalizedAlert schema
# This matches the schema in docs/alert_schema.md
# ─────────────────────────────────────────────────────────
def _normalize_alert(raw: dict) -> dict:
    """
    Convert a raw Wazuh alert JSON object into the NormalizedAlert
    format defined in docs/alert_schema.md.

    Wazuh alert fields:
      id, timestamp, agent.name, agent.ip, rule.id, rule.description,
      rule.level, data.srcip, data.dstip, full_log, etc.

    Returns:
        NormalizedAlert dict matching the agreed schema
    """
    agent = raw.get("agent", {})
    rule = raw.get("rule", {})
    data = raw.get("data", {})

    # Extract MITRE technique if Wazuh already mapped it
    mitre = raw.get("rule", {}).get("mitre", {})
    technique_ids = mitre.get("id", [])
    technique_names = mitre.get("technique", [])

    technique_id = technique_ids[0] if technique_ids else None
    technique_name = technique_names[0] if technique_names else None

    # Infer category from rule groups
    groups = rule.get("groups", [])
    category = _infer_category(groups, rule.get("description", ""))

    # Extract network indicators
    src_ip = (data.get("srcip") or
              data.get("src_ip") or
              raw.get("data", {}).get("srcip"))

    dst_ip = (data.get("dstip") or
              agent.get("ip"))

    username = (data.get("dstuser") or
                data.get("srcuser") or
                data.get("user"))

    return {
        "alert_id": raw.get("id", f"wazuh-{raw.get('_id', 'unknown')}"),
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
        "raw_log": raw.get("full_log", raw.get("message", "")),
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
            "technique_id": technique_id,
            "technique_name": technique_name
        },
        "status": "new"
    }


def _infer_category(groups: list, description: str) -> str:
    """
    Infer alert category from Wazuh rule groups and description.
    Maps to the fixed category list in alert_schema.md.
    """
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


# ─────────────────────────────────────────────────────────
# PRIMARY: Wazuh API — fetch alerts
# ─────────────────────────────────────────────────────────
def _fetch_alerts_via_api(
    agent_name: str = "kali",
    limit: int = 10,
    min_level: int = 3
) -> list:
    """
    Fetch recent alerts from Wazuh API for a specific agent.

    Uses the /security/events endpoint (Wazuh 4.x).
    Falls back to /alerts if events endpoint is unavailable.
    """
    # Try /security/events first (Wazuh 4.3+)
    params = {
        "agent_name": agent_name,
        "limit": limit,
        "sort": "-timestamp",
        "q": f"rule.level>={min_level}"
    }

    response = _api_get("/events", {
    "agent.name": agent_name,
    "limit": limit,
    "sort": "-timestamp",
    "min_rule_level": min_level
	})

    if response and response.get("data", {}).get("affected_items"):
        raw_alerts = response["data"]["affected_items"]
        return [_normalize_alert(a) for a in raw_alerts]

    # Fallback: try /alerts endpoint
    response = _api_get("/alerts", {
        "agent.name": agent_name,
        "limit": limit,
        "sort": "-timestamp"
    })

    if response and response.get("data", {}).get("affected_items"):
        raw_alerts = response["data"]["affected_items"]
        return [_normalize_alert(a) for a in raw_alerts]

    return []


# ─────────────────────────────────────────────────────────
# FALLBACK: File-based alert reading via Docker exec
# ─────────────────────────────────────────────────────────
def _fetch_alerts_via_file(limit: int = 10) -> list:
    """
    Read alerts directly from Wazuh's alerts.json file
    via docker exec. Used as fallback when API is unavailable.

    Wazuh writes one JSON object per line to alerts.json.
    We read the last `limit` lines.
    """
    try:
        result = subprocess.run(
            [
                "docker", "exec",
                WAZUH_MANAGER_CONTAINER,
                "tail", f"-{limit * 3}",  # fetch extra lines in case some are malformed
                WAZUH_ALERTS_FILE
            ],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode != 0:
            print(f"[warn] Docker exec failed: {result.stderr}")
            return []

        alerts = []
        for line in result.stdout.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
                alerts.append(_normalize_alert(raw))
                if len(alerts) >= limit:
                    break
            except json.JSONDecodeError:
                continue

        return alerts

    except subprocess.TimeoutExpired:
        print("[warn] Docker exec timed out")
        return []
    except FileNotFoundError:
        print("[warn] Docker not found — cannot read alert file")
        return []
    except Exception as e:
        print(f"[warn] File-based fallback failed: {e}")
        return []


# ─────────────────────────────────────────────────────────
# PUBLIC FUNCTIONS (called by agent tools)
# ─────────────────────────────────────────────────────────
def get_recent_alerts(
    agent_name: str = "kali",
    limit: int = 10,
    min_level: int = 3
) -> list:
    """
    Get recent alerts from Wazuh — tries API first, falls back to file.

    Args:
        agent_name: Wazuh agent name to filter by (default "kali")
        limit:      Maximum number of alerts to return
        min_level:  Minimum Wazuh severity level (0-15, default 3)

    Returns:
        List of NormalizedAlert dicts, newest first
    """
    print(f"[query_siem] Fetching last {limit} alerts from agent '{agent_name}'...")

    # Try API first
    alerts = _fetch_alerts_via_api(agent_name, limit, min_level)

    if alerts:
        print(f"[query_siem] Retrieved {len(alerts)} alerts via API")
        return alerts

    # Fallback to file
    print("[query_siem] API unavailable — trying file-based fallback...")
    alerts = _fetch_alerts_via_file(limit)

    if alerts:
        print(f"[query_siem] Retrieved {len(alerts)} alerts via file fallback")
        return alerts

    print("[query_siem] No alerts retrieved from either source")
    return []


def get_alert_by_id(alert_id: str) -> Optional[dict]:
    """
    Fetch a specific alert by its Wazuh alert ID.

    Args:
        alert_id: Wazuh alert ID string

    Returns:
        NormalizedAlert dict, or None if not found
    """
    token = _get_jwt_token()
    if not token:
        return None

    response = _api_get("/alerts", {"q": f"id={alert_id}", "limit": 1})

    if response and response.get("data", {}).get("affected_items"):
        return _normalize_alert(response["data"]["affected_items"][0])

    return None


def get_alerts_by_ip(src_ip: str, limit: int = 5) -> list:
    """
    Find recent alerts involving a specific source IP.
    Used by the agent when investigating a suspicious IP indicator.

    Args:
        src_ip: Source IP address to search for
        limit:  Maximum results

    Returns:
        List of NormalizedAlert dicts
    """
    response = _api_get("/alerts", {
        "q": f"data.srcip={src_ip}",
        "limit": limit,
        "sort": "-timestamp"
    })

    if response and response.get("data", {}).get("affected_items"):
        return [_normalize_alert(a) for a in response["data"]["affected_items"]]

    return []


def get_agent_status() -> dict:
    """
    Get status of all registered Wazuh agents.
    Used by agent to confirm which hosts are being monitored.

    Returns:
        Dict with agent summary stats
    """
    response = _api_get("/agents", {"limit": 20, "sort": "name"})

    if not response:
        return {"error": "API unavailable", "agents": []}

    agents = response.get("data", {}).get("affected_items", [])

    return {
        "total_agents": len(agents),
        "agents": [
            {
                "id": a.get("id"),
                "name": a.get("name"),
                "ip": a.get("ip"),
                "status": a.get("status"),
                "os": a.get("os", {}).get("name", "unknown"),
                "last_keep_alive": a.get("lastKeepAlive")
            }
            for a in agents
        ]
    }


# ─────────────────────────────────────────────────────────
# LANGCHAIN @tool WRAPPER
# This is what the ReAct agent calls in Phase 3
# ─────────────────────────────────────────────────────────
@tool
def query_siem(input: str) -> str:
    """
    Query the Wazuh SIEM for recent security alerts.

    Use this tool when you need to:
    - Fetch recent alerts from the monitored Kali agent
    - Find other alerts related to a suspicious IP address
    - Check the current status of monitored agents
    - Get context about what else happened around the time of an alert

    Input format (one of):
        "recent"                    — get last 10 alerts from kali agent
        "recent:N"                  — get last N alerts (e.g. "recent:5")
        "ip:192.168.80.129"         — get alerts involving this IP
        "agent:hostname"            — get alerts from specific agent
        "status"                    — get agent connection status

    Returns:
        JSON string with list of normalized alerts or agent status
    """
    inp = input.strip().lower()

    try:
        if inp.startswith("ip:"):
            src_ip = input.split(":", 1)[1].strip()
            alerts = get_alerts_by_ip(src_ip, limit=5)
            return json.dumps({
                "query": f"alerts for IP {src_ip}",
                "count": len(alerts),
                "alerts": alerts
            }, indent=2)

        elif inp.startswith("agent:"):
            agent_name = input.split(":", 1)[1].strip()
            alerts = get_recent_alerts(agent_name=agent_name, limit=10)
            return json.dumps({
                "query": f"recent alerts from agent {agent_name}",
                "count": len(alerts),
                "alerts": alerts
            }, indent=2)

        elif inp == "status":
            status = get_agent_status()
            return json.dumps(status, indent=2)

        elif inp.startswith("recent:"):
            try:
                n = int(inp.split(":")[1])
            except (ValueError, IndexError):
                n = 10
            alerts = get_recent_alerts(limit=n)
            return json.dumps({
                "query": f"last {n} alerts",
                "count": len(alerts),
                "alerts": alerts
            }, indent=2)

        else:
            # Default: get recent alerts
            alerts = get_recent_alerts(limit=10)
            return json.dumps({
                "query": "recent alerts",
                "count": len(alerts),
                "alerts": alerts
            }, indent=2)

    except Exception as e:
        return json.dumps({
            "error": str(e),
            "message": "query_siem tool encountered an error"
        })


# ─────────────────────────────────────────────────────────
# STANDALONE TEST
# ─────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("  VigilanceAI — query_siem Tool Test")
    print("=" * 60)

    # Test 1: Authenticate
    print("\n[Test 1] Wazuh API Authentication...")
    token = _get_jwt_token()
    if token:
        print(f"  ✓ JWT token obtained ({len(token)} chars)")
    else:
        print("  ✗ Authentication failed — will use file fallback")

    # Test 2: Agent status
    print("\n[Test 2] Agent Status...")
    status = get_agent_status()
    if "agents" in status:
        print(f"  ✓ Found {status['total_agents']} agent(s):")
        for a in status["agents"]:
            print(f"    - {a['name']} ({a['ip']}) — {a['status']}")
    else:
        print(f"  ✗ {status.get('error', 'Unknown error')}")

    # Test 3: Recent alerts
    print("\n[Test 3] Recent Alerts (last 5)...")
    alerts = get_recent_alerts(limit=5)
    if alerts:
        print(f"  ✓ Retrieved {len(alerts)} alert(s):")
        for a in alerts:
            print(f"    [{a['rule']['level']:2d}] {a['rule']['description'][:60]}")
            print(f"         Category: {a['category']} | "
                  f"Agent: {a['source']['agent_name']}")
    else:
        print("  ✗ No alerts retrieved")
        print("    Make sure Wazuh containers are running:")
        print("    cd siem/wazuh-docker && docker-compose up -d")

    # Test 4: LangChain tool call simulation
    print("\n[Test 4] LangChain @tool call simulation...")
    result = query_siem.invoke("recent:3")
    parsed = json.loads(result)
    print(f"  ✓ Tool returned {parsed.get('count', 0)} alerts")

    # Test 5: IP-based query
    print("\n[Test 5] IP-based alert query...")
    result = query_siem.invoke("ip:192.168.80.129")
    parsed = json.loads(result)
    print(f"  ✓ Found {parsed.get('count', 0)} alerts for 192.168.80.129")

    print("\n" + "=" * 60)
    print("  Test complete. Share agent/tools/query_siem.py with Neeraj.")
    print("  He imports it in react_agent.py as:")
    print("  from agent.tools.query_siem import query_siem")
    print("=" * 60)
