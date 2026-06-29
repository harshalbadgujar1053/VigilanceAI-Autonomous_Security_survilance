"""
query_siem.py — Tool 4 for Vigilance AI ReAct Agent
----------------------------------------------------
Project: Vigilance AI

Queries the SIEM for recent security alerts.

Currently uses simulated alerts matching the NormalizedAlert schema.
When SIEM teammate completes the Wazuh pipeline, replace
_fetch_from_wazuh() with their actual API endpoint call.

No change needed in the tool interface or agent code —
only the data source changes.
"""

import json
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from langchain.tools import tool
from datetime import datetime, timedelta


# ─────────────────────────────────────────────
# 1. SIMULATED ALERT STORE
#    Mirrors real Wazuh alert JSON structure.
#    Replace with actual Wazuh API call in Phase 4.
# ─────────────────────────────────────────────
SIMULATED_ALERTS = [
    {
        "id": "1717000001",
        "timestamp": "2024-05-30T14:22:01.000Z",
        "rule": {
            "id": "5712",
            "description": "Multiple failed SSH login attempts (possible brute force)",
            "level": 10,
            "groups": ["authentication_failures", "syslog", "sshd"]
        },
        "agent": {"id": "001", "name": "web-server-prod", "ip": "10.0.1.45"},
        "data": {
            "srcip": "185.220.101.47",
            "dstip": "10.0.1.45",
            "protocol": "ssh",
            "attempt_count": 847,
            "timespan_seconds": 60
        },
        "location": "/var/log/auth.log"
    },
    {
        "id": "1717000002",
        "timestamp": "2024-05-30T15:01:00.000Z",
        "rule": {
            "id": "531",
            "description": "Disk space usage above 80%",
            "level": 3,
            "groups": ["low_diskspace", "ossec"]
        },
        "agent": {"id": "002", "name": "db-server-01", "ip": "10.0.1.12"},
        "data": {"extra": {"disk_usage_pct": 83, "mount": "/var"}},
        "location": "/var/log/syslog"
    },
    {
        "id": "1717000003",
        "timestamp": "2024-05-30T16:45:00.000Z",
        "rule": {
            "id": "510",
            "description": "Rootkit detection: hidden process found",
            "level": 15,
            "groups": ["rootcheck", "rootkit"]
        },
        "agent": {"id": "003", "name": "app-server-02", "ip": "10.0.1.23"},
        "data": {"extra": {"hidden_pid": 4821, "process_name": "kthread"}},
        "location": "rootcheck"
    },
    {
        "id": "1717000004",
        "timestamp": "2024-05-30T17:10:00.000Z",
        "rule": {
            "id": "5503",
            "description": "User login failed — invalid password",
            "level": 5,
            "groups": ["authentication_failures", "syslog"]
        },
        "agent": {"id": "001", "name": "web-server-prod", "ip": "10.0.1.45"},
        "data": {
            "srcip": "192.168.1.55",
            "protocol": "ssh",
            "attempt_count": 3,
            "timespan_seconds": 120
        },
        "location": "/var/log/auth.log"
    },
    {
        "id": "1717000005",
        "timestamp": "2024-05-30T18:00:00.000Z",
        "rule": {
            "id": "550",
            "description": "Integrity checksum changed — possible file modification",
            "level": 7,
            "groups": ["syscheck", "integrity_check_host"]
        },
        "agent": {"id": "002", "name": "db-server-01", "ip": "10.0.1.12"},
        "data": {"extra": {"file": "/etc/passwd", "old_hash": "abc123", "new_hash": "xyz789"}},
        "location": "syscheck"
    }
]


# ─────────────────────────────────────────────
# 2. FILTER FUNCTIONS
# ─────────────────────────────────────────────
def _filter_by_level(alerts: list, min_level: int) -> list:
    return [a for a in alerts if a["rule"]["level"] >= min_level]


def _filter_by_id(alerts: list, alert_id: str) -> list:
    return [a for a in alerts if a["id"] == alert_id]


def _format_alert_summary(alert: dict) -> str:
    rule = alert["rule"]
    agent = alert["agent"]
    data = alert["data"]

    srcip = data.get("srcip", "N/A")
    attempts = data.get("attempt_count", "")
    attempts_str = f", {attempts} attempts" if attempts else ""

    return (
        f"[Alert {alert['id']}] "
        f"Level {rule['level']}/15 | "
        f"{rule['description']} | "
        f"Host: {agent['name']} ({agent['ip']}) | "
        f"Source IP: {srcip}{attempts_str} | "
        f"Time: {alert['timestamp']}"
    )


# ─────────────────────────────────────────────
# 3. THE TOOL
# ─────────────────────────────────────────────
@tool
def query_siem(query: str) -> str:
    """
    Query the SIEM (Security Information and Event Management) system
    for recent security alerts. Can filter by alert ID, severity level,
    or return a summary of recent alerts.

    Use this tool when you need to:
    - Get details of a specific alert by its ID
    - See recent high-severity alerts across all hosts
    - Find all alerts from a specific time window

    Args:
        query: What to search for. Examples:
               "alert 1717000001" — get specific alert by ID
               "critical alerts" — get level 10+ alerts
               "high severity" — get level 7+ alerts
               "all recent" — get all recent alerts summary
               "recent alerts" — get all recent alerts summary

    Returns:
        Formatted list of matching alerts with severity,
        description, host, source IP, and timestamp.
    """
    try:
        query_lower = query.lower()

        # Check for specific alert ID
        if "alert" in query_lower and any(
            word.isdigit() for word in query_lower.split()
        ):
            for word in query_lower.split():
                if word.isdigit() or word.startswith("171"):
                    matches = _filter_by_id(SIMULATED_ALERTS, word)
                    if matches:
                        alert = matches[0]
                        return (
                            f"Alert Details:\n"
                            f"{json.dumps(alert, indent=2)}"
                        )

        # Filter by severity keywords
        if any(word in query_lower for word in ["critical", "level 10", "high priority"]):
            matches = _filter_by_level(SIMULATED_ALERTS, 10)
            label = "CRITICAL (level 10+)"
        elif any(word in query_lower for word in ["high", "level 7", "important"]):
            matches = _filter_by_level(SIMULATED_ALERTS, 7)
            label = "HIGH severity (level 7+)"
        else:
            # Return all recent alerts
            matches = SIMULATED_ALERTS
            label = "recent"

        if not matches:
            return f"No {label} alerts found in SIEM."

        lines = [f"Found {len(matches)} {label} alerts:\n"]
        for alert in matches:
            lines.append(_format_alert_summary(alert))

        return "\n".join(lines)

    except Exception as e:
        return f"SIEM query failed: {str(e)}"


# ─────────────────────────────────────────────
# 4. TEST
# ─────────────────────────────────────────────
if __name__ == "__main__":
    print("TEST 1 — All recent alerts:")
    print(query_siem.invoke("all recent alerts"))
    print("\n" + "─" * 60)

    print("\nTEST 2 — Critical alerts only:")
    print(query_siem.invoke("critical alerts"))
    print("\n" + "─" * 60)

    print("\nTEST 3 — Specific alert by ID:")
    print(query_siem.invoke("alert 1717000003"))
