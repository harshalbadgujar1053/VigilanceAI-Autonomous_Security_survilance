"""
alert_schema.py
----------------
Project: VigilanceAI — Autonomous Security Surveillance

Pydantic models for NormalizedAlert schema (used by FastAPI for
request validation) plus SAMPLE_ALERTS dict for testing.

Shared between:
  - backend/main.py        (FastAPI request validation)
  - agent/classify_alert.py (LangChain classification chain)
  - agent/tools/query_siem.py (alert normalization)
"""

from pydantic import BaseModel
from typing import Optional


# ─────────────────────────────────────────────────────────
# PYDANTIC MODELS
# ─────────────────────────────────────────────────────────

class RuleInfo(BaseModel):
    id: str
    description: str
    level: int

class AgentInfo(BaseModel):
    agent_name: str
    agent_ip: str

class Indicators(BaseModel):
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    username: Optional[str] = None
    process_name: Optional[str] = None
    file_hash: Optional[str] = None

class MitreHint(BaseModel):
    technique_id: Optional[str] = None
    technique_name: Optional[str] = None

class NormalizedAlert(BaseModel):
    alert_id: str
    timestamp: str
    source: AgentInfo
    rule: RuleInfo
    category: str
    raw_log: str
    indicators: Indicators
    mitre_hint: MitreHint
    status: str = "new"


# ─────────────────────────────────────────────────────────
# SAMPLE ALERTS — for testing classify_alert.py and FastAPI
# ─────────────────────────────────────────────────────────

SAMPLE_ALERTS = {

    "ssh_brute_force": {
        "alert_id": "a1b2c3d4-0001",
        "timestamp": "2026-06-19T10:31:08.000Z",
        "source": {
            "agent_name": "kali",
            "agent_ip": "192.168.80.129"
        },
        "rule": {
            "id": "5712",
            "description": "sshd: More than 8 authentication failures",
            "level": 10
        },
        "category": "brute_force",
        "raw_log": (
            "Jun 19 10:31:08 kali sshd[19304]: "
            "error: maximum authentication attempts exceeded "
            "for root from 192.168.80.129 port 46018 ssh2"
        ),
        "indicators": {
            "src_ip": "192.168.80.129",
            "dst_ip": "192.168.80.129",
            "src_port": 46018,
            "dst_port": 22,
            "username": "root",
            "process_name": "sshd",
            "file_hash": None
        },
        "mitre_hint": {
            "technique_id": "T1110",
            "technique_name": "Brute Force"
        },
        "status": "new"
    },

    "rootkit_detection": {
        "alert_id": "a1b2c3d4-0002",
        "timestamp": "2026-06-19T10:13:11.000Z",
        "source": {
            "agent_name": "kali",
            "agent_ip": "192.168.80.129"
        },
        "rule": {
            "id": "510",
            "description": "Host-based anomaly detection event (rootcheck)",
            "level": 7
        },
        "category": "malware",
        "raw_log": (
            "ossec: rootcheck: "
            "Hidden PID detected: 1234. "
            "Process not visible in /proc filesystem."
        ),
        "indicators": {
            "src_ip": None,
            "dst_ip": None,
            "src_port": None,
            "dst_port": None,
            "username": None,
            "process_name": "unknown",
            "file_hash": None
        },
        "mitre_hint": {
            "technique_id": "T1014",
            "technique_name": "Rootkit"
        },
        "status": "new"
    },

    "low_disk": {
        "alert_id": "a1b2c3d4-0003",
        "timestamp": "2026-06-19T09:00:00.000Z",
        "source": {
            "agent_name": "kali",
            "agent_ip": "192.168.80.129"
        },
        "rule": {
            "id": "531",
            "description": "Disk space usage exceeded 90%",
            "level": 4
        },
        "category": "other",
        "raw_log": (
            "ossec: output: 'df -P': "
            "/dev/sda1 100G 91G 9G 91% /"
        ),
        "indicators": {
            "src_ip": None,
            "dst_ip": None,
            "src_port": None,
            "dst_port": None,
            "username": None,
            "process_name": "df",
            "file_hash": None
        },
        "mitre_hint": {
            "technique_id": None,
            "technique_name": None
        },
        "status": "new"
    }
}
