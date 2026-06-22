"""
alert_schema.py
----------------
Project: VigilanceAI

Sample Wazuh-style alert objects for testing the classification chain.
These match the normalized alert schema defined in docs/alert_schema.md

Three samples covering the main attack types we simulate in Phase 1:
  - ssh_brute_force   (Hydra attack — rule 5710/5712)
  - rootkit_detection (Wazuh rootcheck — rule 510)
  - low_disk          (system health — rule 531, low severity)
"""

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
