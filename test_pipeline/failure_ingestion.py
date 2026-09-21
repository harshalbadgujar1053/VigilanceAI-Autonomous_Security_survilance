"""
Resilience tests. Run LAST, against the test backend (:8001 / vigilancedb_test)
since these deliberately break things.

Test 1: Gemini API outage mid-burst
  - Blocks generativelanguage.googleapis.com at the OS level while alerts are
    being posted, to verify: (a) retry/backoff actually engages, (b) alerts
    aren't silently dropped, (c) a fallback/degraded report path exists if
    retries exhaust, (d) unblocking recovers cleanly without manual restart.

Test 2: Postgres connection drop mid-classification
  - Restarts Postgres while classification writes are in flight, to verify
    no partial/corrupt rows and no unhandled exceptions kill the backend.

Run each test manually (needs sudo on the Kali VM), with the Locust load test
or accuracy harness running concurrently in another terminal to generate traffic.
"""
import argparse
import subprocess
import time


def block_gemini(duration_s):
    print(f"Blocking Gemini API for {duration_s}s...")
    subprocess.run(
        ["sudo", "iptables", "-A", "OUTPUT", "-d", "generativelanguage.googleapis.com",
         "-j", "DROP"],
        check=False,  # DNS name in iptables may not resolve; see note below
    )
    print(
        "NOTE: iptables needs an IP, not a hostname, unless using ipset/dnsmasq. "
        "Resolve first: dig +short generativelanguage.googleapis.com, "
        "then: sudo iptables -A OUTPUT -d <ip> -j DROP"
    )
    time.sleep(duration_s)
    print("Unblocking Gemini API...")
    subprocess.run(["sudo", "iptables", "-F", "OUTPUT"], check=False)
    print("Unblocked. Now check backend logs / DB for: "
          "any alerts stuck 'pending', any dropped alerts, any unhandled 500s, "
          "and whether previously-failed alerts got reclassified after recovery "
          "or need a manual retry endpoint.")


def drop_postgres(duration_s):
    print("Stopping Postgres mid-flight...")
    subprocess.run(["sudo", "pg_ctlcluster", "18", "main", "stop", "-m", "fast"], check=False)
    time.sleep(duration_s)
    print("Restarting Postgres...")
    subprocess.run(["sudo", "pg_ctlcluster", "18", "main", "start"], check=False)
    print("Restarted. Check backend logs for: unhandled connection errors, "
          "whether BackgroundTasks in flight during the drop crashed the worker "
          "or retried, and whether any classification results were lost "
          "(compare count of alerts posted during the window vs rows written).")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--test", choices=["gemini-outage", "postgres-drop"], required=True)
    ap.add_argument("--duration", type=int, default=30)
    args = ap.parse_args()

    if args.test == "gemini-outage":
        block_gemini(args.duration)
    else:
        drop_postgres(args.duration)
