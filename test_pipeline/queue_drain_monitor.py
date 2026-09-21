"""
Polls the classification_queue table's backlog size over time, so you can
see it grow during a Locust burst and then drain at the expected steady
rate (~15/min) afterward. Run this in a separate terminal WHILE locustfile.py
is firing alerts.

Usage:
    export DATABASE_URL="postgresql://vigilance:<password>@localhost:5432/vigilancedb_test"
    python3 queue_drain_monitor.py --interval 5 --duration 600
"""
import argparse
import os
import time
from datetime import datetime

import psycopg2

QUERY = """
    SELECT status, count(*) FROM classification_queue GROUP BY status;
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--interval", type=int, default=5, help="seconds between samples")
    ap.add_argument("--duration", type=int, default=600, help="total seconds to run")
    args = ap.parse_args()

    db_url = os.environ.get("DATABASE_URL", "")
    if "vigilancedb_test" not in db_url:
        raise SystemExit("Point DATABASE_URL at vigilancedb_test before running this.")

    print(f"{'time':>10s}  {'pending':>8s}  {'processing':>10s}  {'done':>8s}  {'failed':>8s}")
    start = time.time()
    while time.time() - start < args.duration:
        conn = psycopg2.connect(db_url)
        cur = conn.cursor()
        cur.execute(QUERY)
        rows = dict(cur.fetchall())
        cur.close()
        conn.close()

        pending = rows.get("pending", 0)
        processing = rows.get("processing", 0)
        done = rows.get("done", 0)
        failed = rows.get("failed", 0)

        print(f"{datetime.now().strftime('%H:%M:%S'):>10s}  {pending:>8d}  {processing:>10d}  "
              f"{done:>8d}  {failed:>8d}")

        time.sleep(args.interval)


if __name__ == "__main__":
    main()
