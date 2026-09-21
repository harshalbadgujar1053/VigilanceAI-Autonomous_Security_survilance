"""
Benchmarks /alerts response time across filter/pagination combos, before and
after applying the drafted-but-not-yet-applied indexes on created_at,
severity, verdict. Since no indexes exist yet beyond primary keys, this
script's "before" run against live data IS the true baseline.

Usage:
    # 1. Baseline (no indexes)
    python db_bench.py --base-url http://192.168.80.129:8001 --label before

    # 2. Apply the indexes
    python db_bench.py --apply-indexes --db-url "postgresql://vigilance:<pw>@localhost:5432/vigilancedb_test"

    # 3. Re-run
    python db_bench.py --base-url http://192.168.80.129:8001 --label after --db-url "postgresql://..." --explain
"""
import argparse
import statistics
import time

import psycopg2
import requests

FILTER_COMBOS = [
    {"limit": 20},
    {"limit": 20, "severity": "HIGH"},
    {"limit": 20, "verdict": "TRUE POSITIVE"},
    {"limit": 20, "severity": "CRITICAL", "verdict": "NEEDS INVESTIGATION"},
    {"limit": 200},  # max page size
]

# Since /alerts merges alerts + classifications (returns severity/verdict/
# technique/reasoning together per the confirmed response schema), the
# underlying query is presumably a JOIN. Adjust this to match backend/main.py's
# actual query if it differs.
EXPLAIN_QUERY = """
    SELECT a.*, c.verdict, c.confidence, c.mitre_tactics, c.reasoning, c.recommended_actions
    FROM alerts a
    LEFT JOIN classifications c ON c.alert_id = a.id
    WHERE a.severity = 'HIGH'
    ORDER BY a.created_at DESC
    LIMIT 20;
"""

INDEX_STATEMENTS = [
    "CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts (created_at DESC);",
    "CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts (severity);",
    "CREATE INDEX IF NOT EXISTS idx_classifications_verdict ON classifications (verdict);",
    "CREATE INDEX IF NOT EXISTS idx_classifications_alert_id ON classifications (alert_id);",
]


def apply_indexes(db_url):
    conn = psycopg2.connect(db_url)
    cur = conn.cursor()
    for stmt in INDEX_STATEMENTS:
        print(f"Running: {stmt}")
        cur.execute(stmt)
    conn.commit()
    cur.close()
    conn.close()
    print("Indexes applied.")


def time_request(base_url, params, n=10):
    times = []
    for _ in range(n):
        t0 = time.perf_counter()
        r = requests.get(f"{base_url}/alerts", params=params, timeout=30)
        times.append(time.perf_counter() - t0)
        assert r.status_code == 200, f"Bad status {r.status_code}: {r.text[:200]}"
    return {
        "p50": statistics.median(times),
        "p95": sorted(times)[max(int(len(times) * 0.95) - 1, 0)],
        "max": max(times),
    }


def explain_analyze(db_url):
    conn = psycopg2.connect(db_url)
    cur = conn.cursor()
    cur.execute(f"EXPLAIN ANALYZE {EXPLAIN_QUERY}")
    plan = "\n".join(row[0] for row in cur.fetchall())
    print(f"--- EXPLAIN ANALYZE ---\n{plan}\n")
    cur.close()
    conn.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url")
    ap.add_argument("--db-url")
    ap.add_argument("--label", default="run")
    ap.add_argument("--apply-indexes", action="store_true")
    ap.add_argument("--explain", action="store_true")
    args = ap.parse_args()

    if args.apply_indexes:
        if not args.db_url:
            raise SystemExit("--apply-indexes requires --db-url")
        if "vigilancedb_test" not in args.db_url:
            raise SystemExit("Refusing: --db-url must point at vigilancedb_test, not production.")
        apply_indexes(args.db_url)
        return

    if not args.base_url:
        raise SystemExit("--base-url required unless using --apply-indexes")

    print(f"=== [{args.label}] Benchmarking {args.base_url}/alerts ===\n")
    for combo in FILTER_COMBOS:
        stats = time_request(args.base_url, combo)
        print(f"filters={combo!r:55s}  p50={stats['p50']*1000:7.1f}ms  "
              f"p95={stats['p95']*1000:7.1f}ms  max={stats['max']*1000:7.1f}ms")

    if args.explain and args.db_url:
        print()
        explain_analyze(args.db_url)


if __name__ == "__main__":
    main()
