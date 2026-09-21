"""
Identifies classification rows written BEFORE the wazuh_forwarder.py schema
fix (missing verdict/confidence/recommended_actions, or reasoning containing
raw unparsed tagged text like "[VERDICT]" instead of clean prose). These rows
should be excluded from accuracy test datasets and, ideally, re-classified.

Usage:
    export DATABASE_URL="postgresql://vigilance:<pw>@localhost:5432/vigilancedb"
    python data_quality_check.py
    python data_quality_check.py --reclassify-ids-out bad_ids.txt
"""
import argparse
import os

import psycopg2


FIND_MALFORMED_SQL = """
    SELECT id, alert_id, classified_at, verdict, confidence, recommended_actions,
           LEFT(reasoning, 80) AS reasoning_preview
    FROM classifications
    WHERE verdict IS NULL
       OR confidence IS NULL
       OR recommended_actions IS NULL
       OR verdict = ''
       OR confidence = ''
       OR recommended_actions = ''
       OR reasoning ILIKE '%[VERDICT]%'
       OR reasoning ILIKE '%[CONFIDENCE]%'
       OR reasoning ILIKE '%[SEVERITY]%'
    ORDER BY classified_at ASC;
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reclassify-ids-out", help="write affected alert_ids to this file, one per line")
    args = ap.parse_args()

    db_url = os.environ.get("DATABASE_URL")
    if not db_url:
        raise SystemExit("Set DATABASE_URL first.")

    conn = psycopg2.connect(db_url)
    cur = conn.cursor()
    cur.execute(FIND_MALFORMED_SQL)
    rows = cur.fetchall()
    cur.close()
    conn.close()

    print(f"Found {len(rows)} malformed/pre-fix classification rows:\n")
    for r in rows:
        cid, alert_id, classified_at, verdict, confidence, recommended_actions, preview = r
        print(f"  classification_id={cid}  alert_id={alert_id}  classified_at={classified_at}\n"
              f"    verdict={verdict!r} confidence={confidence!r} "
              f"recommended_actions={'<empty>' if not recommended_actions else '<present>'}\n"
              f"    reasoning preview: {preview!r}\n")

    if args.reclassify_ids_out and rows:
        with open(args.reclassify_ids_out, "w") as f:
            for r in rows:
                f.write(f"{r[1]}\n")  # alert_id
        print(f"Wrote {len(rows)} affected alert_ids to {args.reclassify_ids_out} "
              f"for re-classification or exclusion from test datasets.")

    if not rows:
        print("No malformed rows found — all classifications match the fixed schema.")


if __name__ == "__main__":
    main()
