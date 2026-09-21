"""
Seed vigilancedb_test with synthetic alerts + classifications at scale,
matching the CONFIRMED table DDL:

    alerts: id (PK, varchar), timestamp, rule_id, rule_level, description,
            agent_name, agent_ip, severity, raw_data (json), created_at
    classifications: id (PK serial), alert_id (varchar, FK-like to alerts.id),
                      severity, reasoning, mitre_tactics, recommended_actions,
                      classified_at, verdict, confidence

Usage:
    export DATABASE_URL="postgresql://vigilance:<pw>@localhost:5432/vigilancedb_test"
    python seed_db.py --count 5000
"""
import argparse
import json
import os
import random
import uuid
from datetime import datetime, timedelta

import psycopg2
from psycopg2.extras import execute_values, Json

SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
VERDICTS = ["TRUE POSITIVE", "FALSE POSITIVE", "NEEDS INVESTIGATION"]
CONFIDENCES = ["HIGH", "MEDIUM", "LOW"]
TECHNIQUES = [f"T{1000+i}" for i in range(50)]
RULE_DESCRIPTIONS = [
    "Multiple authentication failures",
    "SSH brute force attempt detected",
    "Suspicious outbound connection",
    "Web server 404 flood",
    "SQL injection pattern in access log",
    "New scheduled task created",
    "Unusual process spawned by web server",
]
AGENTS = [("web-01", "10.0.0.11"), ("db-01", "10.0.0.12"), ("kali-vm", "192.168.80.129")]


def random_timestamp(days_back=180):
    delta = timedelta(
        days=random.randint(0, days_back),
        hours=random.randint(0, 23),
        minutes=random.randint(0, 59),
    )
    return datetime.utcnow() - delta


def gen_alert_row():
    agent_name, agent_ip = random.choice(AGENTS)
    alert_id = str(uuid.uuid4())
    ts = random_timestamp()
    return alert_id, (
        alert_id,
        ts,
        str(random.randint(1000, 9999)),
        random.randint(1, 15),
        random.choice(RULE_DESCRIPTIONS),
        agent_name,
        agent_ip,
        random.choice(SEVERITIES),
        Json({"synthetic": True, "note": "seeded for load/db testing, not a real alert"}),
        ts,
    )


def gen_classification_row(alert_id):
    return (
        alert_id,
        random.choice(SEVERITIES),
        "Synthetic reasoning line one|Synthetic reasoning line two",
        random.choice(TECHNIQUES),
        "Synthetic action one|Synthetic action two",
        random_timestamp(),
        random.choice(VERDICTS),
        random.choice(CONFIDENCES),
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--count", type=int, default=5000)
    ap.add_argument("--batch-size", type=int, default=1000)
    ap.add_argument("--classification-rate", type=float, default=0.9,
                     help="fraction of alerts that also get a classification row")
    args = ap.parse_args()

    db_url = os.environ.get("DATABASE_URL", "")
    if "vigilancedb_test" not in db_url:
        raise SystemExit(
            "Refusing to run: DATABASE_URL does not contain 'vigilancedb_test'. "
            "Point this at the isolated test database, not production."
        )

    conn = psycopg2.connect(db_url)
    cur = conn.cursor()

    alert_insert = """
        INSERT INTO alerts
            (id, timestamp, rule_id, rule_level, description, agent_name,
             agent_ip, severity, raw_data, created_at)
        VALUES %s
    """
    classification_insert = """
        INSERT INTO classifications
            (alert_id, severity, reasoning, mitre_tactics, recommended_actions,
             classified_at, verdict, confidence)
        VALUES %s
    """

    inserted = 0
    while inserted < args.count:
        batch = min(args.batch_size, args.count - inserted)
        alert_ids, alert_rows = [], []
        for _ in range(batch):
            aid, row = gen_alert_row()
            alert_ids.append(aid)
            alert_rows.append(row)

        execute_values(cur, alert_insert, alert_rows)

        classification_rows = [
            gen_classification_row(aid) for aid in alert_ids
            if random.random() < args.classification_rate
        ]
        if classification_rows:
            execute_values(cur, classification_insert, classification_rows)

        conn.commit()
        inserted += batch
        print(f"Inserted {inserted}/{args.count} alerts "
              f"(+{len(classification_rows)} classifications this batch)")

    cur.close()
    conn.close()
    print("Seeding complete.")


if __name__ == "__main__":
    main()
