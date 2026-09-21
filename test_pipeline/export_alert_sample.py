"""
Wazuh's alerts.json is typically one JSON object per line (JSONL), not a
JSON array. This splits N diverse samples out into individual files under
alert_samples/, for use by locustfile.py and accuracy_harness.py.

Usage:
    sudo python3 export_alert_samples.py --source /var/ossec/logs/alerts/alerts.json --count 30
"""
import argparse
import json
import os
import random


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", default="/var/ossec/logs/alerts/alerts.json")
    ap.add_argument("--out-dir", default="./alert_samples")
    ap.add_argument("--count", type=int, default=30)
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)

    alerts = []
    with open(args.source) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                alerts.append(json.loads(line))
            except json.JSONDecodeError:
                continue  # skip malformed/partial lines (log rotation artifacts)

    if not alerts:
        raise SystemExit(f"No valid JSON alerts parsed from {args.source}")

    print(f"Parsed {len(alerts)} alerts from source log")

    # Sample diversely by rule_level if present, else just random
    sample = random.sample(alerts, min(args.count, len(alerts)))

    for i, alert in enumerate(sample):
        with open(os.path.join(args.out_dir, f"sample_{i:03d}.json"), "w") as f:
            json.dump(alert, f, indent=2)

    print(f"Wrote {len(sample)} samples to {args.out_dir}/")


if __name__ == "__main__":
    main()
