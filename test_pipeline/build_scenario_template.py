"""
Builds a starter labeled_scenarios.json from your existing alert_samples/*.json,
so you're filling in ground-truth verdicts rather than writing the JSON
structure by hand.

Usage:
    python3 build_scenario_template.py --count 20

Then open labeled_scenarios.json and replace each "FILL_IN_GROUND_TRUTH"
with one of: "TRUE POSITIVE", "FALSE POSITIVE", "NEEDS INVESTIGATION"
based on your own judgment of what the alert actually represents.
"""
import argparse
import glob
import json
import os


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--samples-dir", default="./alert_samples/*.json")
    ap.add_argument("--count", type=int, default=20)
    ap.add_argument("--out", default="labeled_scenarios.json")
    args = ap.parse_args()

    paths = sorted(glob.glob(args.samples_dir))
    if not paths:
        raise SystemExit(f"No samples found at {args.samples_dir}")

    paths = paths[:args.count]
    scenarios = []
    for i, p in enumerate(paths):
        with open(p) as f:
            alert = json.load(f)
        description = alert.get("rule", {}).get("description", "unknown")
        scenarios.append({
            "id": f"scenario_{i:03d}_{description[:30].replace(' ', '_').lower()}",
            "alert": alert,
            "ground_truth_verdict": "FILL_IN_GROUND_TRUTH",
            "_hint_description": description,  # for your reference while filling in; harmless extra field
        })

    with open(args.out, "w") as f:
        json.dump(scenarios, f, indent=2)

    print(f"Wrote {len(scenarios)} scenarios to {args.out}")
    print("Now edit that file: replace each \"FILL_IN_GROUND_TRUTH\" with one of:")
    print('  "TRUE POSITIVE"  |  "FALSE POSITIVE"  |  "NEEDS INVESTIGATION"')
    print("Use the _hint_description field to see what each alert is without opening the full JSON.")


if __name__ == "__main__":
    main()
