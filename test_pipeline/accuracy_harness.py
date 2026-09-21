"""
Fixed version: /classify returns an ALREADY-PARSED dict under "classification"
(severity, technique, reasoning, verdict, confidence, rawText) — not raw
tagged text. No regex parsing needed; just read the fields directly.

Usage:
    python3 accuracy_harness.py --scenarios labeled_scenarios.json --base-url http://192.168.80.129:8001
"""
import argparse
import json
import time

import requests

VERDICTS = ["TRUE POSITIVE", "FALSE POSITIVE", "NEEDS INVESTIGATION"]
RATE_LIMIT_DELAY = 4.5  # seconds between calls — stays under 15/min with margin


def classify(base_url, alert):
    r = requests.post(f"{base_url}/classify", json={"alert": alert}, timeout=30)
    r.raise_for_status()
    classification = r.json().get("classification", {})
    verdict = classification.get("verdict", "").strip().upper()
    if verdict not in VERDICTS:
        raise ValueError(f"Unrecognized/missing verdict in response: {classification}")
    return verdict, classification


def confusion_matrix(y_true, y_pred):
    matrix = {a: {p: 0 for p in VERDICTS} for a in VERDICTS}
    for t, p in zip(y_true, y_pred):
        matrix[t][p] += 1
    return matrix


def precision_recall_f1(matrix):
    results = {}
    for v in VERDICTS:
        tp = matrix[v][v]
        fp = sum(matrix[o][v] for o in VERDICTS if o != v)
        fn = sum(matrix[v][o] for o in VERDICTS if o != v)
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
        results[v] = {"precision": precision, "recall": recall, "f1": f1, "support": tp + fn}
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenarios", required=True)
    ap.add_argument("--base-url", required=True)
    args = ap.parse_args()

    with open(args.scenarios) as f:
        scenarios = json.load(f)

    y_true, y_pred, errors, skipped = [], [], [], []
    for i, s in enumerate(scenarios):
        if s["ground_truth_verdict"] == "FILL_IN_GROUND_TRUTH":
            skipped.append(s["id"])
            print(f"[{i+1}/{len(scenarios)}] {s['id']}: SKIPPED (ground truth not filled in)")
            continue
        try:
            verdict, classification = classify(args.base_url, s["alert"])
        except Exception as e:
            errors.append((s["id"], str(e)))
            print(f"[{i+1}/{len(scenarios)}] {s['id']}: ERROR - {e}")
            time.sleep(RATE_LIMIT_DELAY)
            continue
        y_true.append(s["ground_truth_verdict"])
        y_pred.append(verdict)
        match = "OK" if verdict == s["ground_truth_verdict"] else "MISS"
        print(f"[{i+1}/{len(scenarios)}] {s['id']}: truth={s['ground_truth_verdict']:22s} "
              f"pred={verdict:22s} [{match}]")
        time.sleep(RATE_LIMIT_DELAY)  # stay safely under the 15/min Gemini free-tier limit

    matrix = confusion_matrix(y_true, y_pred)
    metrics = precision_recall_f1(matrix)

    print("\n=== Confusion Matrix (rows=truth, cols=predicted) ===")
    print("            " + "  ".join(f"{v[:12]:12s}" for v in VERDICTS))
    for v in VERDICTS:
        print(f"{v[:12]:12s}" + "  ".join(f"{matrix[v][p]:12d}" for p in VERDICTS))

    print("\n=== Per-class metrics ===")
    for v, m in metrics.items():
        print(f"{v:22s} precision={m['precision']:.3f}  recall={m['recall']:.3f}  "
              f"f1={m['f1']:.3f}  support={m['support']}")

    overall_acc = sum(t == p for t, p in zip(y_true, y_pred)) / len(y_true) if y_true else 0
    print(f"\nOverall verdict accuracy: {overall_acc:.3f}  (n={len(y_true)}, errors={len(errors)}, skipped={len(skipped)})")
    if errors:
        print("Failed scenarios:", errors)
    if skipped:
        print("Skipped (no ground truth filled in):", skipped)


if __name__ == "__main__":
    main()
