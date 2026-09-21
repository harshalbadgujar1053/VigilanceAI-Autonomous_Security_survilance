"""
reclassify_pending.py — One-off script to re-classify alerts that failed
during the Aug 20 SSH brute-force burst due to Gemini 429 rate limits.

Reuses backend.main._classify_and_store so the parsing/storage logic
stays identical to the live pipeline (no third copy of this logic).

Usage (from repo root, with venv active):
    python3 reclassify_pending.py
"""
import sys
import os
import time

# Make sure backend/ and repo root are importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "backend"))
sys.path.insert(0, os.path.dirname(__file__))

from backend.main import _classify_and_store, SessionLocal, AlertRecord, ClassificationRecord

# The 9 confirmed rate-limited alert IDs from Aug 20 (excludes the 13
# legit pre-pipeline Aug 18 SCA audit alerts, which are expected to have
# no classification row).
TARGET_ALERT_IDS = [
    "1787201675.39298",
    "1787201676.41289",
    "1787201677.41825",
    "1787201679.42894",
    "1787201679.43430",
    "1787201681.43954",
    "1787201681.44499",
    "1787201681.45035",
    "1787201683.45559",
]

def main():
    db = SessionLocal()
    try:
        for alert_id in TARGET_ALERT_IDS:
            # Skip if it already somehow got classified since the handoff was written
            existing = db.query(ClassificationRecord).filter(
                ClassificationRecord.alert_id == alert_id
            ).first()
            if existing:
                print(f"[SKIP] {alert_id} already has a classification, skipping.")
                continue

            record = db.query(AlertRecord).filter(AlertRecord.id == alert_id).first()
            if not record:
                print(f"[WARN] {alert_id} not found in alerts table, skipping.")
                continue

            print(f"[CLASSIFY] {alert_id} ...")
            try:
                _classify_and_store(alert_id, record.raw_data)
                print(f"[OK] {alert_id} classified successfully.")
            except Exception as e:
                print(f"[FAIL] {alert_id} failed: {e}")

            # Small delay between calls to avoid re-triggering rate limits
            time.sleep(2)
    finally:
        db.close()

if __name__ == "__main__":
    main()
