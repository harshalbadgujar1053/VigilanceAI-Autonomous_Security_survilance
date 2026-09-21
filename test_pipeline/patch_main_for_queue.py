"""
Applies all three main.py changes needed for the classification queue:
  1. adds ClassificationQueue to the database import
  2. replaces _classify_and_store with the split parse/save/legacy-wrapper version
  3. replaces the direct background_tasks.add_task call in save_alert with an enqueue

Uses exact text matching (not line numbers), matches your actual current
main.py content pasted earlier in this conversation. Makes a .bak backup.

Usage:
    python3 patch_main_for_queue.py /home/kali/VigilanceAI-Autonomous_Security_survilance/backend/main.py
"""
import sys

# ---- Change 1: import line ----
OLD_IMPORT = "from database import SessionLocal, init_db, AlertRecord, ClassificationRecord, ReportRecord"
NEW_IMPORT = "from database import SessionLocal, init_db, AlertRecord, ClassificationRecord, ReportRecord, ClassificationQueue"

# ---- Change 2: _classify_and_store function, full replacement ----
OLD_FUNC = '''def _classify_and_store(alert_id: str, alert: dict):
    """
    Runs in the background AFTER the /alerts/save response has already
    been sent to the forwarder. This is intentional: ingestion must never
    block on a slow downstream classification call (Gemini can take a
    few seconds, and under a burst of alerts that adds up past a client's
    request timeout). Uses its own DB session since the request-scoped
    session from the original request is already closed by the time this runs.
    """
    db = SessionLocal()
    try:
        rag_result = classify_alert_with_rag(alert)
        classification_text = rag_result.get("classification", "") if isinstance(rag_result, dict) else str(rag_result)

        sev = "UNKNOWN"
        for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if s in classification_text.upper():
                sev = s
                break

        verdict_m = __import__("re").search(r"\\[VERDICT\\]\\s*([^\\n]+)", classification_text, __import__("re").IGNORECASE)
        confidence_m = __import__("re").search(r"\\[CONFIDENCE\\]\\s*(\\w+)", classification_text, __import__("re").IGNORECASE)
        verdict = verdict_m.group(1).strip().upper() if verdict_m else "NEEDS INVESTIGATION"
        confidence = confidence_m.group(1).strip().upper() if confidence_m else "LOW"
        mitre_technique = ""
        for line in classification_text.split("\\n"):
            if line.strip().upper().startswith("[TECHNIQUE]"):
                mitre_technique = line.split("]", 1)[-1].strip()
                break

        import re as _re
        m = _re.search(r"\\[REASONING\\]\\s*([\\s\\S]+?)(?=\\[RECOMMENDED|$)", classification_text, _re.IGNORECASE)
        reasoning_raw = m.group(1).strip() if m else ""
        # PATCHED: split into individual bullet lines and pipe-join, so the
        # frontend's alert.reasoning.split('|') produces separate <li>
        # items instead of one run-on paragraph.
        reasoning_lines = []
        for line in reasoning_raw.splitlines():
            cleaned = _re.sub(r"^\\s*-\\s*", "", line).strip()
            if cleaned:
                reasoning_lines.append(cleaned)
        reasoning_formatted = " | ".join(reasoning_lines) if reasoning_lines else reasoning_raw

        recommended_actions_raw = ""
        if "[RECOMMENDED ACTIONS]" in classification_text.upper():
            idx = classification_text.upper().find("[RECOMMENDED ACTIONS]")
            recommended_actions_raw = classification_text[idx + len("[RECOMMENDED ACTIONS]"):].strip()
        recommended_actions_lines = []
        for line in recommended_actions_raw.splitlines():
            cleaned = _re.sub(r"^\\s*[-\\d.]+\\s*", "", line).strip()
            if cleaned:
                recommended_actions_lines.append(cleaned)
        recommended_actions = " | ".join(recommended_actions_lines) if recommended_actions_lines else recommended_actions_raw

        record_to_update = db.query(AlertRecord).filter(AlertRecord.id == alert_id).first()
        cls_record = ClassificationRecord(
            alert_id=alert_id,
            severity=sev,
            reasoning=reasoning_formatted,
            mitre_tactics=mitre_technique,
            recommended_actions=recommended_actions,
            verdict=verdict,
            confidence=confidence
        )
        db.add(cls_record)
        if record_to_update:
            record_to_update.severity = sev
        db.commit()
        logger.info(f"Alert {alert_id} auto-classified as {sev} (background)")
    except Exception as e:
        logger.warning(f"Background auto-classification failed for {alert_id}: {e}. "
                        f"Alert stays at its last saved severity; can be classified manually later.")
    finally:
        db.close()'''

NEW_FUNC = '''import re as _re


def _parse_classification_text(classification_text: str) -> dict:
    sev = "UNKNOWN"
    for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if s in classification_text.upper():
            sev = s
            break

    verdict_m = _re.search(r"\\[VERDICT\\]\\s*([^\\n]+)", classification_text, _re.IGNORECASE)
    confidence_m = _re.search(r"\\[CONFIDENCE\\]\\s*(\\w+)", classification_text, _re.IGNORECASE)
    verdict = verdict_m.group(1).strip().upper() if verdict_m else "NEEDS INVESTIGATION"
    confidence = confidence_m.group(1).strip().upper() if confidence_m else "LOW"

    mitre_technique = ""
    for line in classification_text.split("\\n"):
        if line.strip().upper().startswith("[TECHNIQUE]"):
            mitre_technique = line.split("]", 1)[-1].strip()
            break

    m = _re.search(r"\\[REASONING\\]\\s*([\\s\\S]+?)(?=\\[RECOMMENDED|$)", classification_text, _re.IGNORECASE)
    reasoning_raw = m.group(1).strip() if m else ""
    reasoning_lines = []
    for line in reasoning_raw.splitlines():
        cleaned = _re.sub(r"^\\s*-\\s*", "", line).strip()
        if cleaned:
            reasoning_lines.append(cleaned)
    reasoning_formatted = " | ".join(reasoning_lines) if reasoning_lines else reasoning_raw

    recommended_actions_raw = ""
    if "[RECOMMENDED ACTIONS]" in classification_text.upper():
        idx = classification_text.upper().find("[RECOMMENDED ACTIONS]")
        recommended_actions_raw = classification_text[idx + len("[RECOMMENDED ACTIONS]"):].strip()
    recommended_actions_lines = []
    for line in recommended_actions_raw.splitlines():
        cleaned = _re.sub(r"^\\s*[-\\d.]+\\s*", "", line).strip()
        if cleaned:
            recommended_actions_lines.append(cleaned)
    recommended_actions = " | ".join(recommended_actions_lines) if recommended_actions_lines else recommended_actions_raw

    return {
        "severity": sev,
        "verdict": verdict,
        "confidence": confidence,
        "mitre_technique": mitre_technique,
        "reasoning": reasoning_formatted,
        "recommended_actions": recommended_actions,
    }


def _save_classification_result(db, alert_id: str, rag_result: dict):
    classification_text = rag_result.get("classification", "") if isinstance(rag_result, dict) else str(rag_result)
    parsed = _parse_classification_text(classification_text)

    record_to_update = db.query(AlertRecord).filter(AlertRecord.id == alert_id).first()
    cls_record = ClassificationRecord(
        alert_id=alert_id,
        severity=parsed["severity"],
        reasoning=parsed["reasoning"],
        mitre_tactics=parsed["mitre_technique"],
        recommended_actions=parsed["recommended_actions"],
        verdict=parsed["verdict"],
        confidence=parsed["confidence"],
    )
    db.add(cls_record)
    if record_to_update:
        record_to_update.severity = parsed["severity"]
    db.commit()
    logger.info(f"Alert {alert_id} classified as {parsed['severity']} / {parsed['verdict']}")


def _classify_and_store(alert_id: str, alert: dict):
    """LEGACY PATH — kept for backward compatibility only. New alerts go
    through the classification_queue worker instead (see save_alert)."""
    db = SessionLocal()
    try:
        rag_result = classify_alert_with_rag(alert)
        _save_classification_result(db, alert_id, rag_result)
    except Exception as e:
        logger.warning(f"Background auto-classification failed for {alert_id}: {e}. "
                        f"Alert stays at its last saved severity; can be classified manually later.")
    finally:
        db.close()'''

# ---- Change 3: save_alert's enqueue call ----
OLD_ENQUEUE = '''    # Kick off classification AFTER this response is sent — ingestion
    # returns immediately (well under the forwarder's request timeout),
    # and the classification result lands in Postgres a few seconds
    # later. The frontend's next GET /alerts poll picks it up naturally.
    background_tasks.add_task(_classify_and_store, record.id, alert)'''

NEW_ENQUEUE = '''    # Alert is queued for classification, not classified inline — this
    # decouples ingestion (which must stay fast) from Gemini's rate limit
    # (15/min). A background worker drains the queue at a steady pace;
    # queued items survive a backend restart since they're stored in Postgres.
    db.add(ClassificationQueue(alert_id=record.id))
    db.commit()'''


def apply_change(content, old, new, label):
    if new in content:
        print(f"[{label}] already applied — skipping.")
        return content, False
    if old not in content:
        print(f"[{label}] ERROR: expected old text not found. No change made for this part.")
        return content, None
    return content.replace(old, new, 1), True


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 patch_main_for_queue.py <path-to-main.py>")
        sys.exit(1)

    path = sys.argv[1]
    with open(path, "r") as f:
        content = f.read()

    backup_path = path + ".bak_before_queue_patch"
    with open(backup_path, "w") as f:
        f.write(content)
    print(f"Backup written to {backup_path}")

    any_failed = False
    content, ok = apply_change(content, OLD_IMPORT, NEW_IMPORT, "1/3 import line")
    any_failed = any_failed or (ok is None)

    content, ok = apply_change(content, OLD_FUNC, NEW_FUNC, "2/3 _classify_and_store split")
    any_failed = any_failed or (ok is None)

    content, ok = apply_change(content, OLD_ENQUEUE, NEW_ENQUEUE, "3/3 save_alert enqueue")
    any_failed = any_failed or (ok is None)

    with open(path, "w") as f:
        f.write(content)

    if any_failed:
        print("\\nSome changes could not be applied automatically (see ERROR lines above). "
              "The parts that DID match were still applied. Paste the current relevant "
              "section and I'll adjust.")
    else:
        print(f"\\nAll changes applied to {path} successfully.")
        print("Next: copy rate_limiter.py and classification_queue_worker.py into backend/, "
              "add the startup hook, run init_db(), and restart uvicorn.")


if __name__ == "__main__":
    main()
