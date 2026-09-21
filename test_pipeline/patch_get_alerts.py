"""
Automatically replaces the old get_alerts() function in backend/main.py with
the fixed version that supports limit/severity/verdict/before/search params.
Uses exact text matching (not line numbers) so it's safe regardless of any
other edits already made to the file.

Usage:
    python3 patch_get_alerts.py /home/kali/VigilanceAI-Autonomous_Security_survilance/backend/main.py

Makes a .bak backup before writing, and refuses to run twice (if the new
code is already present, it exits without changes).
"""
import sys

OLD_BLOCK = '''@app.get("/alerts")
def get_alerts(db: Session = Depends(get_db)):
    alerts = db.query(AlertRecord).order_by(AlertRecord.created_at.desc()).all()

    # Fetch the latest classification per alert_id in one query, so the
    # frontend gets technique/reasoning/recommended_actions for free on
    # load instead of having to trigger classification itself.
    alert_ids = [a.id for a in alerts]
    latest_by_alert = {}
    if alert_ids:
        classifications = (
            db.query(ClassificationRecord)
            .filter(ClassificationRecord.alert_id.in_(alert_ids))
            .order_by(ClassificationRecord.classified_at.desc())
            .all()
        )
        for c in classifications:
            if c.alert_id not in latest_by_alert:
                latest_by_alert[c.alert_id] = c

    result = []
    for a in alerts:
        cls = latest_by_alert.get(a.id)
        entry = {
            "id": a.id,
            "timestamp": a.timestamp,
            "rule_id": a.rule_id,
            "rule_level": a.rule_level,
            "description": a.description,
            "agent_name": a.agent_name,
            "agent_ip": a.agent_ip,
            "severity": a.severity,
            "raw_data": a.raw_data,
            "created_at": str(a.created_at)
        }
        if cls:
            entry["technique"] = cls.mitre_tactics
            entry["reasoning"] = cls.reasoning
            entry["recommended_actions"] = cls.recommended_actions
        result.append(entry)

    return {"success": True, "count": len(result), "alerts": result}'''

NEW_BLOCK = '''@app.get("/alerts")
def get_alerts(
    db: Session = Depends(get_db),
    limit: int = Query(50, ge=1, le=200),
    before: str | None = Query(None, description="ISO datetime cursor — return alerts created before this"),
    severity: str | None = Query(None),
    verdict: str | None = Query(None),
    search: str | None = Query(None, description="matches against description"),
):
    latest_classification_ids = (
        db.query(
            ClassificationRecord.alert_id,
            func.max(ClassificationRecord.classified_at).label("max_classified_at"),
        )
        .group_by(ClassificationRecord.alert_id)
        .subquery()
    )

    query = (
        db.query(AlertRecord, ClassificationRecord)
        .outerjoin(
            latest_classification_ids,
            AlertRecord.id == latest_classification_ids.c.alert_id,
        )
        .outerjoin(
            ClassificationRecord,
            and_(
                ClassificationRecord.alert_id == latest_classification_ids.c.alert_id,
                ClassificationRecord.classified_at == latest_classification_ids.c.max_classified_at,
            ),
        )
    )

    if severity:
        query = query.filter(AlertRecord.severity == severity)
    if verdict:
        query = query.filter(ClassificationRecord.verdict == verdict)
    if search:
        query = query.filter(AlertRecord.description.ilike(f"%{search}%"))
    if before:
        try:
            cursor_dt = datetime.fromisoformat(before)
            query = query.filter(AlertRecord.created_at < cursor_dt)
        except ValueError:
            raise HTTPException(status_code=422, detail=f"Invalid 'before' cursor: {before}")

    query = query.order_by(AlertRecord.created_at.desc())

    rows = query.limit(limit + 1).all()
    has_more = len(rows) > limit
    rows = rows[:limit]

    result = []
    for a, cls in rows:
        entry = {
            "id": a.id,
            "timestamp": a.timestamp,
            "rule_id": a.rule_id,
            "rule_level": a.rule_level,
            "description": a.description,
            "agent_name": a.agent_name,
            "agent_ip": a.agent_ip,
            "severity": a.severity,
            "raw_data": a.raw_data,
            "created_at": str(a.created_at),
        }
        if cls:
            entry["technique"] = cls.mitre_tactics
            entry["reasoning"] = cls.reasoning
            entry["recommended_actions"] = cls.recommended_actions
            entry["verdict"] = cls.verdict
            entry["confidence"] = cls.confidence
        result.append(entry)

    next_cursor = str(rows[-1][0].created_at) if rows and has_more else None

    return {
        "success": True,
        "count": len(result),
        "alerts": result,
        "next_cursor": next_cursor,
        "has_more": has_more,
    }'''


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 patch_get_alerts.py <path-to-main.py>")
        sys.exit(1)

    path = sys.argv[1]
    with open(path, "r") as f:
        content = f.read()

    if NEW_BLOCK in content:
        print("New code already present — nothing to do.")
        return

    if OLD_BLOCK not in content:
        print("ERROR: Could not find the expected old get_alerts() block.")
        print("The file may already be partially edited, or whitespace differs "
              "from what this script expects. No changes made. "
              "Paste the current get_alerts() function and I'll adjust the script.")
        sys.exit(1)

    backup_path = path + ".bak_before_alerts_patch"
    with open(backup_path, "w") as f:
        f.write(content)
    print(f"Backup written to {backup_path}")

    new_content = content.replace(OLD_BLOCK, NEW_BLOCK)
    with open(path, "w") as f:
        f.write(new_content)

    print(f"Patched {path} successfully.")
    print("Now double check 'Query' is imported from fastapi and 'and_' from sqlalchemy,")
    print("then restart uvicorn.")


if __name__ == "__main__":
    main()
