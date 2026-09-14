"""
reformat_existing_classifications_v2.py — Corrected version. The original
script's detection missed records where bullets are separated by real
newlines (e.g. "- foo\\n- bar") because it only checked for " - " with
a leading space, which doesn't match a bullet at the very start of a line.

This version: for any reasoning/recommended_actions field that doesn't yet
contain "|", split on newlines, strip leading "-"/"1."/etc from each line,
and pipe-join. Safe to re-run.
"""
import sys, os, re
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "backend"))
sys.path.insert(0, os.path.dirname(__file__))
from backend.database import SessionLocal, ClassificationRecord


def to_bullets(text: str, action_style: bool = False) -> str:
    if not text or "|" in text:
        return text
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    if len(lines) <= 1:
        # fallback: try splitting a single-line blob on dash-bullets
        parts = re.split(r'(?:(?<=\.)\s*-\s*|^-\s*)', text.strip())
        lines = [p.strip() for p in parts if p.strip()]
    cleaned = []
    for line in lines:
        c = re.sub(r'^\s*[-\d.]+\s*', '', line).strip() if action_style else re.sub(r'^\s*-\s*', '', line).strip()
        if c:
            cleaned.append(c)
    return " | ".join(cleaned) if cleaned else text


def main():
    db = SessionLocal()
    updated = 0
    try:
        records = db.query(ClassificationRecord).all()
        print(f"Found {len(records)} classification records.")
        for r in records:
            changed = False
            if r.reasoning and "|" not in r.reasoning:
                new_r = to_bullets(r.reasoning, action_style=False)
                if new_r != r.reasoning:
                    r.reasoning = new_r
                    changed = True
            if r.recommended_actions and "|" not in r.recommended_actions:
                new_a = to_bullets(r.recommended_actions, action_style=True)
                if new_a != r.recommended_actions:
                    r.recommended_actions = new_a
                    changed = True
            if changed:
                updated += 1
                print(f"[REFORMATTED] alert_id={r.alert_id} (id={r.id})")
        db.commit()
        print(f"\nDone. Reformatted {updated} of {len(records)} records.")
    except Exception as e:
        db.rollback()
        print(f"[ERROR] {e}")
    finally:
        db.close()


if __name__ == "__main__":
    main()
