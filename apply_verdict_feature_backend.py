"""
apply_verdict_feature_backend.py — Adds True Positive / False Positive
verdict + categorical confidence to the classification pipeline.

Patches:
  1. agent/classify_with_rag.py  — prompt template gains [VERDICT] + [CONFIDENCE]
  2. agent/classify_alert.py     — parse_llm_output extracts verdict/confidence
  3. backend/database.py         — ClassificationRecord gains verdict/confidence columns
  4. backend/main.py             — _classify_and_store, SaveClassificationRequest,
                                    save_classification, get_alerts all pass verdict/confidence through

Run from repo root: python3 apply_verdict_feature_backend.py
Idempotent — checks for markers before patching, aborts cleanly on mismatch.
Run the DB migration SQL separately BEFORE or AFTER this (order doesn't matter):
  sudo -u postgres psql -d vigilancedb -c "ALTER TABLE classifications ADD COLUMN IF NOT EXISTS verdict VARCHAR; ALTER TABLE classifications ADD COLUMN IF NOT EXISTS confidence VARCHAR;"
"""
import shutil
from pathlib import Path

def patch_file(path: Path, replacements: list[tuple[str, str]], marker: str, label: str) -> bool:
    if not path.exists():
        print(f"[SKIP] {path} not found.")
        return False
    src = path.read_text()
    if marker in src:
        print(f"[SKIP] {label}: already applied (marker found).")
        return True
    backup = path.with_suffix(path.suffix + ".bak")
    shutil.copy(path, backup)
    for old, new in replacements:
        if old not in src:
            print(f"[ERROR] {label}: expected text not found verbatim. Aborting this file, no changes written.")
            print(f"        Missing snippet starts with: {old[:60]!r}")
            return False
        src = src.replace(old, new)
    path.write_text(src)
    print(f"[OK] {label} patched. Backup at {backup}")
    return True


def main():
    # ── 1. Prompt template ──
    prompt_old = '''The technique for this alert has already been determined via retrieval to be:
{required_technique}

Respond in this EXACT format (no extra text before or after, no markdown).
IMPORTANT: Replace every placeholder with real analysis text. Never include
angle brackets or literal words like "bullet point" or "action" in your output.
The [TECHNIQUE] line MUST be exactly "{required_technique}" — do not
substitute a different technique. Write [REASONING] that specifically
justifies THIS technique, not any other technique from the context above.

[SEVERITY] <CRITICAL | HIGH | MEDIUM | LOW>
[TECHNIQUE] {required_technique}
[REASONING]
- <what triggered this alert — be specific to the actual data above>
- <how it maps specifically to {required_technique} — be specific>
- <key indicators of compromise — be specific>
[RECOMMENDED ACTIONS]
- <a concrete, specific action>
- <a concrete, specific action>
- <a concrete, specific action>
"""
)'''

    prompt_new = '''The technique for this alert has already been determined via retrieval to be:
{required_technique}

Respond in this EXACT format (no extra text before or after, no markdown).
IMPORTANT: Replace every placeholder with real analysis text. Never include
angle brackets or literal words like "bullet point" or "action" in your output.
The [TECHNIQUE] line MUST be exactly "{required_technique}" — do not
substitute a different technique. Write [REASONING] that specifically
justifies THIS technique, not any other technique from the context above.

Also assess whether this alert is likely a real attack (TRUE POSITIVE) or
likely benign/noise (FALSE POSITIVE) or genuinely unclear (NEEDS INVESTIGATION),
along with how confident you are in that assessment. Be honest about
uncertainty — do not default to HIGH confidence if the evidence is thin.

[VERDICT] <TRUE POSITIVE | FALSE POSITIVE | NEEDS INVESTIGATION>
[CONFIDENCE] <HIGH | MEDIUM | LOW>
[SEVERITY] <CRITICAL | HIGH | MEDIUM | LOW>
[TECHNIQUE] {required_technique}
[REASONING]
- <what triggered this alert — be specific to the actual data above>
- <how it maps specifically to {required_technique} — be specific>
- <key indicators of compromise — be specific>
[RECOMMENDED ACTIONS]
- <a concrete, specific action>
- <a concrete, specific action>
- <a concrete, specific action>
"""
)'''

    patch_file(
        Path("agent/classify_with_rag.py"),
        [(prompt_old, prompt_new)],
        marker="[VERDICT]",
        label="Prompt template (VERDICT/CONFIDENCE)"
    )

    # ── 2. parse_llm_output in agent/classify_alert.py ──
    parse_old = '''    technique = technique_match.group(1).strip() if technique_match else "T1543 - Create or Modify System Process"
    reasoning = []
    if reasoning_match:
        for line in reasoning_match.group(1).splitlines():
            cleaned = re.sub(r"^\\s*-\\s*", "", line).strip()
            if cleaned:
                reasoning.append(cleaned)
    if not reasoning:
        reasoning = ["Anomalous host event detected requiring automated SOC triage."]
    return {
        "severity": severity,
        "technique": technique,
        "reasoning": reasoning,
        "rawText": raw_text
    }'''

    parse_new = '''    technique = technique_match.group(1).strip() if technique_match else "T1543 - Create or Modify System Process"
    reasoning = []
    if reasoning_match:
        for line in reasoning_match.group(1).splitlines():
            cleaned = re.sub(r"^\\s*-\\s*", "", line).strip()
            if cleaned:
                reasoning.append(cleaned)
    if not reasoning:
        reasoning = ["Anomalous host event detected requiring automated SOC triage."]

    verdict_match = re.search(r"\\[VERDICT\\]\\s*([^\\n]+)", raw_text, re.IGNORECASE)
    confidence_match = re.search(r"\\[CONFIDENCE\\]\\s*(\\w+)", raw_text, re.IGNORECASE)
    verdict = verdict_match.group(1).strip().upper() if verdict_match else "NEEDS INVESTIGATION"
    confidence = confidence_match.group(1).strip().upper() if confidence_match else "LOW"

    return {
        "severity": severity,
        "technique": technique,
        "reasoning": reasoning,
        "verdict": verdict,
        "confidence": confidence,
        "rawText": raw_text
    }'''

    patch_file(
        Path("agent/classify_alert.py"),
        [(parse_old, parse_new)],
        marker='"verdict": verdict',
        label="parse_llm_output (verdict/confidence extraction)"
    )

    # ── 3. ClassificationRecord model ──
    model_old = '''class ClassificationRecord(Base):
    __tablename__ = "classifications"
    id             = Column(Integer, primary_key=True, autoincrement=True)
    alert_id       = Column(String)
    severity       = Column(String)
    reasoning      = Column(Text)
    mitre_tactics  = Column(Text)
    recommended_actions = Column(Text)
    classified_at  = Column(DateTime, default=datetime.utcnow)'''

    model_new = '''class ClassificationRecord(Base):
    __tablename__ = "classifications"
    id             = Column(Integer, primary_key=True, autoincrement=True)
    alert_id       = Column(String)
    severity       = Column(String)
    reasoning      = Column(Text)
    mitre_tactics  = Column(Text)
    recommended_actions = Column(Text)
    verdict        = Column(String, nullable=True)
    confidence     = Column(String, nullable=True)
    classified_at  = Column(DateTime, default=datetime.utcnow)'''

    patch_file(
        Path("backend/database.py"),
        [(model_old, model_new)],
        marker="verdict        = Column",
        label="ClassificationRecord model (verdict/confidence columns)"
    )

    # ── 4. backend/main.py — several edits ──
    main_path = Path("backend/main.py")
    if not main_path.exists():
        print("[SKIP] backend/main.py not found.")
    else:
        src = main_path.read_text()
        if "verdict: Optional[str]" in src:
            print("[SKIP] backend/main.py: already applied (marker found).")
        else:
            backup = main_path.with_suffix(".py.bak2")
            shutil.copy(main_path, backup)
            ok = True

            # 4a. SaveClassificationRequest gains verdict/confidence
            old = '''class SaveClassificationRequest(BaseModel):
    alert_id: str
    severity: str
    reasoning: str
    mitre_tactics: Optional[str] = ""
    recommended_actions: Optional[str] = ""'''
            new = '''class SaveClassificationRequest(BaseModel):
    alert_id: str
    severity: str
    reasoning: str
    mitre_tactics: Optional[str] = ""
    recommended_actions: Optional[str] = ""
    verdict: Optional[str] = ""
    confidence: Optional[str] = ""'''
            if old in src:
                src = src.replace(old, new)
            else:
                print("[ERROR] SaveClassificationRequest block not found verbatim.")
                ok = False

            # 4b. save_classification endpoint stores verdict/confidence
            old = '''    record = ClassificationRecord(
        alert_id=req.alert_id,
        severity=req.severity,
        reasoning=req.reasoning,
        mitre_tactics=req.mitre_tactics,
        recommended_actions=req.recommended_actions
    )'''
            new = '''    record = ClassificationRecord(
        alert_id=req.alert_id,
        severity=req.severity,
        reasoning=req.reasoning,
        mitre_tactics=req.mitre_tactics,
        recommended_actions=req.recommended_actions,
        verdict=req.verdict,
        confidence=req.confidence
    )'''
            if old in src:
                src = src.replace(old, new)
            else:
                print("[ERROR] save_classification ClassificationRecord construction not found verbatim.")
                ok = False

            # 4c. get_alerts response includes verdict/confidence
            old = '''        if cls:
            entry["technique"] = cls.mitre_tactics
            entry["reasoning"] = cls.reasoning
            entry["recommended_actions"] = cls.recommended_actions'''
            new = '''        if cls:
            entry["technique"] = cls.mitre_tactics
            entry["reasoning"] = cls.reasoning
            entry["recommended_actions"] = cls.recommended_actions
            entry["verdict"] = cls.verdict
            entry["confidence"] = cls.confidence'''
            if old in src:
                src = src.replace(old, new)
            else:
                print("[ERROR] get_alerts entry block not found verbatim.")
                ok = False

            # 4d. _classify_and_store extracts and stores verdict/confidence
            old = '''        mitre_technique = ""
        for line in classification_text.split("\\n"):
            if line.strip().upper().startswith("[TECHNIQUE]"):
                mitre_technique = line.split("]", 1)[-1].strip()
                break
        import re as _re
        m = _re.search(r"\\[REASONING\\]\\s*([\\s\\S]+?)(?=\\[RECOMMENDED|$)", classification_text, _re.IGNORECASE)
        reasoning_text = m.group(1).strip() if m else ""
        recommended_actions = ""
        if "[RECOMMENDED ACTIONS]" in classification_text.upper():
            idx = classification_text.upper().find("[RECOMMENDED ACTIONS]")
            recommended_actions = classification_text[idx + len("[RECOMMENDED ACTIONS]"):].strip()'''
            new = '''        mitre_technique = ""
        for line in classification_text.split("\\n"):
            if line.strip().upper().startswith("[TECHNIQUE]"):
                mitre_technique = line.split("]", 1)[-1].strip()
                break
        import re as _re
        m = _re.search(r"\\[REASONING\\]\\s*([\\s\\S]+?)(?=\\[RECOMMENDED|$)", classification_text, _re.IGNORECASE)
        reasoning_text = m.group(1).strip() if m else ""
        recommended_actions = ""
        if "[RECOMMENDED ACTIONS]" in classification_text.upper():
            idx = classification_text.upper().find("[RECOMMENDED ACTIONS]")
            recommended_actions = classification_text[idx + len("[RECOMMENDED ACTIONS]"):].strip()
        verdict_m = _re.search(r"\\[VERDICT\\]\\s*([^\\n]+)", classification_text, _re.IGNORECASE)
        confidence_m = _re.search(r"\\[CONFIDENCE\\]\\s*(\\w+)", classification_text, _re.IGNORECASE)
        verdict = verdict_m.group(1).strip().upper() if verdict_m else "NEEDS INVESTIGATION"
        confidence = confidence_m.group(1).strip().upper() if confidence_m else "LOW"'''
            if old in src:
                src = src.replace(old, new)
            else:
                print("[ERROR] _classify_and_store parsing block not found verbatim.")
                ok = False

            # 4e. _classify_and_store's ClassificationRecord construction stores them
            old = '''        cls_record = ClassificationRecord(
            alert_id=alert_id,
            severity=sev,
            reasoning=classification_text,
            mitre_tactics=mitre_technique,
            recommended_actions=recommended_actions
        )'''
            new = '''        cls_record = ClassificationRecord(
            alert_id=alert_id,
            severity=sev,
            reasoning=classification_text,
            mitre_tactics=mitre_technique,
            recommended_actions=recommended_actions,
            verdict=verdict,
            confidence=confidence
        )'''
            if old in src:
                src = src.replace(old, new)
            else:
                print("[ERROR] _classify_and_store ClassificationRecord construction not found verbatim.")
                ok = False

            if ok:
                main_path.write_text(src)
                print(f"[OK] backend/main.py patched (4 edits). Backup at {backup}")
            else:
                print("[ABORTED] backend/main.py had at least one mismatch — restoring original, no partial edits kept.")
                shutil.copy(backup, main_path)

    print("\nDone. Next: run the DB migration SQL if you haven't, restart the backend, and apply the frontend patch.")


if __name__ == "__main__":
    main()
