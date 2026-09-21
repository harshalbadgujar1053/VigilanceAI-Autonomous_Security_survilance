"""
apply_verdict_feature_frontend.py — Frontend half of the TP/FP verdict feature.

Patches:
  1. frontend/src/types.ts             — Classification interface gains verdict/confidence
  2. frontend/src/api/vigilanceApi.ts  — fetchSiemAlerts passes verdict/confidence through
  3. frontend/src/components/AlertCard.tsx — parses, auto-populates, saves, and displays
                                             verdict/confidence as a badge next to severity

Run from repo root: python3 apply_verdict_feature_frontend.py
Idempotent — checks for markers before patching, aborts cleanly on mismatch,
never leaves a partially-edited file.
"""
import shutil
from pathlib import Path


def patch_file(path: Path, replacements: list, marker: str, label: str) -> bool:
    if not path.exists():
        print(f"[SKIP] {path} not found.")
        return False
    src = path.read_text()
    if marker in src:
        print(f"[SKIP] {label}: already applied (marker found).")
        return True
    backup = path.with_suffix(path.suffix + ".bak")
    shutil.copy(path, backup)
    working = src
    for old, new in replacements:
        if old not in working:
            print(f"[ERROR] {label}: expected text not found verbatim. No changes written.")
            print(f"        Missing snippet starts with: {old[:70]!r}")
            return False
        working = working.replace(old, new)
    path.write_text(working)
    print(f"[OK] {label} patched. Backup at {backup}")
    return True


def main():
    # ── 1. types.ts ──
    patch_file(
        Path("frontend/src/types.ts"),
        [(
            '''export interface Classification {
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  technique: string;
  reasoning: string[];
  recommendedActions?: string[];
  rawText?: string;
}''',
            '''export interface Classification {
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  technique: string;
  reasoning: string[];
  recommendedActions?: string[];
  verdict?: 'TRUE POSITIVE' | 'FALSE POSITIVE' | 'NEEDS INVESTIGATION';
  confidence?: 'HIGH' | 'MEDIUM' | 'LOW';
  rawText?: string;
}'''
        )],
        marker="verdict?: 'TRUE POSITIVE'",
        label="types.ts Classification interface"
    )

    # ── 2. vigilanceApi.ts: fetchSiemAlerts passes fields through ──
    patch_file(
        Path("frontend/src/api/vigilanceApi.ts"),
        [(
            '''      technique: a.technique,
      reasoning: a.reasoning,
      recommended_actions: a.recommended_actions,
      _source: 'live\'''',
            '''      technique: a.technique,
      reasoning: a.reasoning,
      recommended_actions: a.recommended_actions,
      verdict: a.verdict,
      confidence: a.confidence,
      _source: 'live\''''
        )],
        marker="verdict: a.verdict,",
        label="fetchSiemAlerts (verdict/confidence pass-through)"
    )

    # ── 2b. saveClassificationToDB payload type + handleClassify call site ──
    patch_file(
        Path("frontend/src/api/vigilanceApi.ts"),
        [(
            '''export const saveClassificationToDB = async (payload: { alert_id: string; severity: string; reasoning: string; mitre_tactics: string; recommended_actions?: string }) => {''',
            '''export const saveClassificationToDB = async (payload: { alert_id: string; severity: string; reasoning: string; mitre_tactics: string; recommended_actions?: string; verdict?: string; confidence?: string }) => {'''
        ), (
            '''  saveClassificationToDB({
    alert_id: alert.id,
    severity: classification.severity,
    reasoning: classification.reasoning.join(' | '),
    mitre_tactics: classification.technique,
    recommended_actions: (classification.recommendedActions ?? []).join(' | ')
  }).catch(err => console.warn('DB save classification failed:', err));'''.replace('    ', '  '),
            '''  saveClassificationToDB({
    alert_id: alert.id,
    severity: classification.severity,
    reasoning: classification.reasoning.join(' | '),
    mitre_tactics: classification.technique,
    recommended_actions: (classification.recommendedActions ?? []).join(' | '),
    verdict: classification.verdict,
    confidence: classification.confidence
  }).catch(err => console.warn('DB save classification failed:', err));'''.replace('    ', '  ')
        )],
        marker="verdict: classification.verdict,",
        label="saveClassificationToDB signature + call site"
    )

    # ── 3. AlertCard.tsx ──
    ac = Path("frontend/src/components/AlertCard.tsx")
    if not ac.exists():
        print("[SKIP] AlertCard.tsx not found.")
        return
    src = ac.read_text()
    if "VERDICT-BADGE-MARKER" in src:
        print("[SKIP] AlertCard.tsx: already applied (marker found).")
        return
    backup = ac.with_suffix(".tsx.bak")
    shutil.copy(ac, backup)
    working = src
    ok = True

    # 3a. useEffect auto-populate from alert.verdict/alert.confidence
    old = '''      setResult({
        severity: alert.severity as any,
        technique: alert.technique || (alert.rule.groups.length > 0 ? alert.rule.groups[0].toUpperCase() : 'T1543 - THREAT BEHAVIOR'),
        reasoning: reasoningLines,
        recommendedActions: recommendedActionsLines
      });
      setStatus('done');'''
    new = '''      setResult({
        severity: alert.severity as any,
        technique: alert.technique || (alert.rule.groups.length > 0 ? alert.rule.groups[0].toUpperCase() : 'T1543 - THREAT BEHAVIOR'),
        reasoning: reasoningLines,
        recommendedActions: recommendedActionsLines,
        verdict: (alert as any).verdict || 'NEEDS INVESTIGATION',
        confidence: (alert as any).confidence || 'LOW'
      });
      setStatus('done');'''
    if old in working:
        working = working.replace(old, new)
    else:
        print("[ERROR] useEffect auto-populate block not found verbatim.")
        ok = False

    # 3b. parseResult: extract verdict/confidence from raw text, same style as severity/technique
    old = '''    return {
      severity: (severityMatch ? severityMatch[1].toUpperCase() : (alert.rule.level >= 12 ? 'CRITICAL' : alert.rule.level >= 8 ? 'HIGH' : alert.rule.level >= 4 ? 'MEDIUM' : 'LOW')) as any,
      technique: techniqueMatch ? techniqueMatch[1].trim() : 'T1543 - Threat Behavior',
      reasoning: reasoningLines.length > 0 ? reasoningLines : ['Anomalous host event detected requiring automated SOC triage.'],
      recommendedActions: recommendedActionsLines.length > 0 ? recommendedActionsLines : ['No specific recommended actions provided.']
    };'''
    new = '''    const verdictMatch = text.match(/\\[VERDICT\\]\\s*([^\\n\\[]+)/i);
    const confidenceMatch = text.match(/\\[CONFIDENCE\\]\\s*(\\w+)/i);

    return {
      severity: (severityMatch ? severityMatch[1].toUpperCase() : (alert.rule.level >= 12 ? 'CRITICAL' : alert.rule.level >= 8 ? 'HIGH' : alert.rule.level >= 4 ? 'MEDIUM' : 'LOW')) as any,
      technique: techniqueMatch ? techniqueMatch[1].trim() : 'T1543 - Threat Behavior',
      reasoning: reasoningLines.length > 0 ? reasoningLines : ['Anomalous host event detected requiring automated SOC triage.'],
      recommendedActions: recommendedActionsLines.length > 0 ? recommendedActionsLines : ['No specific recommended actions provided.'],
      verdict: (verdictMatch ? verdictMatch[1].trim().toUpperCase() : 'NEEDS INVESTIGATION') as any,
      confidence: (confidenceMatch ? confidenceMatch[1].trim().toUpperCase() : 'LOW') as any
    };'''
    if old in working:
        working = working.replace(old, new)
    else:
        print("[ERROR] parseResult return block not found verbatim.")
        ok = False

    # 3c. handleClassify save call includes verdict/confidence
    old = '''        await saveClassificationToDB({
  alert_id: alert.id,
  severity: parsed.severity,
  reasoning: parsed.reasoning.join(' | '),
  mitre_tactics: parsed.technique,
  recommended_actions: (parsed.recommendedActions ?? []).join(' | ')
});'''
    new = '''        await saveClassificationToDB({
  alert_id: alert.id,
  severity: parsed.severity,
  reasoning: parsed.reasoning.join(' | '),
  mitre_tactics: parsed.technique,
  recommended_actions: (parsed.recommendedActions ?? []).join(' | '),
  verdict: parsed.verdict,
  confidence: parsed.confidence
});'''
    if old in working:
        working = working.replace(old, new)
    else:
        print("[ERROR] handleClassify saveClassificationToDB call not found verbatim.")
        ok = False

    # 3d. JSX display — badge next to the existing severity badge in CLASSIFICATION section
    old = '''                    REASONING'''
    new = '''                    {/* VERDICT-BADGE-MARKER */}
                    REASONING'''
    if old in working:
        # Only patch the marker in; the visible verdict badge itself is added
        # next to severity below. This comment just marks the file as patched.
        pass

    old_severity_badge = '''              <h4>Case Creation Report</h4>'''
    # Leave Case Creation Report untouched; instead add badge near CLASSIFICATION header.
    # Find the CLASSIFICATION header block with severity badge (result.severity display).
    old_class_header = '''                    REASONING
                  </h5>'''
    # Fallback: insert a verdict/confidence line right before REASONING heading block
    # using a safer, more general anchor: the reasoning .map header section.
    marker_anchor = '''{result.reasoning.map((item, idx) => ('''
    if marker_anchor in working and "VERDICT-BADGE-MARKER" not in working:
        badge_block = '''{/* VERDICT-BADGE-MARKER */}
                {result.verdict && (
                  <div className="verdict-badge-row" style={{ display: 'flex', gap: '8px', alignItems: 'center', margin: '8px 0' }}>
                    <span
                      className={`verdict-badge ${result.verdict === 'TRUE POSITIVE' ? 'verdict-tp' : result.verdict === 'FALSE POSITIVE' ? 'verdict-fp' : 'verdict-investigate'}`}
                      style={{
                        padding: '4px 10px',
                        borderRadius: '6px',
                        fontSize: '12px',
                        fontWeight: 600,
                        background: result.verdict === 'TRUE POSITIVE' ? '#fee2e2' : result.verdict === 'FALSE POSITIVE' ? '#dcfce7' : '#fef9c3',
                        color: result.verdict === 'TRUE POSITIVE' ? '#991b1b' : result.verdict === 'FALSE POSITIVE' ? '#166534' : '#854d0e'
                      }}
                    >
                      {result.verdict}
                    </span>
                    {result.confidence && (
                      <span style={{ fontSize: '12px', color: '#6b7280' }}>
                        Confidence: {result.confidence}
                      </span>
                    )}
                  </div>
                )}
                '''
        working = working.replace(
            marker_anchor,
            badge_block + marker_anchor,
            1  # only the first occurrence (the main classification display, not the compact one if it exists)
        )
    else:
        print("[ERROR] JSX anchor for verdict badge not found, or already patched oddly.")
        ok = False

    if ok:
        ac.write_text(working)
        print(f"[OK] AlertCard.tsx patched (4 edits). Backup at {backup}")
    else:
        print("[ABORTED] AlertCard.tsx had at least one mismatch — restoring original.")
        shutil.copy(backup, ac)

    print("\nDone. Rebuild/restart the frontend (npm run dev picks up changes automatically if already running).")


if __name__ == "__main__":
    main()
