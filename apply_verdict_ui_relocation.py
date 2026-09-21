"""
apply_final_ui_fixes.py

1. backend/main.py — _classify_and_store now splits [REASONING] and
   [RECOMMENDED ACTIONS] into individual bullet lines (pipe-joined),
   matching what the frontend's split('|') expects. Fixes the
   single-run-on-paragraph display bug for auto-classified alerts.

2. frontend/src/components/AlertCard.tsx — bumps font size by ~2px on
   the top meta row (host/ip/rule-id/alert-id/LIVE/severity/Level) and
   on the verdict/confidence badge.

3. frontend/src/components/SOCCharts.tsx — adds a "Wazuh ID" (rule ID)
   column to the Security Event Logs table, and increases table font
   size + row padding to use more of the available space.

Run from repo root: python3 apply_final_ui_fixes.py
Idempotent, aborts cleanly per-file on mismatch, keeps .bak backups.
"""
import shutil
from pathlib import Path


def patch(path_str, edits, marker, label):
    path = Path(path_str)
    if not path.exists():
        print(f"[SKIP] {path} not found.")
        return
    src = path.read_text()
    if marker in src:
        print(f"[SKIP] {label}: already applied.")
        return
    backup = path.with_suffix(path.suffix + ".bak4")
    shutil.copy(path, backup)
    working = src
    for old, new in edits:
        if old not in working:
            print(f"[ERROR] {label}: snippet not found verbatim, aborting this file (no changes written).")
            print(f"        Missing: {old[:90]!r}")
            return
        working = working.replace(old, new, 1)
    path.write_text(working)
    print(f"[OK] {label} patched. Backup at {backup}")


# ── 1. backend/main.py: bullet-split reasoning/recommended_actions ──
backend_edits = [
    (
        '''        import re as _re
        m = _re.search(r"\\[REASONING\\]\\s*([\\s\\S]+?)(?=\\[RECOMMENDED|$)", classification_text, _re.IGNORECASE)
        reasoning_text = m.group(1).strip() if m else ""

        recommended_actions = ""
        if "[RECOMMENDED ACTIONS]" in classification_text.upper():
            idx = classification_text.upper().find("[RECOMMENDED ACTIONS]")
            recommended_actions = classification_text[idx + len("[RECOMMENDED ACTIONS]"):].strip()

        record_to_update = db.query(AlertRecord).filter(AlertRecord.id == alert_id).first()
        cls_record = ClassificationRecord(
            alert_id=alert_id,
            severity=sev,
            reasoning=classification_text,
            mitre_tactics=mitre_technique,
            recommended_actions=recommended_actions,
            verdict=verdict,
            confidence=confidence
        )''',
        '''        import re as _re
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
        )'''
    )
]
patch("backend/main.py", backend_edits, marker="PATCHED: split into individual bullet lines", label="backend/main.py (bullet-line fix)")


# ── 2. AlertCard.tsx: font size increases ──
ac_edits = [
    (
        '''          <div className="alert-meta-grid" style={{ marginTop: '8px' }}>''',
        '''          <div className="alert-meta-grid" style={{ marginTop: '8px', fontSize: '13px' }}>'''
    ),
    (
        '''            {alert._source === 'live' && (
              <span className="meta-tag" style={{ background: 'rgba(16, 185, 129, 0.1)', color: '#10B981', border: '1px solid rgba(16, 185, 129, 0.2)', fontWeight: 700, fontSize: '10px' }}>
                LIVE
              </span>
            )}
            {alert.severity && alert.severity !== 'UNKNOWN' && alert.severity !== 'PENDING' && (
              <span className="meta-tag" style={{ background: 'rgba(56, 189, 248, 0.1)', color: '#0EA5E9', border: '1px solid rgba(56, 189, 248, 0.2)', fontWeight: 700, fontSize: '10px' }}>
                {alert.severity}
              </span>
            )}''',
        '''            {alert._source === 'live' && (
              <span className="meta-tag" style={{ background: 'rgba(16, 185, 129, 0.1)', color: '#10B981', border: '1px solid rgba(16, 185, 129, 0.2)', fontWeight: 700, fontSize: '12px' }}>
                LIVE
              </span>
            )}
            {alert.severity && alert.severity !== 'UNKNOWN' && alert.severity !== 'PENDING' && (
              <span className="meta-tag" style={{ background: 'rgba(56, 189, 248, 0.1)', color: '#0EA5E9', border: '1px solid rgba(56, 189, 248, 0.2)', fontWeight: 700, fontSize: '12px' }}>
                {alert.severity}
              </span>
            )}'''
    ),
    (
        '''            <span className={`severity-badge ${severityCategory}`}>
              <span className="sev-dot" />
              Level {level}/15
            </span>''',
        '''            <span className={`severity-badge ${severityCategory}`} style={{ fontSize: '13px' }}>
              <span className="sev-dot" />
              Level {level}/15
            </span>'''
    ),
    (
        '''                    style={{
                      padding: '3px 9px',
                      borderRadius: '6px',
                      fontSize: '10px',
                      fontWeight: 700,
                      textTransform: 'uppercase',
                      letterSpacing: '0.03em',
                      background: result.verdict === 'TRUE POSITIVE' ? '#fee2e2' : result.verdict === 'FALSE POSITIVE' ? '#dcfce7' : '#fef9c3',
                      color: result.verdict === 'TRUE POSITIVE' ? '#991b1b' : result.verdict === 'FALSE POSITIVE' ? '#166534' : '#854d0e'
                    }}
                  >
                    {result.verdict}
                  </span>
                  {result.confidence && (
                    <span style={{ fontSize: '10px', color: '#6b7280', fontWeight: 600 }}>
                      {result.confidence}
                    </span>
                  )}''',
        '''                    style={{
                      padding: '3px 9px',
                      borderRadius: '6px',
                      fontSize: '12px',
                      fontWeight: 700,
                      textTransform: 'uppercase',
                      letterSpacing: '0.03em',
                      background: result.verdict === 'TRUE POSITIVE' ? '#fee2e2' : result.verdict === 'FALSE POSITIVE' ? '#dcfce7' : '#fef9c3',
                      color: result.verdict === 'TRUE POSITIVE' ? '#991b1b' : result.verdict === 'FALSE POSITIVE' ? '#166534' : '#854d0e'
                    }}
                  >
                    {result.verdict}
                  </span>
                  {result.confidence && (
                    <span style={{ fontSize: '12px', color: '#6b7280', fontWeight: 600 }}>
                      {result.confidence}
                    </span>
                  )}'''
    )
]
patch("frontend/src/components/AlertCard.tsx", ac_edits, marker="fontSize: '13px' }}>", label="AlertCard.tsx (font size increases)")


# ── 3. SOCCharts.tsx: Wazuh Rule ID column + larger rows ──
soc_edits = [
    (
        '''          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px', textAlign: 'left' }}>
            <thead>
              <tr style={{ borderBottom: '2px solid #E2E8F0', paddingBottom: '8px' }}>
                <th style={{ padding: '10px 12px', fontWeight: '600', color: '#64748B' }}>Severity</th>
                <th style={{ padding: '10px 12px', fontWeight: '600', color: '#64748B' }}>Trigger Rule / Description</th>
                <th style={{ padding: '10px 12px', fontWeight: '600', color: '#64748B' }}>Host Agent</th>
                <th style={{ padding: '10px 12px', fontWeight: '600', color: '#64748B' }}>Log File Location</th>
                <th style={{ padding: '10px 12px', fontWeight: '600', color: '#64748B', textAlign: 'right' }}>Timestamp</th>
              </tr>
            </thead>''',
        '''          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '14px', textAlign: 'left' }}>
            <thead>
              <tr style={{ borderBottom: '2px solid #E2E8F0', paddingBottom: '8px' }}>
                <th style={{ padding: '14px 14px', fontWeight: '600', color: '#64748B' }}>Severity</th>
                <th style={{ padding: '14px 14px', fontWeight: '600', color: '#64748B' }}>Wazuh ID</th>
                <th style={{ padding: '14px 14px', fontWeight: '600', color: '#64748B' }}>Trigger Rule / Description</th>
                <th style={{ padding: '14px 14px', fontWeight: '600', color: '#64748B' }}>Host Agent</th>
                <th style={{ padding: '14px 14px', fontWeight: '600', color: '#64748B' }}>Log File Location</th>
                <th style={{ padding: '14px 14px', fontWeight: '600', color: '#64748B', textAlign: 'right' }}>Timestamp</th>
              </tr>
            </thead>'''
    ),
    (
        '''                      <td style={{ padding: '12px', whiteSpace: 'nowrap' }}>
                        <span style={{ 
                          display: 'inline-flex', 
                          alignItems: 'center', 
                          padding: '3px 8px', 
                          borderRadius: '9999px', 
                          fontWeight: '600', 
                          fontSize: '10px',
                          textTransform: 'uppercase',
                          ...badgeStyle 
                        }}>
                          {severityLabel} ({alert.rule.level})
                        </span>
                      </td>
                      <td style={{ padding: '12px' }}>
                        <div style={{ fontWeight: '600', color: '#1E293B', marginBottom: '4px' }}>{alert.rule.description}</div>''',
        '''                      <td style={{ padding: '14px', whiteSpace: 'nowrap' }}>
                        <span style={{ 
                          display: 'inline-flex', 
                          alignItems: 'center', 
                          padding: '4px 9px', 
                          borderRadius: '9999px', 
                          fontWeight: '600', 
                          fontSize: '11px',
                          textTransform: 'uppercase',
                          ...badgeStyle 
                        }}>
                          {severityLabel} ({alert.rule.level})
                        </span>
                      </td>
                      <td style={{ padding: '14px', whiteSpace: 'nowrap', fontFamily: 'monospace', color: '#334155', fontWeight: 600 }}>
                        {alert.rule.id}
                      </td>
                      <td style={{ padding: '14px' }}>
                        <div style={{ fontWeight: '600', color: '#1E293B', marginBottom: '4px' }}>{alert.rule.description}</div>'''
    ),
    (
        '''                      <td style={{ padding: '12px', whiteSpace: 'nowrap' }}>
                        <div style={{ fontWeight: '500', color: '#334155' }}>{alert.agent.name}</div>
                        <div style={{ fontSize: '10px', color: '#94A3B8', fontFamily: 'monospace' }}>{alert.agent.ip}</div>
                      </td>
                      <td style={{ padding: '12px', color: '#475569', fontFamily: 'monospace', fontSize: '11px' }}>
                        {alert.location}
                      </td>
                      <td style={{ padding: '12px', textAlign: 'right', color: '#64748B', whiteSpace: 'nowrap' }}>''',
        '''                      <td style={{ padding: '14px', whiteSpace: 'nowrap' }}>
                        <div style={{ fontWeight: '500', color: '#334155' }}>{alert.agent.name}</div>
                        <div style={{ fontSize: '12px', color: '#94A3B8', fontFamily: 'monospace' }}>{alert.agent.ip}</div>
                      </td>
                      <td style={{ padding: '14px', color: '#475569', fontFamily: 'monospace', fontSize: '13px' }}>
                        {alert.location}
                      </td>
                      <td style={{ padding: '14px', textAlign: 'right', color: '#64748B', whiteSpace: 'nowrap' }}>'''
    ),
    (
        '''                        <td colSpan={5} style={{ padding: 0 }}>''',
        '''                        <td colSpan={6} style={{ padding: 0 }}>'''
    )
]
patch("frontend/src/components/SOCCharts.tsx", soc_edits, marker="Wazuh ID</th>", label="SOCCharts.tsx (Wazuh ID column + larger rows)")

print("\nDone. Restart the backend (uvicorn --reload should auto-restart on file save; if not, restart the tmux session). Frontend should hot-reload via Vite.")
