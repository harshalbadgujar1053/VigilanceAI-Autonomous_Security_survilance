"""
generate_report.py — Tool 5 for Vigilance AI ReAct Agent
---------------------------------------------------------
Project: Vigilance AI

Generates a structured SOC incident report from the findings
gathered by the other 4 tools. This is always the LAST tool
the agent calls — it synthesizes everything into a final report.

Classifier: Google Gemini API (gemini-3.5-flash-lite) — same model
used for alert classification, for consistency and speed. No local
Ollama fallback (removed from this environment); if Gemini is
unavailable, a static structured report is returned instead so the
analyst still gets something usable.
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from langchain.tools import tool
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.5-flash-lite")
GEMINI_TIMEOUT_SECONDS = 30

VALID_VERDICTS = {"TRUE POSITIVE", "FALSE POSITIVE", "NEEDS INVESTIGATION"}
VALID_CONFIDENCE = {"HIGH", "MEDIUM", "LOW"}


# ─────────────────────────────────────────────
# 1. REPORT PROMPT
#    NOTE: {timestamp} is filled in at call time now (previously this
#    was baked in at module import time via .replace(), which meant
#    every report generated in a long-running process showed the same
#    stale timestamp — fixed here).
#
#    NOTE: {verdict}/{confidence} are injected directly from the
#    classifications table (same approach used for {top_technique} in
#    classify_with_rag.py) rather than left for Gemini to infer. This
#    avoids the same mismatch bug fixed for [TECHNIQUE]/[REASONING] —
#    the report must never disagree with the badge already shown in
#    AlertCard.tsx.
# ─────────────────────────────────────────────
REPORT_PROMPT_TEMPLATE = """You are a senior SOC analyst writing a formal incident report.

Based on the following investigation findings, write a complete,
structured incident report:

FINDINGS:
{findings}

The AI triage verdict and confidence below have ALREADY been determined
by the classification pipeline and are final. You MUST reproduce these
two values verbatim in the INCIDENT CLASSIFICATION section below, and
your Executive Summary and Analyst Notes must be consistent with them
(do not contradict, soften, or re-derive a different verdict):

VERDICT: {verdict}
CONFIDENCE: {confidence}

Write the report in this EXACT format:

================================================
VIGILANCE AI — INCIDENT REPORT
Generated: {timestamp}
================================================

EXECUTIVE SUMMARY:
<2-3 sentences summarizing what happened, severity, and impact>

INCIDENT CLASSIFICATION:
- Severity: <CRITICAL | HIGH | MEDIUM | LOW>
- Category: <Attack type e.g. Brute Force, Rootkit, etc.>
- Status: <Active Threat | Contained | Under Investigation>
- AI Verdict: {verdict}
- AI Confidence: {confidence}

AFFECTED SYSTEMS:
- <host name and IP>

ATTACK DETAILS:
- <key finding 1 from the investigation>
- <key finding 2>
- <key finding 3>

MITRE ATT&CK MAPPING:
- <technique ID and name>
- <tactic category>

CVE REFERENCES (if applicable):
- <CVE ID and severity, or "None identified">

RECOMMENDED ACTIONS:
1. <Immediate action — do within 1 hour>
2. <Short term — do within 24 hours>
3. <Long term — do within 1 week>

ANALYST NOTES:
<Any additional context or observations, consistent with the verdict above>
================================================
Write real, specific content only — do not leave any angle-bracket
placeholders in your output.
"""


# ─────────────────────────────────────────────
# 2. GEMINI CALL
# ─────────────────────────────────────────────
def _generate_via_gemini(findings: str, verdict: str, confidence: str) -> str:
    import google.generativeai as genai

    if not GEMINI_API_KEY:
        raise RuntimeError("GEMINI_API_KEY not set")

    genai.configure(api_key=GEMINI_API_KEY)
    model = genai.GenerativeModel(GEMINI_MODEL)

    prompt_text = REPORT_PROMPT_TEMPLATE.format(
        findings=findings,
        verdict=verdict,
        confidence=confidence,
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )

    response = model.generate_content(
        prompt_text,
        generation_config=genai.types.GenerationConfig(
            temperature=0,
            max_output_tokens=1200
        ),
        request_options={"timeout": GEMINI_TIMEOUT_SECONDS}
    )

    text = response.text.strip()
    if not text:
        raise RuntimeError("Gemini returned empty response")
    return text


# ─────────────────────────────────────────────
# 3. THE TOOL
# ─────────────────────────────────────────────
@tool
def generate_report(findings: str, verdict: str = "NEEDS INVESTIGATION", confidence: str = "MEDIUM") -> str:
    """
    Generate a structured SOC incident report from investigation findings.
    This tool should be called LAST, after all other tools have gathered
    information about the alert.

    Use this tool when you have:
    - Identified the alert details (from query_siem)
    - Mapped to MITRE techniques (from map_to_mitre or lookup_threat_intel)
    - Checked CVE severity if applicable (from check_cve)
    - Determined the AI verdict and confidence (from the classification step)
    - Gathered enough context to write a complete report

    Args:
        findings: A summary of all investigation findings gathered
                  from the other tools. Include alert details,
                  MITRE technique mappings, CVE info, and any
                  other relevant context.
                  Example: "Alert 1717000001: 847 failed SSH attempts
                  from 185.220.101.47 to web-server-prod. MITRE mapping:
                  T1110 Brute Force (High confidence). No CVE identified."
        verdict: The AI triage verdict already produced for this alert.
                 One of: TRUE POSITIVE, FALSE POSITIVE, NEEDS INVESTIGATION.
        confidence: The AI triage confidence already produced for this
                    alert. One of: HIGH, MEDIUM, LOW.

    Returns:
        A complete, structured incident report ready for SOC analyst review.
    """
    verdict = (verdict or "").strip().upper()
    confidence = (confidence or "").strip().upper()

    if verdict not in VALID_VERDICTS:
        verdict = "NEEDS INVESTIGATION"
    if confidence not in VALID_CONFIDENCE:
        confidence = "MEDIUM"

    try:
        return _generate_via_gemini(findings, verdict, confidence)

    except Exception as e:
        # Fallback: structured report without LLM (Gemini unreachable,
        # rate-limited, or misconfigured). No local Ollama fallback —
        # removed from this environment. Verdict/confidence are still
        # included since they come from the pipeline, not the LLM call.
        return f"""================================================
VIGILANCE AI — INCIDENT REPORT
Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
================================================

NOTE: LLM unavailable ({e}) — basic report generated.

AI VERDICT: {verdict}
AI CONFIDENCE: {confidence}

FINDINGS SUMMARY:
{findings}

RECOMMENDED ACTION:
Investigate immediately and escalate to senior analyst.
================================================"""


# ─────────────────────────────────────────────
# 4. TEST
# ─────────────────────────────────────────────
if __name__ == "__main__":
    print("Testing generate_report tool...")
    print("(This calls Gemini — should take a few seconds)\n")

    test_findings = """
    Alert ID: 1717000001
    Alert: Multiple failed SSH login attempts (847 in 60 seconds)
    Source IP: 185.220.101.47 (external)
    Target: web-server-prod (10.0.1.45)
    Wazuh Rule Level: 10/15

    MITRE Mapping: T1110 - Brute Force (High confidence)
    Secondary: T1021.004 - SSH (related technique)

    CVE: No specific CVE identified for this attack pattern.

    Additional context: Source IP is a known Tor exit node.
    No successful logins detected in the same timeframe.
    """

    report = generate_report.invoke({
        "findings": test_findings,
        "verdict": "TRUE POSITIVE",
        "confidence": "HIGH"
    })
    print(report)
