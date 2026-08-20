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


# ─────────────────────────────────────────────
# 1. REPORT PROMPT
#    NOTE: {timestamp} is filled in at call time now (previously this
#    was baked in at module import time via .replace(), which meant
#    every report generated in a long-running process showed the same
#    stale timestamp — fixed here).
# ─────────────────────────────────────────────
REPORT_PROMPT_TEMPLATE = """You are a senior SOC analyst writing a formal incident report.

Based on the following investigation findings, write a complete,
structured incident report:

FINDINGS:
{findings}

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
<Any additional context or observations>
================================================
Write real, specific content only — do not leave any angle-bracket
placeholders in your output.
"""


# ─────────────────────────────────────────────
# 2. GEMINI CALL
# ─────────────────────────────────────────────
def _generate_via_gemini(findings: str) -> str:
    import google.generativeai as genai

    if not GEMINI_API_KEY:
        raise RuntimeError("GEMINI_API_KEY not set")

    genai.configure(api_key=GEMINI_API_KEY)
    model = genai.GenerativeModel(GEMINI_MODEL)

    prompt_text = REPORT_PROMPT_TEMPLATE.format(
        findings=findings,
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
def generate_report(findings: str) -> str:
    """
    Generate a structured SOC incident report from investigation findings.
    This tool should be called LAST, after all other tools have gathered
    information about the alert.

    Use this tool when you have:
    - Identified the alert details (from query_siem)
    - Mapped to MITRE techniques (from map_to_mitre or lookup_threat_intel)
    - Checked CVE severity if applicable (from check_cve)
    - Gathered enough context to write a complete report

    Args:
        findings: A summary of all investigation findings gathered
                  from the other tools. Include alert details,
                  MITRE technique mappings, CVE info, and any
                  other relevant context.
                  Example: "Alert 1717000001: 847 failed SSH attempts
                  from 185.220.101.47 to web-server-prod. MITRE mapping:
                  T1110 Brute Force (High confidence). No CVE identified."

    Returns:
        A complete, structured incident report ready for SOC analyst review.
    """
    try:
        return _generate_via_gemini(findings)

    except Exception as e:
        # Fallback: structured report without LLM (Gemini unreachable,
        # rate-limited, or misconfigured). No local Ollama fallback —
        # removed from this environment.
        return f"""================================================
VIGILANCE AI — INCIDENT REPORT
Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
================================================

NOTE: LLM unavailable ({e}) — basic report generated.

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

    report = generate_report.invoke(test_findings)
    print(report)
