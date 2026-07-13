"""
classify_alert.py — Phase 2: FastAPI-ready structured classification
----------------------------------------------------------------------
Project: Vigilance AI

Takes a Wazuh-style alert dict, sends it to local Mistral via Ollama,
and returns a structured dict: {severity, technique, reasoning, rawText}
ready to be JSON-serialized directly by FastAPI's /classify route.

How it works:
  alert JSON  →  PromptTemplate  →  Mistral (Ollama)  →  parse_llm_output()  →  dict

Run standalone for testing:
    python classify_alert.py

Prerequisites (already verified on this machine):
    pip install langchain langchain-ollama
    ollama pull mistral
    ollama serve   (runs automatically as a systemd service on Kali)

NOTE: Uses langchain_ollama.OllamaLLM, NOT the deprecated
langchain_community.llms.Ollama (that class is removed in LangChain 1.0).
"""

import json
import re
from langchain_ollama import OllamaLLM
from langchain_core.prompts import PromptTemplate
from langchain_core.output_parsers import StrOutputParser

from agent.alert_schema import SAMPLE_ALERTS


# ─────────────────────────────────────────────
# 1. PROMPT TEMPLATE
#    Output format uses square brackets ([SEVERITY], [TECHNIQUE],
#    [REASONING]) because the React frontend's parseResult() in
#    AlertCard.tsx regex-matches on that exact bracket format as
#    a fallback when the JSON body isn't clean.
# ─────────────────────────────────────────────
CLASSIFICATION_PROMPT = PromptTemplate(
    input_variables=["alert_json"],
    template="""You are a cybersecurity analyst for a SOC (Security Operations Center).

Analyze the following security alert. Classify its severity and map it to the
single most relevant MITRE ATT&CK technique.

ALERT:
{alert_json}

Respond in this EXACT format (no extra text before or after):

[SEVERITY] <CRITICAL | HIGH | MEDIUM | LOW>

[TECHNIQUE] <MITRE ID and name, e.g. "T1110 - Brute Force">

[REASONING]
- <bullet point 1: what triggered this alert>
- <bullet point 2: why this severity level>
- <bullet point 3: key indicators of compromise>
"""
)


# ─────────────────────────────────────────────
# 2. LLM SETUP
# ─────────────────────────────────────────────
def build_chain():
    """
    Constructs the LCEL chain:
        prompt_template | llm | output_parser
    """
    llm = OllamaLLM(
        model="mistral",
        temperature=0,          # 0 = deterministic; good for consistent parsing
        base_url="http://localhost:11434"   # default Ollama port
    )
    output_parser = StrOutputParser()

    chain = CLASSIFICATION_PROMPT | llm | output_parser
    return chain


# ─────────────────────────────────────────────
# 3. OUTPUT PARSER
#    Converts Mistral's raw bracket-formatted text into the
#    dict shape the frontend's Classification type expects:
#      { severity, technique, reasoning: string[], rawText }
# ─────────────────────────────────────────────
def parse_llm_output(raw_text: str, fallback_level: int = 0) -> dict:
    """
    Parses Mistral's raw text output into a structured dict.

    Args:
        raw_text: str — the raw string returned by the LLM chain
        fallback_level: int — the alert's rule.level, used only if
                        SEVERITY can't be parsed out of the text

    Returns:
        dict — {severity, technique, reasoning, rawText}
    """
    severity_match = re.search(r"\[SEVERITY\]\s*(\w+)", raw_text, re.IGNORECASE)
    technique_match = re.search(r"\[TECHNIQUE\]\s*([^\n]+)", raw_text, re.IGNORECASE)
    reasoning_match = re.search(r"\[REASONING\]\s*([\s\S]+)", raw_text, re.IGNORECASE)

    if severity_match:
        severity = severity_match.group(1).upper()
    else:
        # Fallback severity derived from Wazuh rule level, matching the
        # same thresholds used in App.tsx / SOCCharts.tsx on the frontend
        if fallback_level >= 12:
            severity = "CRITICAL"
        elif fallback_level >= 8:
            severity = "HIGH"
        elif fallback_level >= 4:
            severity = "MEDIUM"
        else:
            severity = "LOW"

    technique = technique_match.group(1).strip() if technique_match else "T1543 - Create or Modify System Process"

    reasoning = []
    if reasoning_match:
        for line in reasoning_match.group(1).splitlines():
            cleaned = re.sub(r"^\s*-\s*", "", line).strip()
            if cleaned:
                reasoning.append(cleaned)

    if not reasoning:
        reasoning = ["Anomalous host event detected requiring automated SOC triage."]

    return {
        "severity": severity,
        "technique": technique,
        "reasoning": reasoning,
        "rawText": raw_text
    }


# ─────────────────────────────────────────────
# 4. PUBLIC ENTRY POINT — call this from FastAPI's /classify route
# ─────────────────────────────────────────────
def classify_alert(alert: dict) -> dict:
    """
    Takes a Wazuh alert dict, runs it through the classification
    chain, and returns a structured dict ready for JSON response.

    Args:
        alert: dict — a Wazuh-style alert JSON object.
               Expected to have alert["rule"]["level"] for fallback
               severity derivation if the LLM output can't be parsed.

    Returns:
        dict — {severity, technique, reasoning, rawText}
    """
    chain = build_chain()
    alert_json_str = json.dumps(alert, indent=2)

    print("─" * 60)
    print("INPUT ALERT:")
    print(alert_json_str)
    print("─" * 60)
    print("RUNNING CLASSIFICATION... (CPU-only mode, may take 30-90s)\n")

    raw_output = chain.invoke({"alert_json": alert_json_str})

    fallback_level = alert.get("rule", {}).get("level", 0)
    parsed = parse_llm_output(raw_output, fallback_level=fallback_level)

    print("PARSED CLASSIFICATION:")
    print("─" * 60)
    print(json.dumps(parsed, indent=2))
    print("─" * 60)

    return parsed


# ─────────────────────────────────────────────
# 5. STANDALONE TEST ENTRY POINT
# ─────────────────────────────────────────────
if __name__ == "__main__":
    alert_to_test = SAMPLE_ALERTS["low_disk"]
    result = classify_alert(alert_to_test)
    print("\nFINAL DICT RETURNED TO CALLER:")
    print(json.dumps(result, indent=2))
