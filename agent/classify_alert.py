"""
classify_alert.py — Phase 1 toy chain
--------------------------------------
Project: Vigilance AI

Takes a hardcoded Wazuh-style alert JSON, sends it to local Mistral via Ollama,
and returns a structured severity classification (critical/medium/low) + reasoning.

How it works:
  alert JSON  →  PromptTemplate  →  Mistral (Ollama)  →  parsed output

Run:
    python classify_alert.py

Prerequisites (already verified on this machine):
    pip install langchain langchain-ollama
    ollama pull mistral
    ollama serve   (runs automatically as a systemd service on Kali)

NOTE: Uses langchain_ollama.OllamaLLM, NOT the deprecated
langchain_community.llms.Ollama (that class is removed in LangChain 1.0).
"""

import json
from langchain_ollama import OllamaLLM
from langchain_core.prompts import PromptTemplate
from langchain_core.output_parsers import StrOutputParser

from agent.alert_schema import SAMPLE_ALERTS


# ─────────────────────────────────────────────
# 1. PROMPT TEMPLATE
#    {alert_json} is the placeholder — LangChain
#    fills it in at runtime via chain.invoke()
# ─────────────────────────────────────────────
CLASSIFICATION_PROMPT = PromptTemplate(
    input_variables=["alert_json"],
    template="""You are a cybersecurity analyst for a SOC (Security Operations Center).

Analyze the following security alert and classify its severity.

ALERT:
{alert_json}

Respond in this EXACT format (no extra text):

SEVERITY: <CRITICAL | MEDIUM | LOW>

REASONING:
- <bullet point 1: what triggered this alert>
- <bullet point 2: why this severity level>
- <bullet point 3: key indicators of compromise>

RECOMMENDED ACTION:
<one sentence on what the analyst should do>
"""
)


# ─────────────────────────────────────────────
# 2. LLM SETUP
#    OllamaLLM runs Mistral locally on your machine.
#    model="mistral" matches the model you pulled.
#    temperature=0 makes output deterministic
#    (same input → same output), good for testing.
# ─────────────────────────────────────────────
def build_chain():
    """
    Constructs the LCEL chain:
        prompt_template | llm | output_parser

    The | operator pipes output from left to right.
    StrOutputParser simply extracts the text from
    the LLM's response object.
    """
    llm = OllamaLLM(
        model="mistral",
        temperature=0,          # 0 = deterministic; 0.7 = more creative
        base_url="http://localhost:11434"   # default Ollama port
    )
    output_parser = StrOutputParser()

    # LCEL pipe syntax: each | passes output to the next stage
    chain = CLASSIFICATION_PROMPT | llm | output_parser
    return chain


# ─────────────────────────────────────────────
# 3. RUN THE CLASSIFICATION
# ─────────────────────────────────────────────
def classify_alert(alert: dict) -> str:
    """
    Takes a Wazuh alert dict, runs it through
    the classification chain, returns the LLM output.

    Args:
        alert: dict — a Wazuh-style alert JSON object

    Returns:
        str — formatted severity + reasoning from Mistral
    """
    chain = build_chain()

    # Convert dict to pretty JSON string for readability in the prompt
    alert_json_str = json.dumps(alert, indent=2)

    print("─" * 60)
    print("INPUT ALERT:")
    print(alert_json_str)
    print("─" * 60)
    print("RUNNING CLASSIFICATION... (CPU-only mode, may take 30-90s)\n")

    # invoke() is how you run a chain — pass a dict matching
    # the prompt's input_variables
    result = chain.invoke({"alert_json": alert_json_str})

    return result


# ─────────────────────────────────────────────
# 4. MAIN ENTRY POINT
#    Classifies the SSH brute force sample by default.
#    Change SAMPLE_ALERTS["ssh_brute_force"] to test
#    the other two samples: "low_disk", "rootkit_detection"
# ─────────────────────────────────────────────
if __name__ == "__main__":
    alert_to_test = SAMPLE_ALERTS["low_disk"]

    output = classify_alert(alert_to_test)

    print("LLM CLASSIFICATION OUTPUT:")
    print("─" * 60)
    print(output)
    print("─" * 60)
