"""
react_agent.py — Vigilance AI Manual ReAct Agent (Phase 3 Final)
-----------------------------------------------------------------
Project: Vigilance AI
LangChain: 1.3.10

Manual ReAct loop that works with Mistral 7B.
Uses text-based Thought/Action/Observation format since
Mistral 7B does not support native function calling.

The loop:
1. LLM decides which tool to call (Thought + Action)
2. We parse the action and call the real Python function
3. We feed the result back as Observation
4. Repeat until generate_report is called
5. generate_report receives the FULL scratchpad as context
   so it never hallucinates — it only uses real findings.

Run:
    cd ~/vigilance-ai/agent
    python react_agent.py
"""

import sys
import os
import re
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from langchain_ollama import OllamaLLM
from langchain_core.prompts import PromptTemplate
from langchain_core.output_parsers import StrOutputParser

# Import all 5 tools
from tools.lookup_threat_intel import lookup_threat_intel
from tools.map_to_mitre import map_to_mitre
from tools.check_cve import check_cve
from tools.query_siem import query_siem
from tools.generate_report import generate_report


# ─────────────────────────────────────────────
# 1. TOOL REGISTRY
#    Maps tool name strings to actual functions.
# ─────────────────────────────────────────────
TOOL_REGISTRY = {
    "query_siem": query_siem,
    "lookup_threat_intel": lookup_threat_intel,
    "map_to_mitre": map_to_mitre,
    "check_cve": check_cve,
    "generate_report": generate_report
}

TOOL_DESCRIPTIONS = """
- query_siem: Get full alert details from SIEM. Input: alert ID e.g. "1717000001"
- lookup_threat_intel: Search MITRE ATT&CK techniques. Input: attack description
- map_to_mitre: Map alert to MITRE technique with confidence score. Input: alert description
- check_cve: Look up CVE severity from NVD. Input: CVE ID e.g. "CVE-2023-38408"
- generate_report: Write final incident report. Input: complete summary of all findings
"""


# ─────────────────────────────────────────────
# 2. REACT PROMPT
#    Text-based format Mistral 7B understands.
#    Forces one action per response.
# ─────────────────────────────────────────────
REACT_PROMPT = PromptTemplate.from_template(
"""You are Vigilance AI, an autonomous SOC analyst.
Investigate the security alert step by step using the tools below.

Available tools:
{tool_descriptions}

STRICT FORMAT — respond with EXACTLY this structure each time:
Thought: [your reasoning about what to do next]
Action: [tool_name — must be one of the tool names above]
Action Input: [the exact input to pass to the tool]

Rules:
- Write only ONE Thought/Action/Action Input block per response
- Do not write Observation — that will be provided to you
- Do not make up results — wait for the Observation
- Your LAST action must always be generate_report

Previous steps taken:
{scratchpad}

Alert to investigate:
{input}

What is your next action?"""
)


# ─────────────────────────────────────────────
# 3. PARSE ACTION FROM LLM OUTPUT
# ─────────────────────────────────────────────
def parse_action(text: str):
    """
    Extracts Action and Action Input from LLM text output.
    Returns (action_name, action_input) or (None, None) if not found.
    """
    action_match = re.search(
        r"Action:\s*([a-zA-Z_]+)", text
    )
    input_match = re.search(
        r"Action Input:\s*(.+?)(?:\n\n|\nThought|\nAction:|$)",
        text,
        re.DOTALL
    )

    if action_match and input_match:
        action = action_match.group(1).strip()
        action_input = input_match.group(1).strip()
        # Clean up any trailing quotes or newlines
        action_input = action_input.strip('"\'').strip()
        return action, action_input

    return None, None


# ─────────────────────────────────────────────
# 4. EXECUTE A TOOL
# ─────────────────────────────────────────────
def run_tool(tool_name: str, tool_input: str) -> str:
    """
    Looks up the tool by name and calls it with the given input.
    Returns the tool's string output.
    """
    tool_name_clean = tool_name.strip().lower()

    if tool_name_clean in TOOL_REGISTRY:
        tool = TOOL_REGISTRY[tool_name_clean]
        try:
            result = tool.invoke(tool_input)
            return str(result)
        except Exception as e:
            return f"Tool error: {str(e)}"
    else:
        available = list(TOOL_REGISTRY.keys())
        return f"Unknown tool '{tool_name}'. Available tools: {available}"


# ─────────────────────────────────────────────
# 5. MAIN REACT LOOP
# ─────────────────────────────────────────────
def investigate(alert_description: str, max_steps: int = 7) -> str:
    """
    Runs the manual ReAct loop:
    - At each step, LLM decides what tool to call
    - We parse the decision and actually call the tool
    - We feed the result back as Observation
    - Loop ends when generate_report is called
    - generate_report receives full scratchpad (all real findings)
      so it never hallucinates
    """
    print("=" * 60)
    print("VIGILANCE AI — Autonomous SOC Investigation")
    print("=" * 60)
    print(f"\nAlert: {alert_description[:120]}...\n")
    print("Starting ReAct loop (30-90s per step on CPU)...")
    print("-" * 60)

    llm = OllamaLLM(
        model="mistral",
        temperature=0,
        base_url="http://localhost:11434"
    )
    chain = REACT_PROMPT | llm | StrOutputParser()

    scratchpad = ""
    final_report = ""
    steps_taken = []

    for step in range(max_steps):
        print(f"\n{'='*20} Step {step + 1}/{max_steps} {'='*20}")
        print("LLM thinking...")

        # Get LLM's next action
        response = chain.invoke({
            "input": alert_description,
            "tool_descriptions": TOOL_DESCRIPTIONS,
            "scratchpad": scratchpad if scratchpad else "None yet — this is the first step."
        })

        print(f"\nLLM decided:\n{response[:400]}")

        # Parse the action
        action, action_input = parse_action(response)

        if not action:
            print("\nCould not parse action from LLM response.")
            print("Raw response:", response[:200])
            # Try to continue rather than crash
            scratchpad += f"\nStep {step+1}: LLM response unclear, continuing...\n"
            continue

        print(f"\n[CALLING TOOL]: {action}")
        print(f"[INPUT]: {action_input[:100]}")

        steps_taken.append(action)

        # Special case: generate_report gets the FULL real findings
        # from all previous steps — not just what LLM passed as input
        if action == "generate_report":
            print("\n[Building full findings from all previous steps...]")

            # Compile all real observations into a findings summary
            full_findings = f"""Alert: {alert_description}

Real findings from investigation:
{scratchpad}

Tools used: {', '.join(steps_taken[:-1])}
"""
            print("[CALLING generate_report with complete real findings]")
            final_report = run_tool("generate_report", full_findings)
            print("\n✓ REPORT GENERATED — Investigation complete")
            print(f"\nTools used in this investigation: {steps_taken}")
            break

        # Call the actual tool
        observation = run_tool(action, action_input)
        print(f"\n[OBSERVATION]: {observation[:300]}...")

        # Add step to scratchpad for LLM context
        thought_match = re.search(r"Thought:\s*(.+?)(?:\nAction:|$)", response, re.DOTALL)
        thought = thought_match.group(1).strip() if thought_match else "Investigating..."

        scratchpad += f"""
Step {step + 1}:
Thought: {thought}
Action: {action}
Action Input: {action_input}
Observation: {observation[:600]}
"""

    # If loop ended without generate_report being called
    if not final_report:
        print("\n[Max steps reached — generating report from available findings]")
        full_findings = f"Alert: {alert_description}\n\nFindings:\n{scratchpad}"
        final_report = run_tool("generate_report", full_findings)

    return final_report


# ─────────────────────────────────────────────
# 6. MAIN ENTRY POINT
# ─────────────────────────────────────────────
if __name__ == "__main__":
    alert = (
        "Alert ID 1717000001: Multiple failed SSH login attempts detected. "
        "847 attempts in 60 seconds from external IP 185.220.101.47 "
        "targeting web-server-prod (10.0.1.45). Wazuh rule level: 10/15. "
        "Investigate this alert, identify the MITRE ATT&CK technique, "
        "check for relevant CVEs, and generate a full incident report."
    )

    final_report = investigate(alert)

    print("\n" + "=" * 60)
    print("FINAL INCIDENT REPORT:")
    print("=" * 60)
    print(final_report)
