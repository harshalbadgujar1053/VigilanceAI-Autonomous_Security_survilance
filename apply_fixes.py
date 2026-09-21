"""
apply_fixes.py — Applies two permanent fixes to agent/classify_with_rag.py:

FIX 1: Retry with exponential backoff on Gemini 429 rate-limit errors,
       instead of failing immediately (root cause of the 9 unclassified
       Aug 20 alerts, and any future burst).

FIX 2: Ground [TECHNIQUE] in the prompt itself (pass top_technique in as
       a required field) so Gemini's [REASONING] text is generated already
       knowing the correct technique, instead of the current approach
       where Gemini picks its own technique for the reasoning and a
       separate line of code silently overwrites the [TECHNIQUE] tag
       afterward — which is what caused the T1110.003 vs T1110.001
       mismatch you saw in the screenshot.

Run from repo root:
    python3 apply_fixes.py

It edits agent/classify_with_rag.py in place. A .bak backup is made first.
Prints a diff-like summary of what changed. Re-run is safe (idempotent) —
it checks for already-applied markers before patching.
"""
import re
import shutil
from pathlib import Path

TARGET = Path("agent/classify_with_rag.py")

def main():
    if not TARGET.exists():
        print(f"ERROR: {TARGET} not found. Run this from the repo root.")
        return

    src = TARGET.read_text()

    if "MAX_GEMINI_RETRIES" in src:
        print("Fixes already applied (found MAX_GEMINI_RETRIES marker). Nothing to do.")
        return

    backup = TARGET.with_suffix(".py.bak")
    shutil.copy(TARGET, backup)
    print(f"Backed up original to {backup}")

    # ── FIX 2a: prompt template gets a new required input variable ──
    old_prompt_header = '''RAG_CLASSIFICATION_PROMPT = PromptTemplate(
    input_variables=["alert_json", "mitre_context"],
    template="""You are a cybersecurity analyst for a SOC (Security Operations Center).

You have access to the following relevant MITRE ATT&CK threat intelligence
that matches this alert:

--- MITRE ATT&CK CONTEXT ---
{mitre_context}
--- END CONTEXT ---

Using the above threat intelligence as reference, analyze this security alert
and classify its severity.

ALERT:
{alert_json}

Respond in this EXACT format (no extra text before or after, no markdown).
IMPORTANT: Replace every placeholder with real analysis text. Never include
angle brackets or literal words like "bullet point" or "action" in your output.

[SEVERITY] <CRITICAL | HIGH | MEDIUM | LOW>
[TECHNIQUE] <the single best-matching technique ID and name from the MITRE ATT&CK CONTEXT above, e.g. "T1110 - Brute Force">
[REASONING]
- <what triggered this alert — be specific to the actual data above>
- <how it maps to the MITRE technique — be specific>
- <key indicators of compromise — be specific>
[RECOMMENDED ACTIONS]
- <a concrete, specific action>
- <a concrete, specific action>
- <a concrete, specific action>
"""
)'''

    new_prompt_header = '''RAG_CLASSIFICATION_PROMPT = PromptTemplate(
    input_variables=["alert_json", "mitre_context", "required_technique"],
    template="""You are a cybersecurity analyst for a SOC (Security Operations Center).

You have access to the following relevant MITRE ATT&CK threat intelligence
that matches this alert:

--- MITRE ATT&CK CONTEXT ---
{mitre_context}
--- END CONTEXT ---

Using the above threat intelligence as reference, analyze this security alert
and classify its severity.

ALERT:
{alert_json}

The technique for this alert has already been determined via retrieval to be:
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

    if old_prompt_header not in src:
        print("ERROR: prompt template block not found verbatim — file may have changed. Aborting, no edits made.")
        return
    src = src.replace(old_prompt_header, new_prompt_header)

    # ── FIX 2b: _classify_via_gemini takes and passes required_technique ──
    old_gemini_sig = '''def _classify_via_gemini(alert_json_str: str, mitre_context: str) -> str:
    """
    Calls the Gemini API directly (not via LangChain) to keep this path
    simple and easy to reason about. Raises on any failure so the caller
    can fall back to local Ollama.
    """
    import google.generativeai as genai

    if not GEMINI_API_KEY:
        raise RuntimeError("GEMINI_API_KEY not set")

    genai.configure(api_key=GEMINI_API_KEY)
    model = genai.GenerativeModel(GEMINI_MODEL)

    prompt_text = RAG_CLASSIFICATION_PROMPT.format(
        alert_json=alert_json_str,
        mitre_context=mitre_context
    )

    response = model.generate_content(
        prompt_text,
        generation_config=genai.types.GenerationConfig(
            temperature=0,
            max_output_tokens=800
        ),
        request_options={"timeout": GEMINI_TIMEOUT_SECONDS}
    )

    text = response.text.strip()
    if not text:
        raise RuntimeError("Gemini returned empty response")
    return text'''

    new_gemini_sig = '''# FIX (permanent): retry with exponential backoff on Gemini 429s.
# Root cause of the Aug 20 burst failures — a wave of near-simultaneous
# SSH alerts each fired their own classification call with zero
# throttling or retry, so any call that landed during the rate-limit
# window failed permanently instead of just waiting it out.
MAX_GEMINI_RETRIES = 3
GEMINI_RETRY_BASE_DELAY_SECONDS = 5  # 5s, 10s, 20s

def _is_rate_limit_error(exc: Exception) -> bool:
    msg = str(exc).lower()
    return "429" in msg or "rate limit" in msg or "resourceexhausted" in msg or "quota" in msg

def _classify_via_gemini(alert_json_str: str, mitre_context: str, required_technique: str = "") -> str:
    """
    Calls the Gemini API directly (not via LangChain) to keep this path
    simple and easy to reason about. Retries on 429/rate-limit errors with
    exponential backoff before giving up; raises on any other failure so
    the caller can fall back to local Ollama.
    """
    import google.generativeai as genai
    import time

    if not GEMINI_API_KEY:
        raise RuntimeError("GEMINI_API_KEY not set")

    genai.configure(api_key=GEMINI_API_KEY)
    model = genai.GenerativeModel(GEMINI_MODEL)

    prompt_text = RAG_CLASSIFICATION_PROMPT.format(
        alert_json=alert_json_str,
        mitre_context=mitre_context,
        required_technique=required_technique or "the best match from context above"
    )

    last_exc = None
    for attempt in range(1, MAX_GEMINI_RETRIES + 1):
        try:
            response = model.generate_content(
                prompt_text,
                generation_config=genai.types.GenerationConfig(
                    temperature=0,
                    max_output_tokens=800
                ),
                request_options={"timeout": GEMINI_TIMEOUT_SECONDS}
            )
            text = response.text.strip()
            if not text:
                raise RuntimeError("Gemini returned empty response")
            return text
        except Exception as e:
            last_exc = e
            if _is_rate_limit_error(e) and attempt < MAX_GEMINI_RETRIES:
                delay = GEMINI_RETRY_BASE_DELAY_SECONDS * (2 ** (attempt - 1))
                print(f"Gemini rate-limited (attempt {attempt}/{MAX_GEMINI_RETRIES}), retrying in {delay}s...")
                time.sleep(delay)
                continue
            raise
    raise last_exc'''

    if old_gemini_sig not in src:
        print("ERROR: _classify_via_gemini block not found verbatim — file may have changed. Aborting, no edits made.")
        return
    src = src.replace(old_gemini_sig, new_gemini_sig)

    # ── FIX 2c: classify_alert_with_rag passes top_technique through ──
    old_call = '''    result = _classify_via_gemini(alert_json_str, mitre_context)'''
    new_call = '''    result = _classify_via_gemini(alert_json_str, mitre_context, required_technique=top_technique or "")'''

    if old_call not in src:
        print("WARNING: call site for _classify_via_gemini not found verbatim — technique won't be passed through. Check manually.")
    else:
        src = src.replace(old_call, new_call)

    TARGET.write_text(src)
    print("\nApplied successfully:")
    print("  1. Added retry/backoff (3 attempts, 5s/10s/20s) for Gemini 429 errors")
    print("  2. Prompt now receives required_technique so [TECHNIQUE] and [REASONING] can't disagree")
    print(f"\nOriginal saved at {backup} in case you need to revert.")

if __name__ == "__main__":
    main()
