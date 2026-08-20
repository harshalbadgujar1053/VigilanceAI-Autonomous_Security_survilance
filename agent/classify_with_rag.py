"""
classify_with_rag.py — RAG-enhanced classification (Phase 2 Track D)
---------------------------------------------------------------------
Project: Vigilance AI

Combines the Phase 1 classification chain with the ChromaDB RAG pipeline.
Before asking the LLM to classify an alert, we first retrieve the top 3
matching MITRE ATT&CK techniques and inject them into the prompt.

This means the LLM reasons with real, verified threat intel context
instead of just its training knowledge.

Primary classifier: Google Gemini API (gemini-3.5-flash-lite) — fast,
free-tier, high accuracy (benchmarked at ~1.8s avg, 87.5% technique
accuracy vs local models' 55-160s and 25% accuracy).

Fallback: local Ollama (phi3:mini) — used automatically if GEMINI_API_KEY
is missing, the API call fails, or the network is unavailable. This keeps
the pipeline resilient if you're offline or hit free-tier rate limits.

Run:
    cd ~/vigilance-ai/agent
    python classify_with_rag.py
"""

import json
import os
import chromadb
from chromadb.utils import embedding_functions
from langchain_ollama import OllamaLLM
from langchain_core.prompts import PromptTemplate
from langchain_core.output_parsers import StrOutputParser
from dotenv import load_dotenv

from alert_schema import SAMPLE_ALERTS

load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.5-flash-lite")
FALLBACK_OLLAMA_MODEL = os.getenv("FALLBACK_OLLAMA_MODEL", "phi3:mini")
GEMINI_TIMEOUT_SECONDS = 20


# ─────────────────────────────────────────────
# 1. RAG: RETRIEVE MITRE CONTEXT
# ─────────────────────────────────────────────
def get_mitre_context(alert_description: str, n_results: int = 3) -> str:
    """
    Queries ChromaDB for the top N MITRE techniques
    matching the alert description.
    Returns a formatted string ready to inject into the prompt.
    """
    client = chromadb.PersistentClient(path=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rag", "chroma_db"))
    embed_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
        model_name="all-MiniLM-L6-v2"
    )
    collection = client.get_collection(
        name="mitre_techniques",
        embedding_function=embed_fn
    )

    results = collection.query(
        query_texts=[alert_description],
        n_results=n_results
    )

    # Format results into a readable block for the prompt
    context_lines = []
    top_technique = None
    for i, doc_id in enumerate(results["ids"][0]):
        technique_name = results["metadatas"][0][i]["technique_name"]
        technique_text = results["documents"][0][i]
        if i == 0:
            # doc_id looks like "T1110" — grounds [TECHNIQUE] deterministically
            # instead of letting the LLM guess it.
            top_technique = f"{doc_id} - {technique_name}"
        # Take first 300 chars of each technique to keep prompt manageable
        context_lines.append(
            f"[{doc_id}] {technique_name}:\n{technique_text[:300]}..."
        )

    return "\n\n".join(context_lines), top_technique


# ─────────────────────────────────────────────
# 2. RAG-ENHANCED PROMPT TEMPLATE
#    Now has TWO variables: {alert_json} AND {mitre_context}
#    The context section grounds the LLM's reasoning in
#    real MITRE data rather than just training memory.
# ─────────────────────────────────────────────
RAG_CLASSIFICATION_PROMPT = PromptTemplate(
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
)


# ─────────────────────────────────────────────
# 3a. PRIMARY: GEMINI API CLASSIFIER
# ─────────────────────────────────────────────
def _classify_via_gemini(alert_json_str: str, mitre_context: str) -> str:
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
    return text


# ─────────────────────────────────────────────
# 3b. FALLBACK: LOCAL OLLAMA CLASSIFIER
# ─────────────────────────────────────────────
def _classify_via_ollama(alert_json_str: str, mitre_context: str) -> str:
    llm = OllamaLLM(
        model=FALLBACK_OLLAMA_MODEL,
        temperature=0,
        base_url="http://localhost:11434"
    )
    output_parser = StrOutputParser()
    chain = RAG_CLASSIFICATION_PROMPT | llm | output_parser

    result = chain.invoke({
        "alert_json": alert_json_str,
        "mitre_context": mitre_context
    })
    return result


# ─────────────────────────────────────────────
# 4. CLASSIFY WITH RAG (Gemini primary, Ollama fallback)
# ─────────────────────────────────────────────
def classify_alert_with_rag(alert: dict) -> dict:
    """
    Full RAG-enhanced classification pipeline:
    1. Extract description from alert
    2. Query ChromaDB for top 3 MITRE matches
    3. Inject matches into prompt
    4. Run classification via Gemini API (fast path), falling back to
       local Ollama if Gemini is unavailable, misconfigured, or errors
    5. Return result with retrieved context included, plus which
       classifier actually served the request
    """
    # Build query string from alert fields
    description = alert.get("rule", {}).get("description", "")
    groups = " ".join(alert.get("rule", {}).get("groups", []))
    query = f"{description} {groups}"

    print(f"Querying ChromaDB for: '{query}'")

    # Step 1: Retrieve MITRE context
    mitre_context, top_technique = get_mitre_context(query)

    print("\nTop MITRE matches retrieved:")
    for line in mitre_context.split("\n\n"):
        print(f"  {line[:80]}...")

    alert_json_str = json.dumps(alert, indent=2)

    # Step 2: Classify via Gemini. No local fallback — Ollama has been
    # removed from this environment. If Gemini fails (rate limit, network,
    # bad key), this raises rather than silently degrading, so failures are
    # visible instead of hidden behind a slower/less accurate local model.
    classifier_used = "gemini"
    print(f"\nRunning classification via Gemini ({GEMINI_MODEL})...\n")
    result = _classify_via_gemini(alert_json_str, mitre_context)

    # Step 3: Ground [TECHNIQUE] in the actual top ChromaDB match rather than
    # trusting the LLM's own read of the context — replaces whatever the LLM
    # wrote on that line (or appends it if the tag is missing).
    if top_technique:
        if "[TECHNIQUE]" in result:
            lines = result.split("\n")
            for idx, line in enumerate(lines):
                if line.strip().upper().startswith("[TECHNIQUE]"):
                    lines[idx] = f"[TECHNIQUE] {top_technique}"
                    break
            result = "\n".join(lines)
        else:
            result = result.strip() + f"\n[TECHNIQUE] {top_technique}"

    return {
        "mitre_context_used": mitre_context,
        "classification": result,
        "classifier_used": classifier_used
    }


# Alias for tests/callers expecting this exact name
classify_with_rag = classify_alert_with_rag


# ─────────────────────────────────────────────
# 5. MAIN — test on SSH brute force alert
# ─────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("VIGILANCE AI — RAG-Enhanced Classification (Phase 2)")
    print("=" * 60)

    alert = SAMPLE_ALERTS["ssh_brute_force"]
    print(f"\nAlert: {alert['rule']['description']}\n")

    result = classify_alert_with_rag(alert)

    print("CLASSIFICATION OUTPUT:")
    print("─" * 60)
    print(f"(classifier used: {result['classifier_used']})")
    print("─" * 60)
    print(result["classification"])
    print("─" * 60)
