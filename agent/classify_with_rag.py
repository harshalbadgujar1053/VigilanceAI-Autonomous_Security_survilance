"""
classify_with_rag.py — RAG-enhanced classification (Phase 2 Track D)
---------------------------------------------------------------------
Project: Vigilance AI

Combines the Phase 1 classification chain with a MULTI-SOURCE ChromaDB RAG
pipeline. Before asking the LLM to classify an alert, we retrieve the top
matches from FOUR independent knowledge sources and inject them into the
prompt:

    - mitre_techniques  (MITRE ATT&CK Enterprise, 697 techniques)
    - nvd_cves          (NVD CVE records)
    - capec_patterns    (MITRE CAPEC attack patterns)
    - cwe_weaknesses    (MITRE CWE weaknesses)

This means the LLM reasons with real, verified, cross-referenced threat
intel context instead of just its training knowledge or a single source.

DETERMINISTIC TECHNIQUE GROUNDING (unchanged core discipline):
The [TECHNIQUE] field injected into the prompt is ALWAYS taken from the
#1 mitre_techniques match — never inferred by the LLM, and never
overridden by CAPEC/CVE/CWE hits, since only mitre_techniques document IDs
are valid MITRE ATT&CK T-codes. This preserves the "deterministic
injection over LLM inference" principle the whole pipeline is built on.

MITRE/CAPEC AGREEMENT FLAG (new in this version):
CAPEC attack patterns carry their own mapped ATT&CK technique IDs
(x_capec_related_attack_pattern-style external references, ingested as
the `attack_technique_ids` metadata field on capec_patterns). We compare
the top CAPEC match's mapped technique(s) against the deterministic MITRE
technique chosen above:
    - If they agree, or CAPEC has no technique mapping, nothing changes.
    - If they disagree, we do NOT override [TECHNIQUE] — instead we
      surface the disagreement as an explicit note passed to the LLM (so
      it can mention it in [REASONING] if relevant) and record it in the
      returned result dict as `mitre_capec_agreement`, so you can compute
      a real "MITRE/CAPEC technique agreement rate" across your alert
      test set for the paper.

Primary classifier: Google Gemini API (gemini-3.5-flash-lite) — fast,
free-tier, high accuracy (benchmarked at ~1.8s avg, 87.5%+ technique
accuracy vs local models' 55-160s and 25% accuracy).

Run:
    cd ~/VigilanceAI-Autonomous_Security_survilance/agent
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
GEMINI_TIMEOUT_SECONDS = 45


# ─────────────────────────────────────────────
# 1. RAG: RETRIEVE MULTI-SOURCE CONTEXT
#    (MITRE ATT&CK + NVD CVEs + CAPEC + CWE)
# ─────────────────────────────────────────────

CHROMA_DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "chroma_db"
)

# Per-collection config: how many chunks to pull from each source per query,
# and how to render each source's metadata into a readable context line.
# Keeping per-source n_results modest keeps total prompt length manageable
# even with 4 sources instead of 1.
COLLECTION_CONFIGS = {
    "mitre_techniques": {
        "n_results": 3,
        "label": "MITRE ATT&CK",
        "format": lambda doc_id, meta, text: (
            f"[{doc_id}] {meta.get('technique_name', '')}:\n{text[:300]}..."
        ),
    },
    "nvd_cves": {
        "n_results": 2,
        "label": "NVD CVE",
        "format": lambda doc_id, meta, text: (
            f"[{doc_id}] CVSS {meta.get('cvss_score', 'N/A')} "
            f"({meta.get('cvss_severity', 'UNKNOWN')}), "
            f"related weaknesses: {meta.get('cwe_ids') or 'none'}:\n{text[:300]}..."
        ),
    },
    "capec_patterns": {
        "n_results": 2,
        "label": "CAPEC Attack Pattern",
        "format": lambda doc_id, meta, text: (
            f"[{doc_id}] {meta.get('name', '')} "
            f"(severity: {meta.get('severity', 'Unknown')}, "
            f"maps to ATT&CK: {meta.get('attack_technique_ids') or 'none'}):\n{text[:300]}..."
        ),
    },
    "cwe_weaknesses": {
        "n_results": 2,
        "label": "CWE Weakness",
        "format": lambda doc_id, meta, text: (
            f"[{doc_id}] {meta.get('name', '')} "
            f"(abstraction: {meta.get('abstraction', 'Unknown')}):\n{text[:300]}..."
        ),
    },
}


def _get_chroma_client_and_embedder():
    client = chromadb.PersistentClient(path=CHROMA_DB_PATH)
    embed_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
        model_name="all-MiniLM-L6-v2"
    )
    return client, embed_fn


def _first_capec_technique_id(attack_technique_ids_str: str) -> str | None:
    """CAPEC's attack_technique_ids metadata is a comma-separated string
    like 'T1055, T1055.001'. Return just the first one, or None if empty."""
    if not attack_technique_ids_str:
        return None
    first = attack_technique_ids_str.split(",")[0].strip()
    return first or None


def get_multi_source_context(alert_description: str) -> dict:
    """
    Queries all four ChromaDB collections (mitre_techniques, nvd_cves,
    capec_patterns, cwe_weaknesses) for the chunks most relevant to the
    alert description, and merges them into one formatted context block
    grouped by source, ready to inject into the Gemini prompt.

    Returns a dict:
        {
            "merged_context": str,
            "top_technique": "T1110 - Brute Force" | None,
            "capec_top_technique_id": "T1110" | None,
            "mitre_capec_agreement": True | False | None,
                # True  -> CAPEC's top mapped technique matches MITRE's
                # False -> CAPEC's top mapped technique DISAGREES with MITRE's
                # None  -> no comparison possible (CAPEC hit had no mapping,
                #          or mitre_techniques returned nothing)
            "capec_disagreement_note": str,
                # empty string if no disagreement; otherwise a sentence to
                # surface to the LLM (and to you, for logging) describing
                # the discrepancy. [TECHNIQUE] itself is NEVER changed by
                # this — MITRE stays the deterministic source of truth.
        }
    """
    client, embed_fn = _get_chroma_client_and_embedder()

    source_blocks: list[str] = []
    top_technique: str | None = None
    top_technique_id: str | None = None
    capec_top_technique_id: str | None = None

    for collection_name, cfg in COLLECTION_CONFIGS.items():
        try:
            collection = client.get_collection(
                name=collection_name, embedding_function=embed_fn
            )
        except Exception as e:
            print(f"  [!] Skipping '{collection_name}': {e}")
            continue

        results = collection.query(
            query_texts=[alert_description],
            n_results=cfg["n_results"],
        )

        ids = results.get("ids", [[]])[0]
        if not ids:
            continue

        lines = []
        for i, doc_id in enumerate(ids):
            meta = results["metadatas"][0][i]
            text = results["documents"][0][i]
            lines.append(cfg["format"](doc_id, meta, text))

            if collection_name == "mitre_techniques" and i == 0:
                # Deterministic grounding, unchanged from single-source
                # version: the #1 mitre_techniques match becomes the
                # required technique, never inferred from CVE/CAPEC/CWE hits.
                technique_name = meta.get("technique_name", "")
                top_technique = f"{doc_id} - {technique_name}"
                top_technique_id = doc_id

            if collection_name == "capec_patterns" and i == 0:
                # Record CAPEC's top mapped technique (if any) for the
                # agreement check below. This NEVER feeds into top_technique.
                capec_top_technique_id = _first_capec_technique_id(
                    meta.get("attack_technique_ids", "")
                )

        source_blocks.append(
            f"--- {cfg['label']} ({len(lines)} matches) ---\n" + "\n\n".join(lines)
        )

    merged_context = "\n\n".join(source_blocks)

    # MITRE/CAPEC agreement check (Option 3: flag disagreement, never override)
    mitre_capec_agreement: bool | None
    capec_disagreement_note = ""
    if top_technique_id is None or capec_top_technique_id is None:
        mitre_capec_agreement = None
    else:
        # Compare base technique IDs (ignore sub-technique suffix like .001
        # for the agreement check, since T1110 vs T1110.001 is a refinement,
        # not a genuine disagreement).
        mitre_base = top_technique_id.split(".")[0]
        capec_base = capec_top_technique_id.split(".")[0]
        mitre_capec_agreement = mitre_base == capec_base
        if not mitre_capec_agreement:
            capec_disagreement_note = (
                f"Note: the top CAPEC attack pattern match suggests technique "
                f"{capec_top_technique_id}, which differs from the retrieved "
                f"MITRE technique {top_technique_id}. This can happen when an "
                f"attack pattern maps to a related but distinct technique — "
                f"mention this briefly in your reasoning if it's relevant, but "
                f"the required technique for this alert remains {top_technique_id}."
            )

    return {
        "merged_context": merged_context,
        "top_technique": top_technique,
        "capec_top_technique_id": capec_top_technique_id,
        "mitre_capec_agreement": mitre_capec_agreement,
        "capec_disagreement_note": capec_disagreement_note,
    }


# Backward-compatible alias: existing callers (and any tests) importing
# get_mitre_context by name keep working, but note the return shape is
# unchanged (context_str, top_technique) — callers wanting the agreement
# flag should call get_multi_source_context() directly instead.
def get_mitre_context(alert_description: str, n_results: int = 3) -> tuple[str, str | None]:
    result = get_multi_source_context(alert_description)
    return result["merged_context"], result["top_technique"]


# ─────────────────────────────────────────────
# 2. RAG-ENHANCED PROMPT TEMPLATE
#    Variables: {alert_json}, {mitre_context}, {required_technique},
#    {capec_disagreement_note} (empty string when there's no disagreement)
# ─────────────────────────────────────────────
RAG_CLASSIFICATION_PROMPT = PromptTemplate(
    input_variables=["alert_json", "mitre_context", "required_technique", "capec_disagreement_note"],
    template="""You are a cybersecurity analyst for a SOC (Security Operations Center).

You have access to the following relevant threat intelligence, retrieved
from MITRE ATT&CK, NVD CVEs, MITRE CAPEC attack patterns, and MITRE CWE
weaknesses, that matches this alert:

--- THREAT INTELLIGENCE CONTEXT ---
{mitre_context}
--- END CONTEXT ---

Using the above threat intelligence as reference, analyze this security alert
and classify its severity.

ALERT:
{alert_json}

The technique for this alert has already been determined via retrieval to be:
{required_technique}

{capec_disagreement_note}

Respond in this EXACT format (no extra text before or after, no markdown).
IMPORTANT: Replace every placeholder with real analysis text. Never include
angle brackets or literal words like "bullet point" or "action" in your output.
The [TECHNIQUE] line MUST be exactly "{required_technique}" — do not
substitute a different technique. Write [REASONING] that specifically
justifies THIS technique, not any other technique from the context above.

STRICT REASONING RULES:
- [REASONING] must contain EXACTLY 2 or 3 bullets. Never more.
- Each bullet must be ONE short sentence (under 25 words).
- Do NOT restate the [SEVERITY], [TECHNIQUE], or [VERDICT] tags as bullets.
- Do NOT repeat or preview any [RECOMMENDED ACTIONS] content inside
  [REASONING] — those belong only in the RECOMMENDED ACTIONS section below.
- Do NOT include section labels like "[REASONING]" or "[RECOMMENDED ACTIONS]"
  as text inside a bullet.

Also assess whether this alert is likely a real attack (TRUE POSITIVE) or
likely benign/noise (FALSE POSITIVE) or genuinely unclear (NEEDS INVESTIGATION),
along with how confident you are in that assessment. Be honest about
uncertainty — do not default to HIGH confidence if the evidence is thin.

[VERDICT] <TRUE POSITIVE | FALSE POSITIVE | NEEDS INVESTIGATION>
[CONFIDENCE] <HIGH | MEDIUM | LOW>
[SEVERITY] <CRITICAL | HIGH | MEDIUM | LOW>
[TECHNIQUE] {required_technique}
[REASONING]
- <one specific sentence: what triggered this alert>
- <one specific sentence: how it maps to {required_technique}>
[RECOMMENDED ACTIONS]
- <a concrete, specific action>
- <a concrete, specific action>
- <a concrete, specific action>
"""
)


# ─────────────────────────────────────────────
# 3a. PRIMARY: GEMINI API CLASSIFIER
# ─────────────────────────────────────────────
# FIX (permanent): retry with exponential backoff on Gemini 429s.
# Root cause of the Aug 20 burst failures — a wave of near-simultaneous
# SSH alerts each fired their own classification call with zero
# throttling or retry, so any call that landed during the rate-limit
# window failed permanently instead of just waiting it out.
MAX_GEMINI_RETRIES = 3
GEMINI_RETRY_BASE_DELAY_SECONDS = 5  # 5s, 10s, 20s

def _is_rate_limit_error(exc: Exception) -> bool:
    msg = str(exc).lower()
    return "429" in msg or "rate limit" in msg or "resourceexhausted" in msg or "quota" in msg

def _classify_via_gemini(
    alert_json_str: str,
    mitre_context: str,
    required_technique: str = "",
    capec_disagreement_note: str = "",
) -> str:
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
        required_technique=required_technique or "the best match from context above",
        capec_disagreement_note=capec_disagreement_note,
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
    raise last_exc


# ─────────────────────────────────────────────
# 3b. FALLBACK: LOCAL OLLAMA CLASSIFIER
# ─────────────────────────────────────────────
def _classify_via_ollama(alert_json_str: str, mitre_context: str, capec_disagreement_note: str = "") -> str:
    llm = OllamaLLM(
        model=FALLBACK_OLLAMA_MODEL,
        temperature=0,
        base_url="http://localhost:11434"
    )
    output_parser = StrOutputParser()
    chain = RAG_CLASSIFICATION_PROMPT | llm | output_parser

    result = chain.invoke({
        "alert_json": alert_json_str,
        "mitre_context": mitre_context,
        "required_technique": "the best match from context above",
        "capec_disagreement_note": capec_disagreement_note,
    })
    return result


# ─────────────────────────────────────────────
# 4. CLASSIFY WITH RAG (multi-source retrieval + Gemini)
# ─────────────────────────────────────────────
def classify_alert_with_rag(alert: dict) -> dict:
    """
    Full RAG-enhanced classification pipeline:
    1. Extract description from alert
    2. Query all 4 ChromaDB collections (MITRE, NVD CVE, CAPEC, CWE)
    3. Inject merged multi-source context into prompt, with [TECHNIQUE]
       deterministically grounded from mitre_techniques only
    4. Check MITRE/CAPEC technique agreement and surface any disagreement
       to the LLM as an informational note (never overriding [TECHNIQUE])
    5. Run classification via Gemini API
    6. Return result with retrieved context, classifier used, and the
       mitre_capec_agreement flag for research-metric logging
    """
    # Build query string from alert fields
    description = alert.get("rule", {}).get("description", "")
    groups = " ".join(alert.get("rule", {}).get("groups", []))
    query = f"{description} {groups}"

    print(f"Querying ChromaDB (4 collections) for: '{query}'")

    # Step 1: Retrieve multi-source context
    retrieval = get_multi_source_context(query)
    mitre_context = retrieval["merged_context"]
    top_technique = retrieval["top_technique"]
    mitre_capec_agreement = retrieval["mitre_capec_agreement"]
    capec_disagreement_note = retrieval["capec_disagreement_note"]

    print("\nRetrieved context (by source):")
    for line in mitre_context.split("\n\n"):
        print(f"  {line[:80]}...")

    if mitre_capec_agreement is False:
        print(f"\n[!] MITRE/CAPEC technique disagreement detected: "
              f"MITRE={top_technique}, CAPEC maps to={retrieval['capec_top_technique_id']}")
    elif mitre_capec_agreement is True:
        print(f"\n[+] MITRE/CAPEC technique agreement confirmed ({top_technique})")

    alert_json_str = json.dumps(alert, indent=2)

    # Step 2: Classify via Gemini. No local fallback — Ollama has been
    # removed from this environment. If Gemini fails (rate limit, network,
    # bad key), this raises rather than silently degrading, so failures are
    # visible instead of hidden behind a slower/less accurate local model.
    classifier_used = "gemini"
    print(f"\nRunning classification via Gemini ({GEMINI_MODEL})...\n")
    result = _classify_via_gemini(
        alert_json_str,
        mitre_context,
        required_technique=top_technique or "",
        capec_disagreement_note=capec_disagreement_note,
    )

    # Step 3: Ground [TECHNIQUE] in the actual top ChromaDB match rather than
    # trusting the LLM's own read of the context — replaces whatever the LLM
    # wrote on that line (or appends it if the tag is missing). Unchanged
    # from the single-source version: MITRE is always the source of truth.
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
        "classifier_used": classifier_used,
        "mitre_capec_agreement": mitre_capec_agreement,
        "capec_top_technique_id": retrieval["capec_top_technique_id"],
    }


# Alias for tests/callers expecting this exact name
classify_with_rag = classify_alert_with_rag


# ─────────────────────────────────────────────
# 5. MAIN — test on SSH brute force alert
# ─────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("VIGILANCE AI — Multi-Source RAG Classification (Phase 2)")
    print("=" * 60)

    alert = SAMPLE_ALERTS["ssh_brute_force"]
    print(f"\nAlert: {alert['rule']['description']}\n")

    result = classify_alert_with_rag(alert)

    print("CLASSIFICATION OUTPUT:")
    print("─" * 60)
    print(f"(classifier used: {result['classifier_used']})")
    print(f"(MITRE/CAPEC agreement: {result['mitre_capec_agreement']})")
    print("─" * 60)
    print(result["classification"])
    print("─" * 60)
