"""
classify_with_rag.py — RAG-enhanced classification (Phase 2 Track D)
---------------------------------------------------------------------
Project: Vigilance AI

Combines the Phase 1 classification chain with the ChromaDB RAG pipeline.
Before asking Mistral to classify an alert, we first retrieve the top 3
matching MITRE ATT&CK techniques and inject them into the prompt.

This means Mistral reasons with real, verified threat intel context
instead of just its training knowledge.

Run:
    cd ~/vigilance-ai/agent
    python classify_with_rag.py
"""

import json
import chromadb
from chromadb.utils import embedding_functions
from langchain_ollama import OllamaLLM
from langchain_core.prompts import PromptTemplate
from langchain_core.output_parsers import StrOutputParser

from alert_schema import SAMPLE_ALERTS


# ─────────────────────────────────────────────
# 1. RAG: RETRIEVE MITRE CONTEXT
# ─────────────────────────────────────────────
def get_mitre_context(alert_description: str, n_results: int = 3) -> str:
    """
    Queries ChromaDB for the top N MITRE techniques
    matching the alert description.
    Returns a formatted string ready to inject into the prompt.
    """
    client = chromadb.PersistentClient(path="./chroma_db")
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
    for i, doc_id in enumerate(results["ids"][0]):
        technique_name = results["metadatas"][0][i]["technique"]
        technique_text = results["documents"][0][i]
        # Take first 300 chars of each technique to keep prompt manageable
        context_lines.append(
            f"[{doc_id}] {technique_name}:\n{technique_text[:300]}..."
        )

    return "\n\n".join(context_lines)


# ─────────────────────────────────────────────
# 2. RAG-ENHANCED PROMPT TEMPLATE
#    Now has TWO variables: {alert_json} AND {mitre_context}
#    The context section grounds Mistral's reasoning in
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

Respond in this EXACT format:

SEVERITY: <CRITICAL | MEDIUM | LOW>

MITRE TECHNIQUES IDENTIFIED:
- <technique ID and name from context above>

REASONING:
- <bullet point 1: what triggered this alert>
- <bullet point 2: how it maps to the MITRE techniques above>
- <bullet point 3: key indicators of compromise>

RECOMMENDED ACTION:
<one sentence on what the analyst should do>
"""
)


# ─────────────────────────────────────────────
# 3. BUILD THE RAG-ENHANCED CHAIN
# ─────────────────────────────────────────────
def build_rag_chain():
    llm = OllamaLLM(
        model="mistral",
        temperature=0,
        base_url="http://localhost:11434"
    )
    output_parser = StrOutputParser()
    chain = RAG_CLASSIFICATION_PROMPT | llm | output_parser
    return chain


# ─────────────────────────────────────────────
# 4. CLASSIFY WITH RAG
# ─────────────────────────────────────────────
def classify_alert_with_rag(alert: dict) -> dict:
    """
    Full RAG-enhanced classification pipeline:
    1. Extract description from alert
    2. Query ChromaDB for top 3 MITRE matches
    3. Inject matches into prompt
    4. Run Mistral classification
    5. Return result with retrieved context included
    """
    # Build query string from alert fields
    description = alert.get("rule", {}).get("description", "")
    groups = " ".join(alert.get("rule", {}).get("groups", []))
    query = f"{description} {groups}"

    print(f"Querying ChromaDB for: '{query}'")

    # Step 1: Retrieve MITRE context
    mitre_context = get_mitre_context(query)

    print("\nTop MITRE matches retrieved:")
    for line in mitre_context.split("\n\n"):
        print(f"  {line[:80]}...")

    print("\nRunning RAG-enhanced classification (30-90s on CPU)...\n")

    # Step 2: Run the enhanced chain
    chain = build_rag_chain()
    alert_json_str = json.dumps(alert, indent=2)

    result = chain.invoke({
        "alert_json": alert_json_str,
        "mitre_context": mitre_context
    })

    return {
        "mitre_context_used": mitre_context,
        "classification": result
    }


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
    print(result["classification"])
    print("─" * 60)
