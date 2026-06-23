"""
query_rag.py — Phase 2: Unified RAG Query Interface
-----------------------------------------------------
Project: VigilanceAI — Autonomous Security Surveillance

This is the central module that the LangChain agent (Phase 3) will import
and call when investigating a Wazuh alert. It searches both ChromaDB
collections (MITRE techniques + NVD CVEs) and returns the most relevant
threat intelligence context.

Usage (imported by agent tools in Phase 3):
    from rag.query_rag import query_threat_intel, query_cve, query_by_technique_id

Usage (standalone test):
    cd ~/VigilanceAI-Autonomous_Security_survilance
    python3 rag/query_rag.py "SSH brute force authentication failures"

Prerequisites:
    Run ingest_mitre.py and ingest_nvd.py FIRST before querying.
"""

import os
import sys
import chromadb
from chromadb.utils import embedding_functions
from typing import Optional

# ─────────────────────────────────────────────────────────
# PATHS
# ─────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHROMA_PATH = os.path.join(BASE_DIR, "rag", "chroma_db")

MITRE_COLLECTION = "mitre_techniques"
NVD_COLLECTION = "nvd_cves"


# ─────────────────────────────────────────────────────────
# CLIENT SETUP (singleton pattern — one client per process)
# ─────────────────────────────────────────────────────────
_client = None
_embed_fn = None


def _get_client():
    """Return a shared ChromaDB client (lazy initialization)."""
    global _client, _embed_fn

    if _client is None:
        if not os.path.exists(CHROMA_PATH):
            raise RuntimeError(
                f"ChromaDB not found at {CHROMA_PATH}.\n"
                "Run ingest_mitre.py and ingest_nvd.py first."
            )
        _client = chromadb.PersistentClient(path=CHROMA_PATH)
        _embed_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
            model_name="all-MiniLM-L6-v2"
        )

    return _client, _embed_fn


def _get_collection(name: str):
    """Return a named ChromaDB collection."""
    client, embed_fn = _get_client()
    try:
        return client.get_collection(name=name, embedding_function=embed_fn)
    except Exception:
        raise RuntimeError(
            f"Collection '{name}' not found. "
            f"Run {'ingest_mitre.py' if 'mitre' in name else 'ingest_nvd.py'} first."
        )


# ─────────────────────────────────────────────────────────
# PUBLIC QUERY FUNCTIONS
# These are what the Phase 3 agent tools will call.
# ─────────────────────────────────────────────────────────

def query_threat_intel(query: str, n_results: int = 3) -> list:
    """
    PRIMARY FUNCTION — searches both MITRE and NVD collections.
    Called by the agent's lookup_threat_intel() tool in Phase 3.

    Args:
        query: Natural language query, e.g.
               "SSH brute force multiple failed authentication"
               "what techniques does APT28 use"
               "privilege escalation via sudo"
        n_results: Number of results per collection (default 3)

    Returns:
        List of result dicts, sorted by relevance score, with source tagged.
        Each dict has: source, id, name/title, text, metadata, distance
    """
    results = []

    # Search MITRE techniques
    try:
        mitre_results = _search_mitre(query, n_results)
        results.extend(mitre_results)
    except RuntimeError as e:
        print(f"[warn] MITRE search unavailable: {e}")

    # Search NVD CVEs
    try:
        nvd_results = _search_nvd(query, n_results)
        results.extend(nvd_results)
    except RuntimeError as e:
        print(f"[warn] NVD search unavailable: {e}")

    # Sort by distance (lower = more similar)
    results.sort(key=lambda x: x.get("distance", 999))

    return results


def query_mitre_only(query: str, n_results: int = 5) -> list:
    """
    Search only the MITRE ATT&CK collection.
    Used when the agent's map_to_mitre() tool needs technique mapping.

    Args:
        query: Description of the observed behavior
        n_results: Number of techniques to return

    Returns:
        List of matching MITRE techniques with metadata
    """
    return _search_mitre(query, n_results)


def query_cve(cve_id: str = None, query: str = None, n_results: int = 3) -> list:
    """
    Search the NVD CVE collection.
    Used by the agent's check_cve() tool in Phase 3.

    Args:
        cve_id: Specific CVE ID (e.g. "CVE-2021-44228") — exact lookup
        query:  Natural language query if no specific CVE ID
        n_results: Number of results

    Returns:
        List of matching CVE entries with metadata
    """
    if cve_id:
        return _lookup_cve_by_id(cve_id)
    elif query:
        return _search_nvd(query, n_results)
    else:
        raise ValueError("Provide either cve_id or query")


def query_by_technique_id(technique_id: str) -> Optional[dict]:
    """
    Exact lookup by MITRE technique ID (e.g. "T1110").
    Used when Wazuh alert already has a mitre_hint populated.

    Args:
        technique_id: ATT&CK technique ID string

    Returns:
        Single technique dict, or None if not found
    """
    collection = _get_collection(MITRE_COLLECTION)

    try:
        result = collection.get(
            ids=[technique_id],
            include=["documents", "metadatas"]
        )
        if result["ids"] and result["ids"][0]:
            return {
                "source": "MITRE ATT&CK",
                "id": result["ids"][0],
                "name": result["metadatas"][0].get("technique_name", "Unknown"),
                "text": result["documents"][0],
                "metadata": result["metadatas"][0]
            }
    except Exception:
        pass

    return None


# ─────────────────────────────────────────────────────────
# INTERNAL SEARCH HELPERS
# ─────────────────────────────────────────────────────────

def _search_mitre(query: str, n_results: int) -> list:
    """Internal: semantic search over MITRE techniques."""
    collection = _get_collection(MITRE_COLLECTION)
    count = collection.count()

    if count == 0:
        raise RuntimeError("MITRE collection is empty. Run ingest_mitre.py.")

    actual_n = min(n_results, count)

    raw = collection.query(
        query_texts=[query],
        n_results=actual_n,
        include=["documents", "metadatas", "distances"]
    )

    results = []
    for i in range(len(raw["ids"][0])):
        results.append({
            "source": "MITRE ATT&CK",
            "id": raw["ids"][0][i],
            "name": raw["metadatas"][0][i].get("technique_name", "Unknown"),
            "text": raw["documents"][0][i][:500],  # truncate for readability
            "metadata": raw["metadatas"][0][i],
            "distance": raw["distances"][0][i]
        })

    return results


def _search_nvd(query: str, n_results: int) -> list:
    """Internal: semantic search over NVD CVEs."""
    collection = _get_collection(NVD_COLLECTION)
    count = collection.count()

    if count == 0:
        raise RuntimeError("NVD collection is empty. Run ingest_nvd.py.")

    actual_n = min(n_results, count)

    raw = collection.query(
        query_texts=[query],
        n_results=actual_n,
        include=["documents", "metadatas", "distances"]
    )

    results = []
    for i in range(len(raw["ids"][0])):
        results.append({
            "source": "NVD CVE",
            "id": raw["ids"][0][i],
            "name": raw["ids"][0][i],  # CVE ID is the name
            "text": raw["documents"][0][i][:500],
            "metadata": raw["metadatas"][0][i],
            "distance": raw["distances"][0][i]
        })

    return results


def _lookup_cve_by_id(cve_id: str) -> list:
    """Internal: exact CVE ID lookup."""
    collection = _get_collection(NVD_COLLECTION)

    try:
        result = collection.get(
            ids=[cve_id],
            include=["documents", "metadatas"]
        )
        if result["ids"] and result["ids"][0]:
            return [{
                "source": "NVD CVE",
                "id": result["ids"][0],
                "name": result["ids"][0],
                "text": result["documents"][0],
                "metadata": result["metadatas"][0],
                "distance": 0.0  # exact match
            }]
    except Exception:
        pass

    return []


# ─────────────────────────────────────────────────────────
# FORMATTING HELPER (used by agent to build context string)
# ─────────────────────────────────────────────────────────

def format_results_for_llm(results: list) -> str:
    """
    Format RAG results into a clean string for injection into
    the LLM prompt. Called by the agent before sending context
    to Mistral for triage reasoning.

    Args:
        results: Output from query_threat_intel()

    Returns:
        Formatted string ready to embed in a prompt
    """
    if not results:
        return "No relevant threat intelligence found."

    lines = ["RELEVANT THREAT INTELLIGENCE CONTEXT:", "=" * 50]

    for i, r in enumerate(results, start=1):
        lines.append(f"\n[{i}] Source: {r['source']} | ID: {r['id']} | {r['name']}")
        lines.append(f"    Relevance score: {1 - r.get('distance', 1):.2f}")
        if r.get("metadata"):
            meta = r["metadata"]
            if r["source"] == "MITRE ATT&CK":
                lines.append(f"    Tactics: {meta.get('tactics', 'N/A')}")
                lines.append(f"    Platforms: {meta.get('platforms', 'N/A')}")
                lines.append(f"    Known threat groups: {meta.get('threat_groups', 'none')}")
            elif r["source"] == "NVD CVE":
                lines.append(f"    Severity: {meta.get('severity', 'N/A')} "
                             f"(CVSS: {meta.get('cvss_score', 'N/A')})")
                lines.append(f"    Affected: {meta.get('affected_products', 'N/A')}")
        lines.append(f"    Details: {r['text'][:300]}...")

    return "\n".join(lines)


# ─────────────────────────────────────────────────────────
# STANDALONE USAGE
# ─────────────────────────────────────────────────────────
if __name__ == "__main__":
    if len(sys.argv) > 1:
        user_query = " ".join(sys.argv[1:])
    else:
        user_query = "SSH brute force authentication failures"

    print(f"\nQuerying threat intel for: '{user_query}'\n")
    print("=" * 60)

    results = query_threat_intel(user_query, n_results=3)
    print(format_results_for_llm(results))
