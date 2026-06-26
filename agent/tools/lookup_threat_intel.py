"""
lookup_threat_intel.py — Tool 1 for Vigilance AI ReAct Agent
-------------------------------------------------------------
Searches the 697-technique MITRE ATT&CK ChromaDB collection
for techniques matching a given indicator or description.

The agent calls this when it needs to understand what attack
technique an alert might be related to.
"""

import chromadb
from chromadb.utils import embedding_functions
from langchain.tools import tool


# ─────────────────────────────────────────────
# ChromaDB connection (reuses Phase 2 collection)
# ─────────────────────────────────────────────
def get_collection():
    client = chromadb.PersistentClient(
        path="/home/kali/vigilance-ai/agent/chroma_db"
    )
    embed_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
        model_name="all-MiniLM-L6-v2"
    )
    return client.get_collection(
        name="mitre_techniques",
        embedding_function=embed_fn
    )


# ─────────────────────────────────────────────
# THE TOOL
# The docstring is critical — the agent reads it
# to decide when to call this function.
# ─────────────────────────────────────────────
@tool
def lookup_threat_intel(query: str) -> str:
    """
    Search the MITRE ATT&CK threat intelligence database for
    attack techniques related to a given description, indicator
    of compromise, or attack pattern.

    Use this tool when you need to:
    - Identify what MITRE technique an alert corresponds to
    - Understand how a specific attack works
    - Find related attack patterns for an indicator

    Args:
        query: A description of the attack, suspicious activity,
               or indicator of compromise to search for.
               Example: "failed SSH login attempts from external IP"
               Example: "hidden process not visible in process list"

    Returns:
        Top 3 matching MITRE ATT&CK techniques with IDs,
        names, and descriptions.
    """
    try:
        collection = get_collection()

        results = collection.query(
            query_texts=[query],
            n_results=3
        )

        if not results["ids"][0]:
            return "No matching MITRE techniques found."

        output_lines = [
            f"Top MITRE ATT&CK techniques matching '{query}':\n"
        ]

        for i, technique_id in enumerate(results["ids"][0]):
            name = results["metadatas"][0][i]["technique"]
            text = results["documents"][0][i]
            # First 200 chars of description
            short_desc = text[:200].replace("\n", " ")
            output_lines.append(
                f"{i+1}. [{technique_id}] {name}\n"
                f"   {short_desc}...\n"
            )

        return "\n".join(output_lines)

    except Exception as e:
        return f"Error querying threat intel: {str(e)}"


# ─────────────────────────────────────────────
# Test it directly
# ─────────────────────────────────────────────
if __name__ == "__main__":
    # Test 1: brute force
    print("TEST 1:", lookup_threat_intel.invoke(
        "multiple failed SSH login attempts brute force"
    ))
    print("─" * 50)

    # Test 2: rootkit
    print("TEST 2:", lookup_threat_intel.invoke(
        "hidden process rootkit kernel"
    ))
