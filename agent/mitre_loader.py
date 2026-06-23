"""
mitre_loader.py — Load full MITRE ATT&CK dataset into ChromaDB
---------------------------------------------------------------
Project: Vigilance AI

Reads datasets/enterprise-attack.json (STIX 2.0 format),
extracts all attack techniques, and indexes them into ChromaDB
so your RAG pipeline can search hundreds of real techniques
instead of the 5 hand-written samples from Phase 1.

Run:
    cd ~/vigilance-ai/agent
    python mitre_loader.py
"""

import json
import os
import sys
import chromadb
from chromadb.utils import embedding_functions


# ─────────────────────────────────────────────
# 1. PATHS
# ─────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_PATH = os.path.join(BASE_DIR, "datasets", "enterprise-attack.json")
CHROMA_PATH = os.path.join(BASE_DIR, "agent", "chroma_db")


# ─────────────────────────────────────────────
# 2. PARSE MITRE STIX FILE
#    The STIX format wraps everything in "objects"
#    We only want type="attack-pattern" entries
#    (those are the actual techniques like T1110)
# ─────────────────────────────────────────────
def parse_mitre_techniques(filepath: str) -> list[dict]:
    """
    Reads the STIX JSON and extracts only attack techniques.
    Returns a list of dicts with id, name, description.
    """
    print(f"Reading MITRE dataset from {filepath}...")

    with open(filepath, "r", encoding="utf-8") as f:
        stix_data = json.load(f)

    techniques = []

    for obj in stix_data.get("objects", []):

        # Only process attack techniques, skip everything else
        if obj.get("type") != "attack-pattern":
            continue

        # Skip deprecated or revoked techniques
        if obj.get("revoked", False) or obj.get("x_mitre_deprecated", False):
            continue

        # Extract the MITRE technique ID (e.g. T1110)
        technique_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id")
                break

        # Skip if no ID found or it's a sub-technique (has a dot like T1110.001)
        # We load sub-techniques too — they're valuable for RAG
        if not technique_id:
            continue

        name = obj.get("name", "Unknown")
        description = obj.get("description", "No description available")

        # Build a rich text document for embedding
        # The more context here, the better the semantic search
        doc_text = f"""{technique_id} - {name}

Description: {description}

Detection: {obj.get('x_mitre_detection', 'No detection guidance available')}
"""

        techniques.append({
            "id": technique_id,
            "name": name,
            "text": doc_text
        })

    print(f"Extracted {len(techniques)} techniques from MITRE dataset")
    return techniques


# ─────────────────────────────────────────────
# 3. INDEX INTO CHROMADB
# ─────────────────────────────────────────────
def index_mitre_techniques(techniques: list[dict]):
    """
    Indexes all extracted techniques into ChromaDB.
    Uses the same embedding model as your Phase 1 rag_setup.py
    so they're compatible.
    """
    client = chromadb.PersistentClient(path=CHROMA_PATH)

    embed_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
        model_name="all-MiniLM-L6-v2"
    )

    # Delete old 5-sample collection and replace with full dataset
    try:
        client.delete_collection("mitre_techniques")
        print("Deleted old 5-sample collection")
    except Exception:
        pass

    collection = client.create_collection(
        name="mitre_techniques",
        embedding_function=embed_fn,
        metadata={"description": "Full MITRE ATT&CK Enterprise techniques"}
    )

    # ChromaDB has limits on batch size — index in chunks of 100
    batch_size = 100
    total = len(techniques)

    for i in range(0, total, batch_size):
        batch = techniques[i:i + batch_size]
        collection.add(
            ids=[t["id"] for t in batch],
            documents=[t["text"] for t in batch],
            metadatas=[{"technique": t["name"]} for t in batch]
        )
        print(f"Indexed {min(i + batch_size, total)}/{total} techniques...")

    print(f"\nDone — {total} MITRE techniques indexed into ChromaDB")
    return collection


# ─────────────────────────────────────────────
# 4. VERIFY WITH A TEST QUERY
# ─────────────────────────────────────────────
def test_query(collection, query: str, n: int = 3):
    """
    Runs a semantic search to confirm indexing worked.
    """
    print(f"\nTest query: '{query}'")
    results = collection.query(
        query_texts=[query],
        n_results=n
    )
    for i, doc_id in enumerate(results["ids"][0]):
        name = results["metadatas"][0][i]["technique"]
        print(f"  [{doc_id}] {name}")


# ─────────────────────────────────────────────
# 5. MAIN
# ─────────────────────────────────────────────
if __name__ == "__main__":

    if not os.path.exists(DATASET_PATH):
        print(f"ERROR: Dataset not found at {DATASET_PATH}")
        print("Run: curl -L -o datasets/enterprise-attack.json \\")
        print("  https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json")
        sys.exit(1)

    # Parse
    techniques = parse_mitre_techniques(DATASET_PATH)

    if not techniques:
        print("ERROR: No techniques extracted. Check the dataset file.")
        sys.exit(1)

    # Index
    collection = index_mitre_techniques(techniques)

    # Verify with 3 test queries
    test_query(collection, "SSH brute force failed login attempts")
    test_query(collection, "hidden process rootkit detection")
    test_query(collection, "ransomware file encryption")
