"""
rag_setup.py — ChromaDB RAG Pipeline (Phase 1 scaffolding)
------------------------------------------------------------
Project: Vigilance AI

Sets up ChromaDB with sample MITRE ATT&CK technique docs.
In Phase 2+, you'll load the real MITRE/CVE datasets.

This file teaches you:
  1. How to create a ChromaDB collection
  2. How to add documents (MITRE techniques)
  3. How to query it semantically

Run:
    python rag_setup.py
"""

import chromadb
from chromadb.utils import embedding_functions


# ─────────────────────────────────────────────
# 1. INITIALIZE CHROMADB
#    PersistentClient stores the DB on disk so
#    you don't re-index every time you run.
# ─────────────────────────────────────────────
def get_chroma_client():
    client = chromadb.PersistentClient(path="./chroma_db")
    return client


# ─────────────────────────────────────────────
# 2. EMBEDDING FUNCTION
#    Converts text -> vector numbers, runs locally.
# ─────────────────────────────────────────────
def get_embedding_fn():
    return embedding_functions.SentenceTransformerEmbeddingFunction(
        model_name="all-MiniLM-L6-v2"
    )


# ─────────────────────────────────────────────
# 3. SAMPLE MITRE ATT&CK DOCUMENTS
# ─────────────────────────────────────────────
SAMPLE_MITRE_DOCS = [
    {
        "id": "T1110",
        "technique": "Brute Force",
        "text": """T1110 - Brute Force
Adversaries may use brute force techniques to gain access to accounts.
This involves trying many passwords or passphrases with the hope of eventually
guessing correctly. Brute force commonly manifests as repeated failed login
attempts. Indicators: high volume of authentication failures from a single
source IP, attempts across multiple usernames, short time intervals between
attempts. Mitigation: account lockout policies, MFA, IP rate limiting."""
    },
    {
        "id": "T1021",
        "technique": "Remote Services",
        "text": """T1021 - Remote Services (SSH)
Adversaries may use valid accounts to log into a service specifically designed
to accept remote connections, such as telnet, SSH, and VNC. SSH brute force
is a precursor to this technique."""
    },
    {
        "id": "T1078",
        "technique": "Valid Accounts",
        "text": """T1078 - Valid Accounts
Adversaries may obtain and abuse credentials of existing accounts as a means
of gaining initial access, persistence, or privilege escalation."""
    },
    {
        "id": "T1055",
        "technique": "Process Injection",
        "text": """T1055 - Process Injection
Adversaries may inject code into processes to evade process-based defenses
and possibly elevate privileges. Hidden processes that appear in rootkit
scans may indicate this technique."""
    },
    {
        "id": "T1014",
        "technique": "Rootkit",
        "text": """T1014 - Rootkit
Adversaries may use rootkits to hide the presence of programs, files, network
connections, services, drivers, and other system components. Hidden processes
(PIDs not visible in process list) are a key indicator."""
    }
]


# ─────────────────────────────────────────────
# 4. INDEX DOCUMENTS
# ─────────────────────────────────────────────
def setup_threat_intel_collection():
    client = get_chroma_client()
    embed_fn = get_embedding_fn()

    collection = client.get_or_create_collection(
        name="mitre_techniques",
        embedding_function=embed_fn,
        metadata={"description": "MITRE ATT&CK technique descriptions"}
    )

    if collection.count() == 0:
        print("Indexing MITRE technique documents into ChromaDB...")
        collection.add(
            ids=[doc["id"] for doc in SAMPLE_MITRE_DOCS],
            documents=[doc["text"] for doc in SAMPLE_MITRE_DOCS],
            metadatas=[{"technique": doc["technique"]} for doc in SAMPLE_MITRE_DOCS]
        )
        print(f"Indexed {len(SAMPLE_MITRE_DOCS)} MITRE techniques")
    else:
        print(f"Collection already has {collection.count()} documents")

    return collection


# ─────────────────────────────────────────────
# 5. QUERY FUNCTION (used by your agent later)
# ─────────────────────────────────────────────
def query_threat_intel(alert_description: str, n_results: int = 3) -> list:
    collection = setup_threat_intel_collection()

    results = collection.query(
        query_texts=[alert_description],
        n_results=n_results
    )

    docs = []
    for i, doc_text in enumerate(results["documents"][0]):
        docs.append({
            "technique_id": results["ids"][0][i],
            "technique_name": results["metadatas"][0][i]["technique"],
            "text": doc_text
        })
    return docs


# ─────────────────────────────────────────────
# 6. DEMO
# ─────────────────────────────────────────────
if __name__ == "__main__":
    print("Setting up ChromaDB threat intel collection...")
    setup_threat_intel_collection()

    test_query = "SSH brute force multiple failed authentication attempts"
    print(f"\nQuerying for: '{test_query}'\n")

    results = query_threat_intel(test_query)
    for r in results:
        print(f"[{r['technique_id']}] {r['technique_name']}")
        print(f"  -> {r['text'][:120]}...\n")
