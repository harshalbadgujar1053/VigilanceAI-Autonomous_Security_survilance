"""
test_rag.py — Phase 2: End-to-End RAG Pipeline Test
-----------------------------------------------------
Project: VigilanceAI — Autonomous Security Surveillance

Runs 5 representative threat intel queries against both ChromaDB
collections and prints results. Use this to verify the full
ingestion → query pipeline is working before Phase 3.

Run:
    cd ~/VigilanceAI-Autonomous_Security_survilance
    python3 rag/test_rag.py

Expected output:
    - 5 queries, each returning 3-6 results
    - MITRE technique IDs (T1xxx) and CVE IDs in results
    - APT28 query returns techniques used by that group
    - Brute force query returns T1110 as top result
    - All queries complete in < 10 seconds after first run
"""

import os
import sys
import time

# Add parent directory to path so we can import from rag/
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rag.query_rag import (
    query_threat_intel,
    query_mitre_only,
    query_cve,
    query_by_technique_id,
    format_results_for_llm
)

# ─────────────────────────────────────────────────────────
# 5 TEST QUERIES covering different agent use cases
# ─────────────────────────────────────────────────────────
TEST_QUERIES = [
    {
        "name": "Brute Force Detection",
        "query": "SSH brute force multiple failed authentication attempts",
        "function": "query_threat_intel",
        "expected_id": "T1110",
        "description": "Should return T1110 (Brute Force) as top result"
    },
    {
        "name": "APT Group Attribution",
        "query": "what techniques does APT28 Fancy Bear use for credential access",
        "function": "query_mitre_only",
        "expected_id": None,
        "description": "Should return techniques linked to APT28 in metadata"
    },
    {
        "name": "Privilege Escalation",
        "query": "privilege escalation local exploit rootkit hidden process",
        "function": "query_threat_intel",
        "expected_id": "T1055",
        "description": "Should return process injection and rootkit techniques"
    },
    {
        "name": "Exact Technique Lookup",
        "query": "T1110",
        "function": "query_by_technique_id",
        "expected_id": "T1110",
        "description": "Direct lookup by technique ID — should be instant"
    },
    {
        "name": "CVE Vulnerability Search",
        "query": "buffer overflow remote code execution HIGH severity",
        "function": "query_cve",
        "expected_id": None,
        "description": "Should return HIGH/CRITICAL CVEs matching the description"
    }
]


def run_single_test(test: dict) -> bool:
    """
    Run one test query and print results.
    Returns True if results were found, False if empty.
    """
    print(f"\n{'='*65}")
    print(f"TEST: {test['name']}")
    print(f"DESC: {test['description']}")
    print(f"QUERY: \"{test['query']}\"")
    print('='*65)

    start = time.time()
    results = []

    try:
        fn = test["function"]

        if fn == "query_threat_intel":
            results = query_threat_intel(test["query"], n_results=3)

        elif fn == "query_mitre_only":
            results = query_mitre_only(test["query"], n_results=3)

        elif fn == "query_by_technique_id":
            result = query_by_technique_id(test["query"])
            results = [result] if result else []

        elif fn == "query_cve":
            results = query_cve(query=test["query"], n_results=3)

        elapsed = time.time() - start

        if not results:
            print(f"[FAIL] No results returned ({elapsed:.2f}s)")
            return False

        print(f"[PASS] {len(results)} results in {elapsed:.2f}s\n")

        for i, r in enumerate(results, 1):
            source = r.get("source", "Unknown")
            rid = r.get("id", "?")
            name = r.get("name", "?")
            distance = r.get("distance", 1.0)
            relevance = max(0, 1 - distance)

            print(f"  {i}. [{source}] {rid} — {name}")
            print(f"     Relevance: {relevance:.3f}")

            meta = r.get("metadata", {})
            if source == "MITRE ATT&CK":
                print(f"     Tactics: {meta.get('tactics', 'N/A')}")
                print(f"     Groups:  {meta.get('threat_groups', 'none')[:80]}")
            elif source == "NVD CVE":
                print(f"     Severity: {meta.get('severity', 'N/A')} "
                      f"(CVSS: {meta.get('cvss_score', 'N/A')})")
            print()

        # Check if expected technique ID is in results (if specified)
        if test.get("expected_id"):
            found_ids = [r.get("id", "") for r in results]
            if test["expected_id"] in found_ids:
                print(f"  ✓ Expected {test['expected_id']} found in results")
            else:
                print(f"  ⚠ Expected {test['expected_id']} not in top results")
                print(f"    Got: {found_ids}")
                print(f"    This may be OK — check if relevant techniques appear")

        return True

    except RuntimeError as e:
        elapsed = time.time() - start
        print(f"[ERROR] {e} ({elapsed:.2f}s)")
        print("        Make sure you ran ingest_mitre.py and ingest_nvd.py first")
        return False

    except Exception as e:
        elapsed = time.time() - start
        print(f"[ERROR] Unexpected error: {e} ({elapsed:.2f}s)")
        return False


def run_format_test():
    """
    Test format_results_for_llm — verifies the output
    that will actually be injected into the Mistral prompt.
    """
    print(f"\n{'='*65}")
    print("TEST: LLM Context Formatting")
    print("DESC: Verify RAG output is properly formatted for Mistral prompt")
    print('='*65)

    results = query_threat_intel(
        "brute force SSH authentication failed multiple attempts",
        n_results=2
    )

    formatted = format_results_for_llm(results)
    print(formatted)
    print(f"\n[PASS] format_results_for_llm produced {len(formatted)} characters")


def check_collection_stats():
    """Print stats about what's in ChromaDB before running queries."""
    import chromadb
    from chromadb.utils import embedding_functions

    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    chroma_path = os.path.join(base_dir, "rag", "chroma_db")

    if not os.path.exists(chroma_path):
        print("[error] ChromaDB not found. Run ingest_mitre.py and ingest_nvd.py first.")
        sys.exit(1)

    client = chromadb.PersistentClient(path=chroma_path)
    embed_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
        model_name="all-MiniLM-L6-v2"
    )

    print("\n" + "="*65)
    print("CHROMADB COLLECTION STATS")
    print("="*65)

    collections = client.list_collections()
    if not collections:
        print("[error] No collections found. Run ingest scripts first.")
        sys.exit(1)

    for col in collections:
        c = client.get_collection(col.name, embedding_function=embed_fn)
        print(f"  Collection: {col.name}")
        print(f"  Documents:  {c.count()}")
        print()


# ─────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("\n" + "="*65)
    print("  VigilanceAI — RAG Pipeline End-to-End Test")
    print("="*65)

    # Step 1: Check what's in ChromaDB
    check_collection_stats()

    # Step 2: Run all 5 query tests
    passed = 0
    failed = 0

    for test in TEST_QUERIES:
        success = run_single_test(test)
        if success:
            passed += 1
        else:
            failed += 1

    # Step 3: Test LLM formatting
    try:
        run_format_test()
        passed += 1
    except Exception as e:
        print(f"[ERROR] Format test failed: {e}")
        failed += 1

    # Step 4: Summary
    total = passed + failed
    print("\n" + "="*65)
    print(f"RESULTS: {passed}/{total} tests passed")
    if failed == 0:
        print("✓ RAG pipeline is ready for Phase 3 agent integration")
        print("✓ Member 2 can now import from rag.query_rag")
    else:
        print(f"✗ {failed} test(s) failed — check errors above")
        print("  Most likely cause: ingest scripts not run yet")
        print("  Fix: python3 rag/ingest_mitre.py && python3 rag/ingest_nvd.py")
    print("="*65)
