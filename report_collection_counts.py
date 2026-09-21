"""
report_collection_counts.py

Prints exact document counts per ChromaDB collection, plus a few
cross-source mapping statistics, so you can cite precise numbers in the
VigilanceAI paper's dataset/methodology section.

Run from the project root:
    python3 report_collection_counts.py
"""

import chromadb
from chromadb.utils import embedding_functions

CHROMA_PATH = "./chroma_db"


def pct(n, total):
    return f"{100 * n / total:.1f}%" if total else "N/A"


def main():
    embed_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
        model_name="all-MiniLM-L6-v2"
    )
    client = chromadb.PersistentClient(path=CHROMA_PATH)

    collections = client.list_collections()
    if not collections:
        print("[!] No collections found at", CHROMA_PATH)
        return

    print("=" * 70)
    print("VigilanceAI RAG Knowledge Base — Collection Report")
    print("=" * 70)

    counts = {}
    total_docs = 0
    for c in collections:
        collection = client.get_collection(name=c.name, embedding_function=embed_fn)
        n = collection.count()
        counts[c.name] = n
        total_docs += n

    print(f"\n{'Collection':<22} {'Documents':>10}")
    print("-" * 34)
    for name, n in sorted(counts.items(), key=lambda x: -x[1]):
        print(f"{name:<22} {n:>10,}")
    print("-" * 34)
    print(f"{'TOTAL':<22} {total_docs:>10,}")

    # Cross-source mapping stats (only computed for collections that exist)
    print("\n" + "=" * 70)
    print("Cross-Source Mapping Statistics")
    print("=" * 70)

    if "nvd_cves" in counts:
        c = client.get_collection("nvd_cves", embedding_function=embed_fn)
        data = c.get(include=["metadatas"])
        n = counts["nvd_cves"]
        with_cwe = sum(1 for m in data["metadatas"] if m.get("cwe_ids"))
        print(f"\nnvd_cves ({n} total):")
        print(f"  Mapped to >=1 CWE: {with_cwe} ({pct(with_cwe, n)})")

    if "capec_patterns" in counts:
        c = client.get_collection("capec_patterns", embedding_function=embed_fn)
        data = c.get(include=["metadatas"])
        n = counts["capec_patterns"]
        with_attack = sum(1 for m in data["metadatas"] if m.get("attack_technique_ids"))
        with_cwe = sum(1 for m in data["metadatas"] if m.get("cwe_ids"))
        print(f"\ncapec_patterns ({n} total):")
        print(f"  Mapped to >=1 ATT&CK technique: {with_attack} ({pct(with_attack, n)})")
        print(f"  Mapped to >=1 CWE: {with_cwe} ({pct(with_cwe, n)})")

    if "cwe_weaknesses" in counts:
        c = client.get_collection("cwe_weaknesses", embedding_function=embed_fn)
        data = c.get(include=["metadatas"])
        n = counts["cwe_weaknesses"]
        with_capec = sum(1 for m in data["metadatas"] if m.get("related_capec_ids"))
        with_cwe = sum(1 for m in data["metadatas"] if m.get("related_cwe_ids"))
        print(f"\ncwe_weaknesses ({n} total):")
        print(f"  Mapped to >=1 CAPEC pattern: {with_capec} ({pct(with_capec, n)})")
        print(f"  Mapped to >=1 related CWE: {with_cwe} ({pct(with_cwe, n)})")

    print("\n" + "=" * 70)
    print(f"Grand total across all {len(counts)} collections: {total_docs:,} documents")
    print("=" * 70)


if __name__ == "__main__":
    main()
