"""
migrate_mitre_to_root_chromadb.py

One-time migration: copies the 'mitre_techniques' collection from
rag/chroma_db into the project root's ./chroma_db, so all four collections
(mitre_techniques, nvd_cves, capec_patterns, cwe_weaknesses) live in the
same ChromaDB store.

Run this ONCE from the project root:
    python migrate_mitre_to_root_chromadb.py

Safe to re-run: uses upsert, so re-running just overwrites with identical data.
Does NOT delete or modify rag/chroma_db — that store is left untouched in
case you want to roll back.
"""

import chromadb
from chromadb.utils import embedding_functions

SOURCE_PATH = "./rag/chroma_db"
DEST_PATH = "./chroma_db"
COLLECTION_NAME = "mitre_techniques"
BATCH_SIZE = 200


def main():
    embed_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
        model_name="all-MiniLM-L6-v2"
    )

    print(f"[*] Connecting to source store: {SOURCE_PATH}")
    source_client = chromadb.PersistentClient(path=SOURCE_PATH)
    source_collection = source_client.get_collection(
        name=COLLECTION_NAME, embedding_function=embed_fn
    )
    source_count = source_collection.count()
    print(f"[*] Source '{COLLECTION_NAME}' has {source_count} documents")

    print(f"[*] Fetching all documents, metadatas, and embeddings from source...")
    data = source_collection.get(include=["documents", "metadatas", "embeddings"])
    ids = data["ids"]
    documents = data["documents"]
    metadatas = data["metadatas"]
    embeddings = data["embeddings"]
    print(f"[*] Fetched {len(ids)} records")

    print(f"[*] Connecting to destination store: {DEST_PATH}")
    dest_client = chromadb.PersistentClient(path=DEST_PATH)
    dest_collection = dest_client.get_or_create_collection(
        name=COLLECTION_NAME,
        embedding_function=embed_fn,
        metadata={"description": "MITRE ATT&CK Enterprise techniques", "source": "MITRE ATT&CK STIX"},
    )

    print(f"[*] Upserting {len(ids)} records into destination in batches of {BATCH_SIZE}...")
    for i in range(0, len(ids), BATCH_SIZE):
        dest_collection.upsert(
            ids=ids[i:i + BATCH_SIZE],
            documents=documents[i:i + BATCH_SIZE],
            metadatas=metadatas[i:i + BATCH_SIZE],
            embeddings=embeddings[i:i + BATCH_SIZE],
        )
        print(f"  upserted {min(i + BATCH_SIZE, len(ids))}/{len(ids)}")

    dest_count = dest_collection.count()
    print(f"[+] Done. Destination '{COLLECTION_NAME}' now has {dest_count} documents.")

    if dest_count != source_count:
        print(f"[!] WARNING: destination count ({dest_count}) != source count "
              f"({source_count}). Investigate before relying on this migration.")
    else:
        print(f"[+] Counts match ({source_count} == {dest_count}). Migration verified.")


if __name__ == "__main__":
    main()
