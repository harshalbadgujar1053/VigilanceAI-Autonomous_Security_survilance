"""
ingest_mitre.py — Phase 2: MITRE ATT&CK → ChromaDB
-----------------------------------------------------
Project: VigilanceAI — Autonomous Security Surveillance

Reads the full MITRE ATT&CK Enterprise STIX bundle (enterprise-attack.json)
and ingests all attack-pattern objects (techniques + sub-techniques) into
a ChromaDB collection with rich metadata for semantic search.

What this script does:
  1. Loads enterprise-attack.json from datasets/
  2. Extracts all attack-pattern objects (625+ techniques)
  3. Builds a rich text document per technique for embedding
  4. Extracts metadata: technique_id, name, tactics, platforms
  5. Ingests in batches into ChromaDB collection "mitre_techniques"
  6. Maps technique → group relationships (APT28, Lazarus Group, etc.)

Run:
    cd ~/VigilanceAI-Autonomous_Security_survilance
    python3 rag/ingest_mitre.py

Output:
    rag/chroma_db/   — persistent ChromaDB store
"""

import json
import os
import sys
import time
import chromadb
from chromadb.utils import embedding_functions

# ─────────────────────────────────────────────────────────
# PATHS
# ─────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STIX_PATH = os.path.join(BASE_DIR, "datasets", "enterprise-attack.json")
CHROMA_PATH = os.path.join(BASE_DIR, "rag", "chroma_db")

COLLECTION_NAME = "mitre_techniques"
BATCH_SIZE = 50  # ChromaDB performs best with batches of 50-100


# ─────────────────────────────────────────────────────────
# CHROMADB CLIENT + EMBEDDING FUNCTION
# ─────────────────────────────────────────────────────────
def get_client_and_collection():
    """
    Creates a persistent ChromaDB client and returns the
    mitre_techniques collection (creates it if it doesn't exist).

    Uses all-MiniLM-L6-v2 — a lightweight, fast embedding model
    that runs locally. Good balance of speed and quality for
    semantic similarity over security text.
    """
    client = chromadb.PersistentClient(path=CHROMA_PATH)

    embed_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
        model_name="all-MiniLM-L6-v2"
    )

    collection = client.get_or_create_collection(
        name=COLLECTION_NAME,
        embedding_function=embed_fn,
        metadata={"description": "MITRE ATT&CK Enterprise techniques v14"}
    )

    return client, collection


# ─────────────────────────────────────────────────────────
# STIX PARSING HELPERS
# ─────────────────────────────────────────────────────────
def load_stix_bundle(path: str) -> dict:
    """Load the raw STIX JSON bundle."""
    print(f"[info] Loading STIX bundle from {path} ...")
    with open(path, "r", encoding="utf-8") as f:
        bundle = json.load(f)
    print(f"[info] Bundle contains {len(bundle.get('objects', []))} total objects")
    return bundle


def build_object_index(bundle: dict) -> dict:
    """
    Build a lookup dict: stix_id → object
    Used to resolve relationships (technique → tactic, group → technique)
    """
    return {obj["id"]: obj for obj in bundle.get("objects", [])}


def extract_technique_id(obj: dict) -> str:
    """Extract the ATT&CK technique ID (e.g. T1110) from external_references."""
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id", "UNKNOWN")
    return "UNKNOWN"


def extract_tactics(obj: dict) -> list:
    """
    Extract tactic names from kill_chain_phases.
    MITRE uses 'mitre-attack' kill chain with phase names like
    'credential-access', 'initial-access', etc.
    """
    tactics = []
    for phase in obj.get("kill_chain_phases", []):
        if phase.get("kill_chain_name") == "mitre-attack":
            tactics.append(phase.get("phase_name", "unknown").replace("-", " ").title())
    return tactics


def extract_platforms(obj: dict) -> list:
    """Extract target platforms (Windows, Linux, macOS, Cloud, etc.)"""
    return obj.get("x_mitre_platforms", [])


def extract_data_sources(obj: dict) -> list:
    """Extract data sources useful for detection (Process monitoring, etc.)"""
    return obj.get("x_mitre_data_sources", [])


def build_technique_document(obj: dict) -> str:
    """
    Build a rich text string for embedding.
    The quality of this text directly determines how well
    semantic search works — more context = better retrieval.

    Structure:
      Technique ID + Name
      Tactics (which phase of the attack lifecycle)
      Platforms (what OS/environment is targeted)
      Full description
      Detection data sources
    """
    technique_id = extract_technique_id(obj)
    name = obj.get("name", "Unknown")
    description = obj.get("description", "No description available")
    tactics = extract_tactics(obj)
    platforms = extract_platforms(obj)
    data_sources = extract_data_sources(obj)

    # Clean up markdown links from MITRE descriptions
    # e.g. [Valid Accounts](https://...) → Valid Accounts
    import re
    description = re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', description)

    doc = f"""MITRE ATT&CK Technique: {technique_id} — {name}

Tactics: {', '.join(tactics) if tactics else 'Unknown'}
Platforms: {', '.join(platforms) if platforms else 'Unknown'}

Description:
{description[:1500]}

Detection Data Sources: {', '.join(data_sources[:5]) if data_sources else 'Not specified'}
"""
    return doc.strip()


def build_group_technique_map(bundle: dict, obj_index: dict) -> dict:
    """
    Build a mapping: technique_stix_id → [group_names]

    STIX relationship objects connect intrusion-sets (APT groups)
    to attack-patterns (techniques) via 'uses' relationships.
    This lets us answer "what techniques does APT28 use?"
    """
    group_map = {}  # technique_stix_id → [group_name, ...]

    for obj in bundle.get("objects", []):
        if obj.get("type") != "relationship":
            continue
        if obj.get("relationship_type") != "uses":
            continue

        source_id = obj.get("source_ref", "")
        target_id = obj.get("target_ref", "")

        source_obj = obj_index.get(source_id, {})
        target_obj = obj_index.get(target_id, {})

        # We want: intrusion-set USES attack-pattern
        if (source_obj.get("type") == "intrusion-set" and
                target_obj.get("type") == "attack-pattern"):

            group_name = source_obj.get("name", "Unknown Group")
            if target_id not in group_map:
                group_map[target_id] = []
            group_map[target_id].append(group_name)

    return group_map


# ─────────────────────────────────────────────────────────
# MAIN INGESTION
# ─────────────────────────────────────────────────────────
def ingest_mitre(force_reingest: bool = False):
    """
    Main ingestion function.

    Args:
        force_reingest: If True, deletes existing collection and re-ingests.
                        Useful if you want to update with new ATT&CK version.
    """
    if not os.path.exists(STIX_PATH):
        print(f"[error] STIX bundle not found at: {STIX_PATH}")
        print("        Run: python3 datasets/explore_mitre_attack.py  first")
        sys.exit(1)

    client, collection = get_client_and_collection()

    # Check if already ingested
    existing_count = collection.count()
    if existing_count > 0 and not force_reingest:
        print(f"[info] Collection '{COLLECTION_NAME}' already has {existing_count} documents.")
        print("       Pass force_reingest=True to re-ingest, or run test_rag.py to query.")
        return collection

    if force_reingest and existing_count > 0:
        print(f"[info] Force re-ingest: deleting existing {existing_count} documents...")
        client.delete_collection(COLLECTION_NAME)
        _, collection = get_client_and_collection()

    # Load and parse STIX bundle
    bundle = load_stix_bundle(STIX_PATH)
    obj_index = build_object_index(bundle)

    # Extract all attack-pattern objects (techniques + sub-techniques)
    techniques = [
        obj for obj in bundle.get("objects", [])
        if obj.get("type") == "attack-pattern"
        and not obj.get("x_mitre_deprecated", False)  # skip deprecated
        and not obj.get("revoked", False)              # skip revoked
    ]
    print(f"[info] Found {len(techniques)} active techniques/sub-techniques")

    # Build group→technique map for enriched metadata
    print("[info] Building group-technique relationship map...")
    group_map = build_group_technique_map(bundle, obj_index)
    print(f"[info] Mapped techniques to {len(set(g for groups in group_map.values() for g in groups))} threat groups")

    # Prepare documents for ChromaDB
    ids = []
    documents = []
    metadatas = []

    for obj in techniques:
        technique_id = extract_technique_id(obj)
        stix_id = obj.get("id", "")

        if technique_id == "UNKNOWN":
            continue

        # Build the text document for embedding
        doc_text = build_technique_document(obj)

        # Build metadata (stored alongside vectors, searchable/filterable)
        tactics = extract_tactics(obj)
        platforms = extract_platforms(obj)
        groups = group_map.get(stix_id, [])

        metadata = {
            "technique_id": technique_id,
            "technique_name": obj.get("name", "Unknown"),
            "tactics": ", ".join(tactics) if tactics else "unknown",
            "platforms": ", ".join(platforms[:5]) if platforms else "unknown",
            "is_subtechnique": "." in technique_id,  # T1110.001 is a sub-technique
            "threat_groups": ", ".join(groups[:10]) if groups else "none",
            "detection": ", ".join(obj.get("x_mitre_data_sources", [])[:3])
        }

        ids.append(technique_id)
        documents.append(doc_text)
        metadatas.append(metadata)

    # Ingest in batches
    total = len(ids)
    print(f"\n[info] Ingesting {total} techniques into ChromaDB in batches of {BATCH_SIZE}...")
    print("[info] This will take 3-8 minutes (embedding model running locally)...\n")

    start_time = time.time()
    ingested = 0

    for i in range(0, total, BATCH_SIZE):
        batch_ids = ids[i:i + BATCH_SIZE]
        batch_docs = documents[i:i + BATCH_SIZE]
        batch_meta = metadatas[i:i + BATCH_SIZE]

        collection.add(
            ids=batch_ids,
            documents=batch_docs,
            metadatas=batch_meta
        )

        ingested += len(batch_ids)
        elapsed = time.time() - start_time
        pct = (ingested / total) * 100
        print(f"  [{pct:5.1f}%] {ingested}/{total} techniques ingested "
              f"({elapsed:.0f}s elapsed)")

    elapsed_total = time.time() - start_time
    print(f"\n[success] Ingested {collection.count()} techniques in {elapsed_total:.0f}s")
    print(f"[info] ChromaDB stored at: {CHROMA_PATH}")

    return collection


if __name__ == "__main__":
    # Pass --force to re-ingest even if collection already exists
    force = "--force" in sys.argv
    ingest_mitre(force_reingest=force)
