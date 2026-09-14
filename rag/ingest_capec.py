"""
rag/ingest_capec.py

Pulls MITRE CAPEC (Common Attack Pattern Enumeration and Classification)
attack patterns from the official MITRE CTI STIX 2.1 bundle on GitHub, and
ingests them into their own ChromaDB collection ("capec_patterns") using the
same all-MiniLM-L6-v2 embedding function used for mitre_techniques and nvd_cves.

Each CAPEC pattern's STIX external_references are parsed to extract:
  - Mapped MITRE ATT&CK technique IDs (bridges capec_patterns <-> mitre_techniques)
  - Mapped CWE IDs (bridges capec_patterns <-> cwe_weaknesses, once ingested)

Usage:
    python rag/ingest_capec.py
    python rag/ingest_capec.py --limit 50   # smoke-test on a subset first
"""

import argparse
import re
import sys

import requests
import chromadb
from chromadb.utils import embedding_functions

CAPEC_STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/capec/2.1/stix-capec.json"
)
CHROMA_PATH = "./chroma_db"
COLLECTION_NAME = "capec_patterns"
EMBED_MODEL_NAME = "all-MiniLM-L6-v2"

ATTACK_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
CWE_ID_RE = re.compile(r"^CWE-\d+$", re.IGNORECASE)


def fetch_stix_bundle() -> dict:
    print(f"[*] Fetching CAPEC STIX bundle from {CAPEC_STIX_URL} ...")
    resp = requests.get(CAPEC_STIX_URL, timeout=60)
    resp.raise_for_status()
    bundle = resp.json()
    objects = bundle.get("objects", [])
    print(f"[*] Bundle fetched: {len(objects)} total STIX objects")
    return bundle


def extract_capec_id(stix_obj: dict) -> str | None:
    for ref in stix_obj.get("external_references", []):
        if ref.get("source_name") == "capec" and ref.get("external_id"):
            return ref["external_id"]  # e.g. "CAPEC-66"
    return None


def extract_related_ids(stix_obj: dict) -> tuple[list[str], list[str]]:
    """Return (attack_technique_ids, cwe_ids) referenced by this CAPEC pattern."""
    attack_ids, cwe_ids = [], []
    for ref in stix_obj.get("external_references", []):
        ext_id = ref.get("external_id", "")
        source = ref.get("source_name", "")
        if source == "ATTACK" or ATTACK_ID_RE.match(ext_id):
            attack_ids.append(ext_id)
        elif source == "cwe" or CWE_ID_RE.match(ext_id):
            norm = ext_id if ext_id.upper().startswith("CWE-") else f"CWE-{ext_id}"
            cwe_ids.append(norm.upper())
    return sorted(set(attack_ids)), sorted(set(cwe_ids))


def clean_description(desc: str) -> str:
    # CAPEC descriptions sometimes embed literal HTML like <xhtml:p>
    desc = re.sub(r"</?xhtml:[a-zA-Z0-9]+>", " ", desc)
    desc = re.sub(r"\s+", " ", desc).strip()
    return desc


def build_record(stix_obj: dict) -> dict | None:
    if stix_obj.get("type") != "attack-pattern":
        return None
    # STIX marks deprecated/revoked entries; skip them for a clean corpus
    if stix_obj.get("x_capec_status", "").lower() == "deprecated":
        return None
    if stix_obj.get("revoked"):
        return None

    capec_id = extract_capec_id(stix_obj)
    name = stix_obj.get("name")
    if not capec_id or not name:
        return None

    description = clean_description(stix_obj.get("description", ""))
    if not description:
        return None

    severity = stix_obj.get("x_capec_typical_severity", "Unknown")
    likelihood = stix_obj.get("x_capec_likelihood_of_attack", "Unknown")
    attack_ids, cwe_ids = extract_related_ids(stix_obj)

    prereqs = stix_obj.get("x_capec_prerequisites", [])
    prereq_text = " ".join(clean_description(p) for p in prereqs) if prereqs else ""

    doc_text = (
        f"{capec_id}: {name}\n"
        f"{description}\n"
        f"Typical severity: {severity}. Likelihood of attack: {likelihood}.\n"
        f"Mapped MITRE ATT&CK techniques: "
        f"{', '.join(attack_ids) if attack_ids else 'none listed'}\n"
        f"Mapped weaknesses: {', '.join(cwe_ids) if cwe_ids else 'none listed'}"
    )
    if prereq_text:
        doc_text += f"\nPrerequisites: {prereq_text}"

    metadata = {
        "capec_id": capec_id,
        "name": name,
        "severity": severity,
        "likelihood": likelihood,
        "attack_technique_ids": ", ".join(attack_ids) if attack_ids else "",
        "cwe_ids": ", ".join(cwe_ids) if cwe_ids else "",
        "source": "CAPEC",
    }
    return {"id": capec_id, "text": doc_text, "metadata": metadata}


def main():
    parser = argparse.ArgumentParser(description="Ingest MITRE CAPEC into ChromaDB")
    parser.add_argument("--limit", type=int, default=None,
                         help="Optional cap on number of patterns ingested (for smoke tests)")
    parser.add_argument("--batch-size", type=int, default=200)
    args = parser.parse_args()

    bundle = fetch_stix_bundle()
    objects = bundle.get("objects", [])

    records = []
    for obj in objects:
        rec = build_record(obj)
        if rec:
            records.append(rec)

    print(f"[*] Valid, non-deprecated attack-pattern records extracted: {len(records)}")

    if args.limit:
        records = records[: args.limit]
        print(f"[*] --limit applied: ingesting {len(records)} records")

    if not records:
        print("[!] No records extracted. Check the STIX bundle structure/URL.")
        sys.exit(1)

    mapped_to_attack = sum(1 for r in records if r["metadata"]["attack_technique_ids"])
    mapped_to_cwe = sum(1 for r in records if r["metadata"]["cwe_ids"])
    print(f"[*] Records mapped to >=1 ATT&CK technique: {mapped_to_attack}")
    print(f"[*] Records mapped to >=1 CWE: {mapped_to_cwe}")

    print(f"[*] Loading embedding function ({EMBED_MODEL_NAME})...")
    embed_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
        model_name=EMBED_MODEL_NAME
    )

    client = chromadb.PersistentClient(path=CHROMA_PATH)
    collection = client.get_or_create_collection(
        name=COLLECTION_NAME,
        embedding_function=embed_fn,
        metadata={"description": "MITRE CAPEC attack patterns", "source": "MITRE CTI STIX 2.1"},
    )

    print(f"[*] Upserting {len(records)} records into '{COLLECTION_NAME}' "
          f"in batches of {args.batch_size}...")
    for i in range(0, len(records), args.batch_size):
        batch = records[i:i + args.batch_size]
        collection.upsert(
            ids=[r["id"] for r in batch],
            documents=[r["text"] for r in batch],
            metadatas=[r["metadata"] for r in batch],
        )
        print(f"  upserted {min(i + args.batch_size, len(records))}/{len(records)}")

    final_count = collection.count()
    print(f"[+] Done. '{COLLECTION_NAME}' collection now has {final_count} documents.")


if __name__ == "__main__":
    main()
