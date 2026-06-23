"""
ingest_nvd.py — Phase 2: NVD CVE Feed → ChromaDB
--------------------------------------------------
Project: VigilanceAI — Autonomous Security Surveillance

Reads nvd_sample.json (NVD CVE API response) and ingests CVE entries
into a ChromaDB collection for semantic search by the agent.

In Phase 3, the agent's check_cve() tool will query this collection
when it encounters a CVE ID in a Wazuh alert.

Run:
    cd ~/VigilanceAI-Autonomous_Security_survilance
    python3 rag/ingest_nvd.py

To fetch more CVEs before ingesting:
    python3 datasets/explore_nvd_cve.py   (fetches/caches 10 CVEs)
    # For more CVEs, set NVD_API_KEY and modify resultsPerPage in explore_nvd_cve.py
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
NVD_PATH = os.path.join(BASE_DIR, "datasets", "nvd_sample.json")
CHROMA_PATH = os.path.join(BASE_DIR, "rag", "chroma_db")

COLLECTION_NAME = "nvd_cves"
BATCH_SIZE = 50


# ─────────────────────────────────────────────────────────
# CHROMADB SETUP
# ─────────────────────────────────────────────────────────
def get_client_and_collection():
    client = chromadb.PersistentClient(path=CHROMA_PATH)

    embed_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
        model_name="all-MiniLM-L6-v2"
    )

    collection = client.get_or_create_collection(
        name=COLLECTION_NAME,
        embedding_function=embed_fn,
        metadata={"description": "NVD CVE vulnerability database"}
    )

    return client, collection


# ─────────────────────────────────────────────────────────
# CVE PARSING HELPERS
# ─────────────────────────────────────────────────────────
def extract_english_description(cve: dict) -> str:
    """Get the English description from NVD CVE object."""
    descriptions = cve.get("descriptions", [])
    for d in descriptions:
        if d.get("lang") == "en":
            return d.get("value", "No description available")
    return "No description available"


def extract_severity(cve: dict) -> str:
    """Extract CVSS severity (CRITICAL/HIGH/MEDIUM/LOW/NONE)."""
    metrics = cve.get("metrics", {})

    # Prefer CVSSv3.1 > CVSSv3.0 > CVSSv2
    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if key in metrics and metrics[key]:
            data = metrics[key][0]
            if key.startswith("cvssMetricV3"):
                return data.get("cvssData", {}).get("baseSeverity", "UNKNOWN")
            else:
                return data.get("baseSeverity", "UNKNOWN")

    return "UNKNOWN"


def extract_cvss_score(cve: dict) -> float:
    """Extract numeric CVSS base score (0.0 - 10.0)."""
    metrics = cve.get("metrics", {})

    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if key in metrics and metrics[key]:
            data = metrics[key][0]
            return float(data.get("cvssData", {}).get("baseScore", 0.0))

    return 0.0


def extract_weaknesses(cve: dict) -> list:
    """Extract CWE weakness IDs (e.g. CWE-79 for XSS)."""
    weaknesses = []
    for weakness in cve.get("weaknesses", []):
        for desc in weakness.get("description", []):
            if desc.get("lang") == "en":
                weaknesses.append(desc.get("value", ""))
    return weaknesses


def extract_affected_products(cve: dict) -> list:
    """
    Extract affected CPE configurations (vendor/product names).
    Useful for matching CVEs to software mentioned in Wazuh alerts.
    """
    products = []
    configs = cve.get("configurations", [])

    for config in configs[:3]:  # limit to first 3 config blocks
        for node in config.get("nodes", [])[:5]:
            for cpe_match in node.get("cpeMatch", [])[:3]:
                cpe_name = cpe_match.get("criteria", "")
                # CPE format: cpe:2.3:a:vendor:product:version:...
                parts = cpe_name.split(":")
                if len(parts) >= 5:
                    vendor = parts[3]
                    product = parts[4]
                    if vendor != "*" and product != "*":
                        products.append(f"{vendor} {product}")

    return list(set(products))[:10]


def build_cve_document(cve: dict, cve_id: str) -> str:
    """
    Build a rich text string for embedding.
    Combines the CVE description with severity, weakness type,
    and affected products so semantic search can find it from
    natural language queries like "Apache buffer overflow HIGH".
    """
    description = extract_english_description(cve)
    severity = extract_severity(cve)
    score = extract_cvss_score(cve)
    weaknesses = extract_weaknesses(cve)
    products = extract_affected_products(cve)
    published = cve.get("published", "Unknown")[:10]

    doc = f"""CVE: {cve_id}
Severity: {severity} (CVSS Score: {score})
Published: {published}

Description:
{description}

Weakness Type: {', '.join(weaknesses) if weaknesses else 'Not specified'}
Affected Products: {', '.join(products) if products else 'Not specified'}
"""
    return doc.strip()


# ─────────────────────────────────────────────────────────
# MAIN INGESTION
# ─────────────────────────────────────────────────────────
def ingest_nvd(force_reingest: bool = False):
    """
    Main ingestion function for NVD CVE data.

    Args:
        force_reingest: Delete and re-ingest if True.
    """
    if not os.path.exists(NVD_PATH):
        print(f"[error] NVD sample not found at: {NVD_PATH}")
        print("        Run: python3 datasets/explore_nvd_cve.py  first")
        sys.exit(1)

    client, collection = get_client_and_collection()

    # Check if already ingested
    existing_count = collection.count()
    if existing_count > 0 and not force_reingest:
        print(f"[info] Collection '{COLLECTION_NAME}' already has {existing_count} CVEs.")
        print("       Pass --force to re-ingest.")
        return collection

    if force_reingest and existing_count > 0:
        print(f"[info] Force re-ingest: deleting {existing_count} existing CVEs...")
        client.delete_collection(COLLECTION_NAME)
        _, collection = get_client_and_collection()

    # Load NVD data
    print(f"[info] Loading NVD data from {NVD_PATH} ...")
    with open(NVD_PATH, "r", encoding="utf-8") as f:
        nvd_data = json.load(f)

    vulnerabilities = nvd_data.get("vulnerabilities", [])
    print(f"[info] Found {len(vulnerabilities)} CVE entries to ingest")

    if len(vulnerabilities) == 0:
        print("[warn] No CVEs found in file. Re-run explore_nvd_cve.py to fetch more.")
        return collection

    # Prepare batch
    ids = []
    documents = []
    metadatas = []

    for item in vulnerabilities:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")

        if not cve_id:
            continue

        doc_text = build_cve_document(cve, cve_id)
        severity = extract_severity(cve)
        score = extract_cvss_score(cve)
        products = extract_affected_products(cve)
        weaknesses = extract_weaknesses(cve)

        metadata = {
            "cve_id": cve_id,
            "severity": severity,
            "cvss_score": score,
            "published_date": cve.get("published", "")[:10],
            "affected_products": ", ".join(products[:5]) if products else "unknown",
            "weakness_types": ", ".join(weaknesses[:3]) if weaknesses else "unknown"
        }

        ids.append(cve_id)
        documents.append(doc_text)
        metadatas.append(metadata)

    # Ingest in batches
    total = len(ids)
    print(f"\n[info] Ingesting {total} CVEs into ChromaDB...")

    start_time = time.time()

    for i in range(0, total, BATCH_SIZE):
        collection.add(
            ids=ids[i:i + BATCH_SIZE],
            documents=documents[i:i + BATCH_SIZE],
            metadatas=metadatas[i:i + BATCH_SIZE]
        )

    elapsed = time.time() - start_time
    final_count = collection.count()
    print(f"\n[success] Ingested {final_count} CVEs in {elapsed:.1f}s")
    print(f"[info] ChromaDB stored at: {CHROMA_PATH}")
    print(f"[note] Current sample has {final_count} CVEs.")
    print(f"       To get more CVEs, set NVD_API_KEY env var and")
    print(f"       increase resultsPerPage in datasets/explore_nvd_cve.py")

    return collection


if __name__ == "__main__":
    force = "--force" in sys.argv
    ingest_nvd(force_reingest=force)
