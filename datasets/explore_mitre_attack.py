"""
explore_mitre_attack.py
Downloads the MITRE ATT&CK Enterprise STIX 2.1 bundle and prints
10 sample technique entries to inspect the data structure before
building the RAG ingestion pipeline in Phase 2.
"""

import json
import urllib.request
import os

STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)

OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "enterprise-attack.json")


def download_stix_bundle(url, out_path):
    if os.path.exists(out_path):
        print(f"[info] Bundle already exists at {out_path}, skipping download.")
        return
    print(f"[info] Downloading MITRE ATT&CK STIX bundle...")
    urllib.request.urlretrieve(url, out_path)
    print(f"[info] Saved to {out_path}")


def load_techniques(path, limit=10):
    with open(path, "r", encoding="utf-8") as f:
        bundle = json.load(f)
    objects = bundle.get("objects", [])
    techniques = [obj for obj in objects if obj.get("type") == "attack-pattern"]
    return techniques[:limit]


def print_sample(techniques):
    print(f"\n=== Showing {len(techniques)} sample ATT&CK techniques ===\n")
    for i, tech in enumerate(techniques, start=1):
        name = tech.get("name", "Unknown")
        description = tech.get("description", "")[:200].replace("\n", " ")
        ext_refs = tech.get("external_references", [])
        technique_id = next(
            (ref.get("external_id") for ref in ext_refs
             if ref.get("source_name") == "mitre-attack"),
            "N/A"
        )
        print(f"{i}. [{technique_id}] {name}")
        print(f"   {description}...\n")


if __name__ == "__main__":
    download_stix_bundle(STIX_URL, OUTPUT_FILE)
    sample_techniques = load_techniques(OUTPUT_FILE, limit=10)
    print_sample(sample_techniques)
