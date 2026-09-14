"""
rag/ingest_cwe.py

Downloads the official MITRE CWE XML database export (Research Concepts /
full catalog), parses weakness entries, and ingests them into their own
ChromaDB collection ("cwe_weaknesses") using the same all-MiniLM-L6-v2
embedding function used for mitre_techniques, nvd_cves, and capec_patterns.

Each CWE entry's Related_Attack_Patterns are extracted to bridge
cwe_weaknesses <-> capec_patterns (CAPEC IDs), closing the three-way
CVE <-> CAPEC <-> CWE grounding loop alongside the cwe_ids fields already
present in nvd_cves and capec_patterns metadata.

Usage:
    python rag/ingest_cwe.py
    python rag/ingest_cwe.py --limit 50   # smoke-test on a subset first
"""

import argparse
import io
import re
import sys
import zipfile

import requests
import chromadb
from chromadb.utils import embedding_functions
from lxml import etree

CWE_ZIP_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
CHROMA_PATH = "./chroma_db"
COLLECTION_NAME = "cwe_weaknesses"
EMBED_MODEL_NAME = "all-MiniLM-L6-v2"

CWE_NS = {"cwe": "http://cwe.mitre.org/cwe-7"}


def fetch_and_extract_xml() -> bytes:
    print(f"[*] Downloading CWE catalog from {CWE_ZIP_URL} ...")
    resp = requests.get(CWE_ZIP_URL, timeout=60)
    resp.raise_for_status()
    print(f"[*] Downloaded {len(resp.content)} bytes, unzipping...")

    with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
        xml_names = [n for n in zf.namelist() if n.endswith(".xml")]
        if not xml_names:
            raise RuntimeError("No .xml file found inside the downloaded zip.")
        xml_name = xml_names[0]
        print(f"[*] Extracting {xml_name} from archive...")
        return zf.read(xml_name)


def text_or_empty(elem) -> str:
    """Flatten all text content of an element (including nested tags like <xhtml:p>)."""
    if elem is None:
        return ""
    parts = [t.strip() for t in elem.itertext() if t and t.strip()]
    return " ".join(parts)


def extract_related_capec_ids(weakness_elem) -> list[str]:
    capec_ids = []
    rel_patterns = weakness_elem.find("cwe:Related_Attack_Patterns", CWE_NS)
    if rel_patterns is not None:
        for rap in rel_patterns.findall("cwe:Related_Attack_Pattern", CWE_NS):
            cid = rap.get("CAPEC_ID")
            if cid:
                capec_ids.append(f"CAPEC-{cid}")
    return sorted(set(capec_ids))


def extract_related_cwe_ids(weakness_elem) -> list[str]:
    related = []
    rel_weaknesses = weakness_elem.find("cwe:Related_Weaknesses", CWE_NS)
    if rel_weaknesses is not None:
        for rw in rel_weaknesses.findall("cwe:Related_Weakness", CWE_NS):
            cwe_id = rw.get("CWE_ID")
            if cwe_id:
                related.append(f"CWE-{cwe_id}")
    return sorted(set(related))


def extract_consequences(weakness_elem) -> str:
    consequences = []
    cc = weakness_elem.find("cwe:Common_Consequences", CWE_NS)
    if cc is not None:
        for cons in cc.findall("cwe:Consequence", CWE_NS):
            scopes = [s.text for s in cons.findall("cwe:Scope", CWE_NS) if s.text]
            impacts = [i.text for i in cons.findall("cwe:Impact", CWE_NS) if i.text]
            if scopes or impacts:
                consequences.append(f"{'/'.join(scopes)}: {', '.join(impacts)}")
    return "; ".join(consequences)


def build_record(weakness_elem) -> dict | None:
    status = weakness_elem.get("Status", "")
    if status.lower() in ("deprecated", "obsolete"):
        return None

    cwe_num = weakness_elem.get("ID")
    name = weakness_elem.get("Name")
    if not cwe_num or not name:
        return None
    cwe_id = f"CWE-{cwe_num}"

    description = text_or_empty(weakness_elem.find("cwe:Description", CWE_NS))
    extended_description = text_or_empty(
        weakness_elem.find("cwe:Extended_Description", CWE_NS)
    )
    if not description and not extended_description:
        return None  # nothing useful to embed

    likelihood = text_or_empty(
        weakness_elem.find("cwe:Likelihood_Of_Exploit", CWE_NS)
    ) or "Unknown"
    abstraction = weakness_elem.get("Abstraction", "Unknown")
    consequences = extract_consequences(weakness_elem)
    related_capec = extract_related_capec_ids(weakness_elem)
    related_cwe = extract_related_cwe_ids(weakness_elem)

    full_description = description
    if extended_description:
        full_description += " " + extended_description
    full_description = re.sub(r"\s+", " ", full_description).strip()

    doc_text = (
        f"{cwe_id}: {name}\n"
        f"{full_description}\n"
        f"Abstraction: {abstraction}. Likelihood of exploit: {likelihood}.\n"
        f"Common consequences: {consequences or 'not specified'}\n"
        f"Related CAPEC attack patterns: "
        f"{', '.join(related_capec) if related_capec else 'none listed'}\n"
        f"Related weaknesses: {', '.join(related_cwe) if related_cwe else 'none listed'}"
    )

    metadata = {
        "cwe_id": cwe_id,
        "name": name,
        "abstraction": abstraction,
        "likelihood": likelihood,
        "related_capec_ids": ", ".join(related_capec) if related_capec else "",
        "related_cwe_ids": ", ".join(related_cwe) if related_cwe else "",
        "source": "CWE",
    }
    return {"id": cwe_id, "text": doc_text, "metadata": metadata}


def main():
    parser = argparse.ArgumentParser(description="Ingest MITRE CWE into ChromaDB")
    parser.add_argument("--limit", type=int, default=None,
                         help="Optional cap on number of weaknesses ingested (for smoke tests)")
    parser.add_argument("--batch-size", type=int, default=200)
    args = parser.parse_args()

    xml_bytes = fetch_and_extract_xml()
    print("[*] Parsing XML...")
    root = etree.fromstring(xml_bytes)

    weaknesses_container = root.find("cwe:Weaknesses", CWE_NS)
    if weaknesses_container is None:
        print("[!] Could not find <Weaknesses> element - check the CWE XML schema/namespace.")
        sys.exit(1)

    weakness_elems = weaknesses_container.findall("cwe:Weakness", CWE_NS)
    print(f"[*] Total <Weakness> entries in catalog: {len(weakness_elems)}")

    records = []
    for elem in weakness_elems:
        rec = build_record(elem)
        if rec:
            records.append(rec)

    print(f"[*] Valid, non-deprecated weakness records extracted: {len(records)}")

    if args.limit:
        records = records[: args.limit]
        print(f"[*] --limit applied: ingesting {len(records)} records")

    if not records:
        print("[!] No records extracted. Check the XML structure/namespace.")
        sys.exit(1)

    mapped_to_capec = sum(1 for r in records if r["metadata"]["related_capec_ids"])
    print(f"[*] Records mapped to >=1 CAPEC pattern: {mapped_to_capec}")

    print(f"[*] Loading embedding function ({EMBED_MODEL_NAME})...")
    embed_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
        model_name=EMBED_MODEL_NAME
    )

    client = chromadb.PersistentClient(path=CHROMA_PATH)
    collection = client.get_or_create_collection(
        name=COLLECTION_NAME,
        embedding_function=embed_fn,
        metadata={"description": "MITRE CWE weaknesses", "source": "MITRE CWE XML export"},
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
