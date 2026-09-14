"""
rag/ingest_nvd.py

Pulls a real CVE corpus from the NVD REST API 2.0, paginates through results,
and ingests them into their own ChromaDB collection ("nvd_cves") using the
same all-MiniLM-L6-v2 embedding function used for mitre_techniques.

Usage:
    export NVD_API_KEY="your-key-here"        # optional but strongly recommended
    python rag/ingest_nvd.py --days 90 --max-results 5000

Notes:
- NVD API 2.0 requires pubStartDate/pubEndDate to be supplied together and
  the span between them cannot exceed 120 days per request. This script
  automatically chunks a larger --days window into <=120-day slices.
- Without an API key you get ~5 requests/30s; with one, ~50 requests/30s.
  The script self-throttles accordingly.
- Re-running is idempotent: CVE IDs are used as Chroma document IDs, so
  upserting the same CVE twice just overwrites it instead of duplicating.
"""

import argparse
import os
import sys
import time
import datetime as dt
from typing import Any

import requests
import chromadb
from chromadb.utils import embedding_functions

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CHROMA_PATH = os.environ.get("VIGILANCE_CHROMA_PATH", "./chroma_db")
COLLECTION_NAME = "nvd_cves"
EMBED_MODEL_NAME = "all-MiniLM-L6-v2"

MAX_SPAN_DAYS = 120  # NVD hard limit per request window


def get_api_key() -> str | None:
    return os.environ.get("NVD_API_KEY")


def throttle_delay(has_key: bool) -> float:
    # Stay comfortably under NVD's published rate limits
    return 0.7 if has_key else 6.5


def chunk_date_ranges(start: dt.datetime, end: dt.datetime, max_days: int):
    """Yield (chunk_start, chunk_end) tuples each <= max_days apart, covering [start, end]."""
    cur = start
    while cur < end:
        chunk_end = min(cur + dt.timedelta(days=max_days), end)
        yield cur, chunk_end
        cur = chunk_end


def _published_dt(vuln_wrapper: dict[str, Any]) -> dt.datetime | None:
    """Extract and parse the 'published' timestamp from a raw NVD vulnerability wrapper."""
    published = vuln_wrapper.get("cve", {}).get("published")
    if not published:
        return None
    try:
        # NVD timestamps look like 2025-09-11T00:15:33.303 (no timezone suffix)
        return dt.datetime.strptime(published[:19], "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return None


def fetch_cves_for_range(
    session: requests.Session,
    api_key: str | None,
    start: dt.datetime,
    end: dt.datetime,
    max_results: int,
) -> list[dict[str, Any]]:
    """Paginate through NVD results for a single date window.

    NOTE: NVD's paginated results are not guaranteed to stay perfectly bounded
    to [start, end] on every page once startIndex moves past the first page
    (observed drift where later pages return CVEs with 'published' dates
    outside the requested window). We defend against this by dropping any
    record whose published date falls outside [start, end] client-side,
    rather than trusting server-side filtering to hold across all pages.
    """
    all_items: list[dict[str, Any]] = []
    dropped_out_of_range = 0
    start_index = 0
    results_per_page = 2000  # NVD max per page
    headers = {"apiKey": api_key} if api_key else {}
    delay = throttle_delay(bool(api_key))
    last_total_results = None

    while True:
        params = {
            "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": results_per_page,
            "startIndex": start_index,
        }
        resp = session.get(NVD_BASE_URL, params=params, headers=headers, timeout=30)
        if resp.status_code == 403:
            print(f"  [!] 403 from NVD (rate limited or bad key). Backing off 30s...")
            time.sleep(30)
            continue
        resp.raise_for_status()
        data = resp.json()

        total_results = data.get("totalResults", 0)
        if last_total_results is not None and total_results != last_total_results:
            print(f"  [!] totalResults shifted mid-pagination: "
                  f"{last_total_results} -> {total_results} "
                  f"(NVD index moved under us; this is expected/known behavior)")
        last_total_results = total_results

        page_vulns = data.get("vulnerabilities", [])
        kept = 0
        for v in page_vulns:
            pub_dt = _published_dt(v)
            if pub_dt is not None and (pub_dt < start or pub_dt > end):
                dropped_out_of_range += 1
                continue
            all_items.append(v)
            kept += 1

        start_index += results_per_page
        print(f"  fetched page (startIndex={start_index - results_per_page}): "
              f"{kept} kept, {len(page_vulns) - kept} out-of-range dropped | "
              f"running total {len(all_items)}/{total_results} for window "
              f"{start.date()} -> {end.date()}")

        if start_index >= total_results or len(all_items) >= max_results:
            break
        time.sleep(delay)

    if dropped_out_of_range:
        print(f"  [*] Total dropped for being outside requested date window: "
              f"{dropped_out_of_range}")

    return all_items[:max_results]


def extract_fields(vuln_wrapper: dict[str, Any]) -> dict[str, Any] | None:
    """Pull the fields we care about out of one NVD 'vulnerabilities[]' entry."""
    cve = vuln_wrapper.get("cve", {})
    cve_id = cve.get("id")
    if not cve_id:
        return None

    descriptions = cve.get("descriptions", [])
    desc_en = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
    if not desc_en:
        return None  # skip CVEs with no English description; not useful for RAG

    # CVSS: prefer v3.1, fall back to v3.0, then v2
    metrics = cve.get("metrics", {})
    cvss_score = None
    cvss_vector = None
    cvss_severity = None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            m = metrics[key][0]
            cvss_data = m.get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            cvss_vector = cvss_data.get("vectorString")
            cvss_severity = m.get("baseSeverity") or cvss_data.get("baseSeverity")
            break

    # CWE mapping (bridges to the cwe_weaknesses collection)
    cwe_ids = []
    for weakness in cve.get("weaknesses", []):
        for d in weakness.get("description", []):
            if d.get("value", "").startswith("CWE-"):
                cwe_ids.append(d["value"])
    cwe_ids = sorted(set(cwe_ids))

    # Affected products (first few CPE URIs, for context only)
    cpe_hints = []
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable") and match.get("criteria"):
                    cpe_hints.append(match["criteria"])
    cpe_hints = cpe_hints[:5]

    published = cve.get("published", "")

    doc_text = (
        f"{cve_id}: {desc_en}\n"
        f"CVSS: {cvss_score if cvss_score is not None else 'N/A'} "
        f"({cvss_severity or 'UNKNOWN'}) - {cvss_vector or 'N/A'}\n"
        f"Related weaknesses: {', '.join(cwe_ids) if cwe_ids else 'none listed'}\n"
        f"Published: {published}"
    )

    metadata = {
        "cve_id": cve_id,
        "cvss_score": cvss_score if cvss_score is not None else -1.0,
        "cvss_severity": cvss_severity or "UNKNOWN",
        "cwe_ids": ", ".join(cwe_ids) if cwe_ids else "",
        "published": published,
        "cpe_sample": ", ".join(cpe_hints) if cpe_hints else "",
        "source": "NVD",
    }
    return {"id": cve_id, "text": doc_text, "metadata": metadata}


def main():
    parser = argparse.ArgumentParser(description="Ingest NVD CVEs into ChromaDB")
    parser.add_argument("--days", type=int, default=90,
                         help="How many days back from today to pull CVEs for (default 90)")
    parser.add_argument("--start-date", type=str, default=None,
                         help="Explicit start date YYYY-MM-DD (overrides --days)")
    parser.add_argument("--end-date", type=str, default=None,
                         help="Explicit end date YYYY-MM-DD (default: now)")
    parser.add_argument("--max-results", type=int, default=5000,
                         help="Cap on total CVEs ingested (default 5000)")
    parser.add_argument("--batch-size", type=int, default=256,
                         help="Chroma upsert batch size")
    args = parser.parse_args()

    end = (dt.datetime.strptime(args.end_date, "%Y-%m-%d")
           if args.end_date else dt.datetime.utcnow())
    start = (dt.datetime.strptime(args.start_date, "%Y-%m-%d")
             if args.start_date else end - dt.timedelta(days=args.days))

    api_key = get_api_key()
    print(f"[*] NVD API key present: {bool(api_key)}")
    print(f"[*] Pulling CVEs published between {start.date()} and {end.date()}")
    print(f"[*] Max results cap: {args.max_results}")

    session = requests.Session()
    all_vulns: list[dict[str, Any]] = []
    for chunk_start, chunk_end in chunk_date_ranges(start, end, MAX_SPAN_DAYS):
        if len(all_vulns) >= args.max_results:
            break
        remaining = args.max_results - len(all_vulns)
        chunk_vulns = fetch_cves_for_range(session, api_key, chunk_start, chunk_end, remaining)
        all_vulns.extend(chunk_vulns)
        time.sleep(throttle_delay(bool(api_key)))

    print(f"[*] Raw vulnerabilities fetched: {len(all_vulns)}")

    records = []
    for v in all_vulns:
        rec = extract_fields(v)
        if rec:
            records.append(rec)
    print(f"[*] Usable records after filtering (has English description): {len(records)}")

    if not records:
        print("[!] No records to ingest. Exiting without touching ChromaDB.")
        sys.exit(1)

    print(f"[*] Loading embedding function ({EMBED_MODEL_NAME})...")
    embed_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
        model_name=EMBED_MODEL_NAME
    )

    client = chromadb.PersistentClient(path=CHROMA_PATH)
    collection = client.get_or_create_collection(
        name=COLLECTION_NAME,
        embedding_function=embed_fn,
        metadata={"description": "NVD CVE records", "source": "NVD API 2.0"},
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
