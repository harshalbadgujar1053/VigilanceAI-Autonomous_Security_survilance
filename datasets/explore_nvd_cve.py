"""
explore_nvd_cve.py
Fetches recent CVE entries from the NVD REST API and prints
10 sample entries to inspect the data structure before building
the RAG ingestion pipeline in Phase 2.

If you get a 403 error, get a free API key from:
https://nvd.nist.gov/developers/request-an-api-key
Then set it: export NVD_API_KEY="your-key-here"
"""

import json
import urllib.request
import urllib.error
import os
import sys

NVD_API_URL = (
    "https://services.nvd.nist.gov/rest/json/cves/2.0"
    "?resultsPerPage=10&startIndex=0"
)

OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "nvd_sample.json")


def fetch_cve_data(url, out_path):
    if os.path.exists(out_path):
        print(f"[info] Cached CVE sample found at {out_path}, using it.")
        with open(out_path, "r", encoding="utf-8") as f:
            return json.load(f)

    print("[info] Fetching CVE data from NVD API...")

    headers = {"User-Agent": "VigilanceAI-Project/1.0"}

    # Use API key if set as environment variable
    api_key = os.environ.get("b1850888-4c1c-4ac1-a36c-374fa76a7556")
    if api_key:
        headers["apiKey"] = api_key
        print("[info] Using NVD API key from environment.")
    else:
        print("[warn] No NVD_API_KEY set. May hit rate limits.")
        print("[warn] Get a free key: https://nvd.nist.gov/developers/request-an-api-key")

    req = urllib.request.Request(url, headers=headers)

    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            data = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        print(f"[error] HTTP {e.code}: {e.reason}")
        print("[tip] If 403, set your API key: export NVD_API_KEY='your-key'")
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"[error] Connection failed: {e.reason}")
        sys.exit(1)

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    print(f"[info] Saved sample to {out_path}")
    return data


def print_sample(data):
    vulnerabilities = data.get("vulnerabilities", [])
    print(f"\n=== Showing {len(vulnerabilities)} sample CVE entries ===\n")

    for i, item in enumerate(vulnerabilities, start=1):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "Unknown")
        published = cve.get("published", "N/A")[:10]

        descriptions = cve.get("descriptions", [])
        eng_desc = next(
            (d.get("value") for d in descriptions if d.get("lang") == "en"),
            "No description available"
        )[:200]

        metrics = cve.get("metrics", {})
        severity = "N/A"
        if "cvssMetricV31" in metrics:
            severity = metrics["cvssMetricV31"][0]["cvssData"].get("baseSeverity", "N/A")
        elif "cvssMetricV2" in metrics:
            severity = metrics["cvssMetricV2"][0].get("baseSeverity", "N/A")

        print(f"{i}. {cve_id}  (Published: {published}, Severity: {severity})")
        print(f"   {eng_desc}...\n")


if __name__ == "__main__":
    cve_data = fetch_cve_data(NVD_API_URL, OUTPUT_FILE)
    print_sample(cve_data)
