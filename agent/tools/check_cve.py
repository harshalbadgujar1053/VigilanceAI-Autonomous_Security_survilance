"""
check_cve.py — Tool 3 for Vigilance AI ReAct Agent
---------------------------------------------------
Looks up CVE details and CVSS severity scores from the
National Vulnerability Database (NVD) public API.

Has a local cache fallback for when NVD API is unavailable.
No API key required for basic usage.
"""

import requests
from langchain.tools import tool


# ─────────────────────────────────────────────
# 1. LOCAL CACHE
#    Used when NVD API is down or rate-limiting.
#    Add more CVEs here as needed.
# ─────────────────────────────────────────────
CVE_LOCAL_CACHE = {
    "CVE-2021-44228": {
        "cve_id": "CVE-2021-44228",
        "description": "Apache Log4j2 remote code execution vulnerability. "
                       "Allows attackers to execute arbitrary code via JNDI lookup.",
        "cvss_score": 10.0,
        "cvss_severity": "CRITICAL",
        "published": "2021-12-10"
    },
    "CVE-2023-38408": {
        "cve_id": "CVE-2023-38408",
        "description": "OpenSSH ssh-agent PKCS#11 remote code execution. "
                       "Allows remote attackers to execute arbitrary commands.",
        "cvss_score": 9.8,
        "cvss_severity": "CRITICAL",
        "published": "2023-07-20"
    },
    "CVE-2022-30190": {
        "cve_id": "CVE-2022-30190",
        "description": "Microsoft Windows Support Diagnostic Tool (MSDT) "
                       "remote code execution vulnerability (Follina).",
        "cvss_score": 7.8,
        "cvss_severity": "HIGH",
        "published": "2022-06-01"
    },
    "CVE-2021-34527": {
        "cve_id": "CVE-2021-34527",
        "description": "Windows Print Spooler remote code execution "
                       "vulnerability (PrintNightmare).",
        "cvss_score": 8.8,
        "cvss_severity": "HIGH",
        "published": "2021-07-02"
    },
    "CVE-2023-44487": {
        "cve_id": "CVE-2023-44487",
        "description": "HTTP/2 Rapid Reset Attack causing denial of service "
                       "in multiple web servers.",
        "cvss_score": 7.5,
        "cvss_severity": "HIGH",
        "published": "2023-10-10"
    }
}


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


# ─────────────────────────────────────────────
# 2. FETCH FUNCTION
#    Checks local cache first, then NVD API.
# ─────────────────────────────────────────────
def fetch_cve(cve_id: str) -> dict:
    """
    Fetches CVE data — local cache first, then NVD API.
    Returns parsed dict with severity info.
    """
    cve_upper = cve_id.upper().strip()

    # Check local cache first (works offline / when NVD is down)
    if cve_upper in CVE_LOCAL_CACHE:
        print(f"(Using local cache for {cve_upper})")
        return CVE_LOCAL_CACHE[cve_upper]

    # Otherwise try NVD API
    params = {"cveId": cve_upper}

    try:
        response = requests.get(
            NVD_API_URL,
            params=params,
            timeout=10,
            headers={"User-Agent": "VigilanceAI-SOC-Copilot/1.0"}
        )
        response.raise_for_status()
        data = response.json()

        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return {"error": f"CVE {cve_upper} not found in NVD database"}

        cve_data = vulnerabilities[0]["cve"]

        # Extract description
        descriptions = cve_data.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d["lang"] == "en"),
            "No description available"
        )

        # Extract CVSS score (try v3.1 first, then v3.0, then v2)
        metrics = cve_data.get("metrics", {})
        cvss_score = None
        cvss_severity = None

        for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if version in metrics:
                metric = metrics[version][0]
                cvss_data = metric.get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                cvss_severity = cvss_data.get(
                    "baseSeverity",
                    metric.get("baseSeverity", "Unknown")
                )
                break

        # Extract published date
        published = cve_data.get("published", "Unknown")[:10]

        return {
            "cve_id": cve_upper,
            "description": description[:300],
            "cvss_score": cvss_score,
            "cvss_severity": cvss_severity,
            "published": published,
        }

    except requests.exceptions.Timeout:
        return {"error": "NVD API timeout — try again"}
    except requests.exceptions.ConnectionError:
        return {"error": "Cannot reach NVD API — check internet connection"}
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}"}


# ─────────────────────────────────────────────
# 3. THE TOOL
# ─────────────────────────────────────────────
@tool
def check_cve(cve_id: str) -> str:
    """
    Look up a specific CVE (Common Vulnerability and Exposure) by its ID
    to get severity score, description, and risk assessment.

    Use this tool when:
    - An alert mentions a specific CVE ID
    - You need to assess the risk level of a known vulnerability
    - You want to understand what software is affected

    Args:
        cve_id: The CVE identifier to look up.
                Format: CVE-YYYY-NNNNN
                Example: "CVE-2023-38408"
                Example: "CVE-2021-44228"

    Returns:
        CVE description, CVSS base score (0.0-10.0),
        severity level (LOW/MEDIUM/HIGH/CRITICAL),
        and publication date.
    """
    result = fetch_cve(cve_id)

    if "error" in result:
        return f"CVE lookup failed: {result['error']}"

    # Format score interpretation
    score = result["cvss_score"]
    if score is None:
        score_info = "No CVSS score available"
    elif score >= 9.0:
        score_info = f"{score}/10 — CRITICAL (immediate action required)"
    elif score >= 7.0:
        score_info = f"{score}/10 — HIGH (urgent attention needed)"
    elif score >= 4.0:
        score_info = f"{score}/10 — MEDIUM (schedule remediation)"
    else:
        score_info = f"{score}/10 — LOW (monitor)"

    return f"""CVE: {result['cve_id']}
Published: {result['published']}
CVSS Score: {score_info}
Severity: {result['cvss_severity']}
Description: {result['description']}..."""


# ─────────────────────────────────────────────
# 4. TEST
# ─────────────────────────────────────────────
if __name__ == "__main__":
    print("TEST 1 — Log4Shell (from local cache):")
    print(check_cve.invoke("CVE-2021-44228"))
    print("\n" + "─" * 50)

    print("\nTEST 2 — OpenSSH (from local cache):")
    print(check_cve.invoke("CVE-2023-38408"))
    print("\n" + "─" * 50)

    print("\nTEST 3 — Unknown CVE (will try NVD API):")
    print(check_cve.invoke("CVE-2024-12345"))
