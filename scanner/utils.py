import re
import requests

def fetch_headers(url):
    """Fetch HTTP headers from a target URL."""
    try:
        response = requests.get(url, timeout=5)
        return response.headers
    except Exception as e:
        print(f"[!] Error fetching headers from {url}: {e}")
        return {}

def match_signatures(headers, signatures):
    """Check headers against known vulnerability signatures and return structured findings."""
    findings = []
    server_info = headers.get("Server", "")
    x_powered_by = headers.get("X-Powered-By", "")

    combined_info = f"{server_info} {x_powered_by}"

    for sig in signatures.get("signatures", []):
        if re.search(sig["pattern"], combined_info, re.IGNORECASE):
            findings.append({
                "name": sig.get("name", "Unknown"),
                "severity": sig.get("severity", "Info"),
                "description": sig.get("description", "No description available."),
                "remediation": sig.get("remediation", "Upgrade or patch the affected software.")
            })

    return findings

def severity_score(severity):
    """Map severity to a numeric score (for later prioritization)."""
    levels = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
    return levels.get(severity, 0)

def print_findings(findings):
    """Nicely print findings to the terminal."""
    if not findings:
        print("[+] No known vulnerabilities detected.")
    else:
        print("\n--- Scan Findings ---")
        for f in findings:
            print(f"[{f['severity']}] {f['name']} - {f['description']}")
