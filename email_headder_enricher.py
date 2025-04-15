# email_header_enricher.py
# Email Header IOC Extractor + VirusTotal Enricher

import re
import json
import time
import requests
from dotenv import load_dotenv
import os

# Load VT API Key from .env
load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")
VT_HEADERS = {"x-apikey": VT_API_KEY}

def extract_iocs_from_header(header_path):
    with open(header_path, "r") as f:
        content = f.read()

    ips = list(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", content)))
    domains = list(set(re.findall(r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}\b", content)))
    return domains, ips

def query_vt(ioc_type, value):
    base_url = "https://www.virustotal.com/api/v3/"
    endpoint = "domains" if ioc_type == "domain" else "ip_addresses"
    url = f"{base_url}{endpoint}/{value}"
    response = requests.get(url, headers=VT_HEADERS)

    if response.status_code == 200:
        data = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return {
            "ioc": value,
            "type": ioc_type,
            "harmless": data.get("harmless", 0),
            "malicious": data.get("malicious", 0),
            "suspicious": data.get("suspicious", 0),
            "undetected": data.get("undetected", 0)
        }
    else:
        return {
            "ioc": value,
            "type": ioc_type,
            "error": response.status_code
        }

def enrich_iocs(domains, ips):
    all_iocs = [{"type": "domain", "value": d} for d in domains] + [{"type": "ip", "value": ip} for ip in ips]
    results = []
    for ioc in all_iocs:
        print(f"[+] Enriching {ioc['type']}: {ioc['value']}")
        result = query_vt(ioc["type"], ioc["value"])
        results.append(result)
        time.sleep(15)  # Respect free-tier VT rate limit
    return results

def main():
    header_file = "email_header.txt"
    domains, ips = extract_iocs_from_header(header_file)
    print(f"[+] Found {len(domains)} domains, {len(ips)} IPs in {header_file}")
    enriched = enrich_iocs(domains, ips)

    with open("email_header_enrichment_results.json", "w") as f:
        json.dump(enriched, f, indent=2)
    print("[✓] Results saved to email_header_enrichment_results.json")

if __name__ == "__main__":
    main()
