# ============================================================
# AegisRecon AI — Passive Reconnaissance
# ============================================================

import requests
import json
import time
from urllib.parse import urlparse
import dns.resolver
import whois
from bs4 import BeautifulSoup

def whois_lookup(domain):
    try:
        w = whois.whois(domain)
        return {
            "domain": w.domain_name,
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "nameservers": w.name_servers,
            "status": w.status
        }
    except:
        return {"error": "WHOIS lookup failed"}

def dns_lookup(domain):
    try:
        answers = {}
        for qtype in ['A', 'MX', 'NS', 'TXT']:
            try:
                answers[qtype] = [str(r) for r in dns.resolver.resolve(domain, qtype)]
            except:
                pass
        return answers
    except:
        return {}

def crtsh_subdomains(domain):
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        resp = requests.get(url, timeout=15)
        data = resp.json()
        subs = list(set([entry['name_value'].lower() for entry in data if 'name_value' in entry]))
        return sorted(subs)[:100]
    except:
        return []

def wayback_urls(domain):
    try:
        url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}&output=json&limit=50"
        resp = requests.get(url, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            return [row[2] for row in data[1:]] if len(data) > 1 else []
        return []
    except:
        return []

# Main passive recon function
def run_passive_recon(target):
    results = {}
    results["whois_data"] = whois_lookup(target)
    results["dns_records"] = dns_lookup(target)
    results["subdomains"] = crtsh_subdomains(target)
    results["wayback_urls"] = wayback_urls(target)
    return results