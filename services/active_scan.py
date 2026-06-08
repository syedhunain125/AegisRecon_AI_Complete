# ============================================================
# AegisRecon AI — Active Scanning
# ============================================================

import nmap
import requests
from urllib.parse import urlparse

def nmap_scan(target):
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=target, arguments="-sV -T3 --open -p 21,22,23,25,53,80,110,143,443,445,3306,5432,6379,8080,8443,27017")
        return nm[target] if target in nm.all_hosts() else {}
    except:
        return {"error": "Nmap scan failed"}

def check_http_headers(target):
    try:
        url = f"http://{target}" if not target.startswith("http") else target
        resp = requests.get(url, timeout=10, verify=False)
        headers = dict(resp.headers)
        security_headers = {
            "Strict-Transport-Security": headers.get("Strict-Transport-Security"),
            "X-Frame-Options": headers.get("X-Frame-Options"),
            "X-Content-Type-Options": headers.get("X-Content-Type-Options"),
            "Content-Security-Policy": headers.get("Content-Security-Policy")
        }
        return security_headers
    except:
        return {}

def ssl_check(target):
    try:
        import ssl
        import socket
        hostname = urlparse(f"http://{target}").netloc or target
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return {
                    "subject": cert.get("subject"),
                    "issuer": cert.get("issuer"),
                    "version": cert.get("version"),
                    "expired": False
                }
    except:
        return {"error": "SSL check failed"}

def run_active_scan(target):
    results = {}
    results["nmap"] = nmap_scan(target)
    results["headers"] = check_http_headers(target)
    results["ssl"] = ssl_check(target)
    return results