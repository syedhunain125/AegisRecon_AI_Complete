# ============================================================
# Basic Vulnerability Engine
# ============================================================

def generate_findings(scan_data):
    findings = []
    
    # Example findings from Nmap / Headers
    if scan_data.get("nmap"):
        findings.append({
            "module": "nmap",
            "severity": "medium",
            "title": "Open Ports Detected",
            "description": "Several ports are open on the target.",
            "evidence": str(scan_data["nmap"])
        })
    
    if scan_data.get("headers"):
        missing = [k for k,v in scan_data["headers"].items() if not v]
        if missing:
            findings.append({
                "module": "headers",
                "severity": "high",
                "title": "Missing Security Headers",
                "description": f"Missing: {', '.join(missing)}"
            })
    
    return findings