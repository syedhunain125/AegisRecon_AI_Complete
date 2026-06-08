# ============================================================
# AegisRecon AI — Scan Service (Fixed with App Context)
# ============================================================

from datetime import datetime
from extensions import db
from models.scan import ScanTarget, ReconData, ScanFinding, RiskScore
from .passive_recon import run_passive_recon
from .active_scan import run_active_scan
from .vuln_engine import generate_findings
from .risk_calculator import calculate_risk_score
from flask import current_app

def run_scan(scan_id):
    """Run scan in background thread with proper app context"""
    
    # Important: Push application context in thread
    with current_app.app_context():
        scan = ScanTarget.query.get(scan_id)
        if not scan:
            return

        scan.status = "running"
        db.session.commit()

        try:
            print(f"[SCAN] Starting scan for {scan.target}...")  # Debugging

            # Passive Recon
            passive_data = run_passive_recon(scan.target)
            
            # Active Scan (if needed)
            active_data = {}
            if scan.scan_type in ["active", "hybrid"]:
                active_data = run_active_scan(scan.target)

            # Save Recon Data
            recon = ReconData(scan_id=scan.id)
            recon.set_json("whois_data", passive_data.get("whois_data", {}))
            recon.set_json("dns_records", passive_data.get("dns_records", {}))
            recon.set_json("subdomains", passive_data.get("subdomains", []))
            db.session.add(recon)

            # Generate Findings
            findings_list = generate_findings({**passive_data, **active_data})
            for f in findings_list:
                finding = ScanFinding(
                    scan_id=scan.id,
                    module=f.get("module"),
                    severity=f.get("severity"),
                    title=f.get("title"),
                    description=f.get("description"),
                    evidence=f.get("evidence")
                )
                db.session.add(finding)

            # Risk Score
            risk_data = calculate_risk_score(findings_list)
            risk = RiskScore(scan_id=scan.id, **risk_data)
            db.session.add(risk)

            scan.status = "done"
            scan.completed_at = datetime.utcnow()

            print(f"[SCAN] Completed scan for {scan.target}")

        except Exception as e:
            print(f"[SCAN ERROR] {str(e)}")
            scan.status = "error"
            scan.error_message = str(e)

        db.session.commit()