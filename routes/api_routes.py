# ============================================================
# AegisRecon AI — routes/api_routes.py
# Internal JSON API endpoints
# ============================================================

from flask import Blueprint, jsonify
from models.scan import ScanTarget, ScanFinding

api_bp = Blueprint("api_bp", __name__)


@api_bp.route("/scans")
def list_scans():
    scans = ScanTarget.query.order_by(ScanTarget.created_at.desc()).limit(20).all()
    return jsonify([{
        "id":         s.id,
        "target":     s.target,
        "scan_type":  s.scan_type,
        "status":     s.status,
        "created_at": s.created_at.isoformat(),
    } for s in scans])


@api_bp.route("/scan/<int:scan_id>/findings")
def scan_findings(scan_id):
    scan = ScanTarget.query.get_or_404(scan_id)
    findings = scan.findings.all()
    return jsonify([{
        "id":          f.id,
        "module":      f.module,
        "severity":    f.severity,
        "title":       f.title,
        "cve_id":      f.cve_id,
        "cvss_score":  f.cvss_score,
    } for f in findings])
