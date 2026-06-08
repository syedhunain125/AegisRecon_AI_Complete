# ============================================================
# AegisRecon AI — routes/report_routes.py
# PDF report generation and download routes
# (Full implementation comes in Phase 3)
# ============================================================

from flask import Blueprint, redirect, url_for, flash
from models.scan import ScanTarget

report_bp = Blueprint("report_bp", __name__)


@report_bp.route("/generate/<int:scan_id>/<report_type>")
def generate(scan_id, report_type="full"):
    """Generate a PDF report for the given scan."""
    scan = ScanTarget.query.get_or_404(scan_id)
    # TODO Phase 3: call PDF service
    flash("PDF generation will be available in Phase 3.", "info")
    return redirect(url_for("scan_detail", scan_id=scan_id))
