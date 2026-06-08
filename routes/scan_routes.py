from flask import Blueprint, render_template, request, redirect, url_for, flash
from extensions import db
from models.scan import ScanTarget
import validators
from services.scan_service import run_scan

scan_bp = Blueprint("scan_bp", __name__)


@scan_bp.route("/scan/new", methods=["GET", "POST"])
def new_scan():
    if request.method == "POST":
        target = request.form.get("target", "").strip()
        scan_type = request.form.get("scan_type", "hybrid")

        if not target:
            flash("Please enter a target domain or IP address.", "danger")
            return render_template("new_scan.html")

        if not validators.domain(target) and not validators.ipv4(target):
            flash("Invalid domain or IP address.", "danger")
            return render_template("new_scan.html")

        # Database mein scan save karo
        scan = ScanTarget(target=target, scan_type=scan_type, status="pending")
        db.session.add(scan)
        db.session.commit()

        # Scan chalao (abhi ke liye synchronous)
        flash(f"Scan started for {target}...", "info")
        
        run_scan(scan.id)   # ← Yeh line database ke saath safely chalay gi

        flash(f"✅ Scan Completed for {target}!", "success")
        return redirect(url_for("scan_detail", scan_id=scan.id))

    return render_template("new_scan.html")