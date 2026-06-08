# ============================================================
# AegisRecon AI — app.py
# Flask Application Factory + Route Registration
# ============================================================

import os
import json
import threading
from datetime import datetime
from pathlib import Path

from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, jsonify, send_file, abort
)

from extensions import db, migrate
from config import get_config
from models.scan import ScanTarget, ScanFinding, ReconData, RiskScore, ScanReport


# ──────────────────────────────────────────────────────────────
# Application Factory
# ──────────────────────────────────────────────────────────────

def create_app(config_class=None):
    """
    Flask application factory.
    """
    app = Flask(__name__, instance_relative_config=True)

    # Load configuration
    if config_class is None:
        config_class = get_config()
    app.config.from_object(config_class)

    # Ensure directories exist
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    Path(app.config["REPORTS_DIR"]).mkdir(parents=True, exist_ok=True)

    # Initialise Flask extensions
    db.init_app(app)
    migrate.init_app(app, db)

    # Load company branding config
    company_cfg_path = Path(__file__).parent / "company_config.json"
    with open(company_cfg_path, encoding='utf-8') as f:
        app.config["COMPANY"] = json.load(f)

    # ── Register Blueprints ────────────────────────────────────
    from routes.scan_routes   import scan_bp
    from routes.report_routes import report_bp
    from routes.api_routes    import api_bp

    app.register_blueprint(scan_bp)
    app.register_blueprint(report_bp, url_prefix="/reports")
    app.register_blueprint(api_bp,    url_prefix="/api")

    # ── Jinja2 Global Helpers ──────────────────────────────────
    @app.template_filter("datetimeformat")
    def datetimeformat(value, fmt="%d %b %Y, %H:%M"):
        if isinstance(value, datetime):
            return value.strftime(fmt)
        return value

    @app.template_filter("pkr_format")
    def pkr_format(value):
        try:
            return f"₨ {int(value):,}"
        except (TypeError, ValueError):
            return "₨ 0"

    @app.context_processor
    def inject_globals():
        return {"company": app.config.get("COMPANY", {})}

    # ── Database Initialisation ────────────────────────────────
    with app.app_context():
        db.create_all()

    return app


# ──────────────────────────────────────────────────────────────
# Core Routes
# ──────────────────────────────────────────────────────────────

def register_core_routes(app):
    """Register simple core routes directly on the app object."""

    @app.route("/")
    def index():
        recent_scans = (
            ScanTarget.query
            .order_by(ScanTarget.created_at.desc())
            .limit(app.config["SCANS_PER_PAGE"])
            .all()
        )
        total_scans    = ScanTarget.query.count()
        done_scans     = ScanTarget.query.filter_by(status="done").count()
        critical_count = ScanFinding.query.filter_by(severity="critical").count()
        high_count     = ScanFinding.query.filter_by(severity="high").count()

        stats = {
            "total":    total_scans,
            "done":     done_scans,
            "critical": critical_count,
            "high":     high_count,
        }
        return render_template("index.html", scans=recent_scans, stats=stats)

    @app.route("/history")
    def history():
        page = request.args.get("page", 1, type=int)
        per_page = app.config["SCANS_PER_PAGE"]
        pagination = (
            ScanTarget.query
            .order_by(ScanTarget.created_at.desc())
            .paginate(page=page, per_page=per_page, error_out=False)
        )
        return render_template("history.html", pagination=pagination)

    @app.route("/scan/<int:scan_id>")
    def scan_detail(scan_id):
        scan = ScanTarget.query.get_or_404(scan_id)
        findings     = scan.findings.order_by(ScanFinding.severity).all()
        risk_score   = scan.risk_score
        recon        = scan.recon_data
        report       = scan.report
        severity_map = scan.findings_by_severity()

        return render_template(
            "scan_detail.html",
            scan=scan,
            findings=findings,
            risk_score=risk_score,
            recon=recon,
            report=report,
            severity_map=severity_map,
        )

    @app.route("/scan/<int:scan_id>/delete", methods=["POST"])
    def delete_scan(scan_id):
        scan = ScanTarget.query.get_or_404(scan_id)
        if scan.report and Path(scan.report.file_path).exists():
            Path(scan.report.file_path).unlink(missing_ok=True)
        db.session.delete(scan)
        db.session.commit()
        flash("Scan deleted successfully.", "success")
        return redirect(url_for("index"))

    @app.errorhandler(404)
    def not_found(e):
        return render_template("errors/404.html"), 404

    @app.errorhandler(500)
    def server_error(e):
        return render_template("errors/500.html"), 500


# ──────────────────────────────────────────────────────────────
# Entry Point
# ──────────────────────────────────────────────────────────────

def _ensure_route_files():
    routes_dir = Path(__file__).parent / "routes"
    routes_dir.mkdir(exist_ok=True)
    init_f = routes_dir / "__init__.py"
    if not init_f.exists():
        init_f.write_text("# routes package\n")

    for name in ("scan_routes", "report_routes", "api_routes"):
        fpath = routes_dir / f"{name}.py"
        if not fpath.exists():
            blueprint_name = name.replace("_routes", "_bp")
            fpath.write_text(
                f"# {name}.py — auto-generated placeholder\n"
                f"from flask import Blueprint\n"
                f"{blueprint_name} = Blueprint('{blueprint_name}', __name__)\n"
            )


_ensure_route_files()

app = create_app()
register_core_routes(app)


if __name__ == "__main__":
    print("=" * 60)
    print("          AegisRecon AI — Starting Server")
    print("   Intelligent Hybrid Vulnerability Scanner")
    print("   http://127.0.0.1:5000")
    print("=" * 60)
    
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=app.config.get("DEBUG", True),
        use_reloader=True,
    )