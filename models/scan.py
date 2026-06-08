# ============================================================
# AegisRecon AI — models/scan.py
# SQLAlchemy ORM models for scan history, findings, and reports
# ============================================================

from datetime import datetime
from extensions import db
import json


class ScanTarget(db.Model):
    """
    Represents a single scan job submitted by the user.
    One target → many ScanFindings, one RiskScore, one Report.
    """
    __tablename__ = "scan_targets"

    id             = db.Column(db.Integer, primary_key=True)
    target         = db.Column(db.String(255), nullable=False)   # domain / IP
    scan_type      = db.Column(db.String(20), default="hybrid")  # passive|active|hybrid
    status         = db.Column(db.String(20), default="pending") # pending|running|done|error
    created_at     = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at   = db.Column(db.DateTime, nullable=True)
    error_message  = db.Column(db.Text, nullable=True)

    # Relationships
    findings    = db.relationship("ScanFinding",  backref="scan", lazy="dynamic", cascade="all, delete-orphan")
    risk_score  = db.relationship("RiskScore",    backref="scan", uselist=False,  cascade="all, delete-orphan")
    recon_data  = db.relationship("ReconData",    backref="scan", uselist=False,  cascade="all, delete-orphan")
    report      = db.relationship("ScanReport",   backref="scan", uselist=False,  cascade="all, delete-orphan")

    def duration_seconds(self):
        """Return scan duration in seconds, or None if not completed."""
        if self.completed_at and self.created_at:
            return int((self.completed_at - self.created_at).total_seconds())
        return None

    def findings_by_severity(self):
        """Return a dict of severity → count for quick dashboard display."""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            if f.severity in counts:
                counts[f.severity] += 1
        return counts

    def __repr__(self):
        return f"<ScanTarget {self.target} [{self.status}]>"


class ScanFinding(db.Model):
    """
    Individual vulnerability or finding from a scan.
    Each finding belongs to one ScanTarget.
    """
    __tablename__ = "scan_findings"

    id          = db.Column(db.Integer, primary_key=True)
    scan_id     = db.Column(db.Integer, db.ForeignKey("scan_targets.id"), nullable=False)

    # Finding classification
    module      = db.Column(db.String(50))   # e.g. "nmap", "ssl_check", "headers"
    severity    = db.Column(db.String(20))   # critical|high|medium|low|info
    title       = db.Column(db.String(255))
    description = db.Column(db.Text)
    evidence    = db.Column(db.Text)         # raw output / proof

    # CVE data (if applicable)
    cve_id      = db.Column(db.String(30), nullable=True)   # e.g. CVE-2024-1234
    cvss_score  = db.Column(db.Float, nullable=True)        # 0.0 – 10.0

    # Remediation advice
    remediation = db.Column(db.Text, nullable=True)

    created_at  = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Finding [{self.severity.upper()}] {self.title}>"


class ReconData(db.Model):
    """
    Stores raw passive recon results as JSON blobs.
    One-to-one with ScanTarget.
    """
    __tablename__ = "recon_data"

    id              = db.Column(db.Integer, primary_key=True)
    scan_id         = db.Column(db.Integer, db.ForeignKey("scan_targets.id"), nullable=False)

    # Each field stores a JSON-serialised dict/list
    whois_data      = db.Column(db.Text, nullable=True)
    dns_records     = db.Column(db.Text, nullable=True)
    subdomains      = db.Column(db.Text, nullable=True)   # from crt.sh
    technologies    = db.Column(db.Text, nullable=True)   # from Wappalyzer-style detection
    wayback_urls    = db.Column(db.Text, nullable=True)
    http_headers    = db.Column(db.Text, nullable=True)
    ssl_info        = db.Column(db.Text, nullable=True)
    open_ports      = db.Column(db.Text, nullable=True)   # from Nmap

    created_at      = db.Column(db.DateTime, default=datetime.utcnow)

    # Convenience helpers — get/set JSON fields transparently
    def get_json(self, field: str):
        raw = getattr(self, field, None)
        if raw:
            try:
                return json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                return {}
        return {}

    def set_json(self, field: str, value):
        setattr(self, field, json.dumps(value, default=str))

    def __repr__(self):
        return f"<ReconData scan_id={self.scan_id}>"


class RiskScore(db.Model):
    """
    Calculated Business Risk Score for a scan.
    Includes PKR financial exposure and 30-day predictive risk.
    """
    __tablename__ = "risk_scores"

    id                   = db.Column(db.Integer, primary_key=True)
    scan_id              = db.Column(db.Integer, db.ForeignKey("scan_targets.id"), nullable=False)

    # Overall score 0–100
    overall_score        = db.Column(db.Float, default=0.0)
    risk_level           = db.Column(db.String(20), default="info")  # critical|high|medium|low|info

    # Component scores (0–100 each)
    score_open_ports     = db.Column(db.Float, default=0.0)
    score_ssl            = db.Column(db.Float, default=0.0)
    score_headers        = db.Column(db.Float, default=0.0)
    score_cve            = db.Column(db.Float, default=0.0)
    score_services       = db.Column(db.Float, default=0.0)

    # PECA Financial Exposure (PKR)
    peca_min_pkr         = db.Column(db.BigInteger, default=0)
    peca_max_pkr         = db.Column(db.BigInteger, default=0)

    # 30-day Predictive Risk
    predictive_score_30d = db.Column(db.Float, default=0.0)
    breach_probability   = db.Column(db.Float, default=0.0)  # 0.0 – 1.0

    # AI-generated summary (from Ollama)
    ai_summary           = db.Column(db.Text, nullable=True)
    ai_summary_ur        = db.Column(db.Text, nullable=True)   # Urdu translation

    created_at           = db.Column(db.DateTime, default=datetime.utcnow)

    def peca_min_formatted(self):
        """Return human-readable PKR amount (e.g. '₨ 50,00,000')."""
        return f"₨ {self.peca_min_pkr:,.0f}"

    def peca_max_formatted(self):
        return f"₨ {self.peca_max_pkr:,.0f}"

    def __repr__(self):
        return f"<RiskScore scan_id={self.scan_id} score={self.overall_score}>"


class ScanReport(db.Model):
    """
    Metadata for generated PDF reports.
    """
    __tablename__ = "scan_reports"

    id           = db.Column(db.Integer, primary_key=True)
    scan_id      = db.Column(db.Integer, db.ForeignKey("scan_targets.id"), nullable=False)

    filename     = db.Column(db.String(255), nullable=False)  # e.g. report_1_20240601.pdf
    file_path    = db.Column(db.String(512), nullable=False)  # absolute path
    report_type  = db.Column(db.String(20), default="full")   # full|technical|executive
    language     = db.Column(db.String(10), default="en")     # en | ur | bilingual
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<ScanReport {self.filename}>"
