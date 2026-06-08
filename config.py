# ============================================================
# AegisRecon AI — config.py
# Central configuration for Flask app, database, scan settings,
# PECA fines, and Ollama AI integration.
# ============================================================

import os
from pathlib import Path

# Base directory of the project
BASE_DIR = Path(__file__).resolve().parent


class Config:
    """Base configuration shared across all environments."""

    # ----------------------------------------------------------
    # Flask Core
    # ----------------------------------------------------------
    SECRET_KEY = os.environ.get("SECRET_KEY", "aegisrecon-dev-secret-change-in-prod")
    DEBUG = False
    TESTING = False

    # ----------------------------------------------------------
    # Database — SQLite stored in instance/ folder
    # ----------------------------------------------------------
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        f"sqlite:///{BASE_DIR / 'instance' / 'aegisrecon.db'}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # ----------------------------------------------------------
    # Scan Settings
    # ----------------------------------------------------------
    # Maximum seconds to wait for passive recon requests
    PASSIVE_TIMEOUT = 15

    # Maximum seconds for active scanning (Nmap etc.)
    ACTIVE_TIMEOUT = 60

    # Nmap scan arguments (safe defaults — no aggressive scan)
    # -sV: version detection  -T3: normal timing  --open: only open ports
    NMAP_ARGUMENTS = "-sV -T3 --open -p 21,22,23,25,53,80,110,143,443,445,3306,5432,6379,8080,8443,27017"

    # Wayback Machine CDX API base URL
    WAYBACK_CDX_URL = "https://web.archive.org/cdx/search/cdx"

    # crt.sh certificate transparency URL
    CRTSH_URL = "https://crt.sh/?q={domain}&output=json"

    # ----------------------------------------------------------
    # PECA 2016 Fine Schedule (PKR)
    # Prevention of Electronic Crimes Act — Pakistan
    # ----------------------------------------------------------
    PECA_FINES = {
        "critical": {
            "label": "Critical",
            "min_pkr": 10_000_000,   # 1 Crore
            "max_pkr": 50_000_000,   # 5 Crore
            "description": "Unauthorized access to critical infrastructure / data breach"
        },
        "high": {
            "label": "High",
            "min_pkr": 5_000_000,    # 50 Lakh
            "max_pkr": 10_000_000,   # 1 Crore
            "description": "Serious cybersecurity negligence leading to exposure"
        },
        "medium": {
            "label": "Medium",
            "min_pkr": 1_000_000,    # 10 Lakh
            "max_pkr": 5_000_000,    # 50 Lakh
            "description": "Moderate vulnerability allowing partial data access"
        },
        "low": {
            "label": "Low",
            "min_pkr": 100_000,      # 1 Lakh
            "max_pkr": 1_000_000,    # 10 Lakh
            "description": "Minor security misconfiguration"
        },
        "info": {
            "label": "Informational",
            "min_pkr": 0,
            "max_pkr": 100_000,
            "description": "Informational finding — no direct financial penalty"
        }
    }

    # ----------------------------------------------------------
    # Risk Score Weights (used in Business Risk Score calculation)
    # ----------------------------------------------------------
    RISK_WEIGHTS = {
        "open_ports":        0.20,
        "ssl_issues":        0.25,
        "header_issues":     0.15,
        "cve_count":         0.25,
        "exposed_services":  0.15,
    }

    # ----------------------------------------------------------
    # Predictive Risk — 30-day window multipliers
    # Based on industry-average exploit probability per severity
    # ----------------------------------------------------------
    EXPLOIT_PROBABILITY_30D = {
        "critical": 0.85,
        "high":     0.60,
        "medium":   0.35,
        "low":      0.10,
        "info":     0.02,
    }

    # ----------------------------------------------------------
    # Ollama AI Settings (local LLM — optional)
    # ----------------------------------------------------------
    OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
    OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3")
    OLLAMA_ENABLED = os.environ.get("OLLAMA_ENABLED", "false").lower() == "true"
    OLLAMA_TIMEOUT = 120  # seconds

    # ----------------------------------------------------------
    # PDF Report Settings
    # ----------------------------------------------------------
    REPORTS_DIR = BASE_DIR / "instance" / "reports"
    PDF_LOGO_PATH = BASE_DIR / "static" / "img" / "logo.png"

    # ----------------------------------------------------------
    # Pagination
    # ----------------------------------------------------------
    SCANS_PER_PAGE = 10


class DevelopmentConfig(Config):
    """Development-specific overrides."""
    DEBUG = True
    SQLALCHEMY_ECHO = False  # Set True to log all SQL queries


class ProductionConfig(Config):
    """Production-specific overrides."""
    DEBUG = False
    # In production, set SECRET_KEY via environment variable!
    PASSIVE_TIMEOUT = 20
    ACTIVE_TIMEOUT = 90


class TestingConfig(Config):
    """Testing-specific overrides."""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"


# ----------------------------------------------------------
# Environment selector
# ----------------------------------------------------------
config_map = {
    "development": DevelopmentConfig,
    "production":  ProductionConfig,
    "testing":     TestingConfig,
}

def get_config():
    """Return the correct config class based on FLASK_ENV env var."""
    env = os.environ.get("FLASK_ENV", "development")
    return config_map.get(env, DevelopmentConfig)
