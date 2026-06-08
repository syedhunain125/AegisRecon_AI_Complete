# ============================================================
# AegisRecon AI — extensions.py
# Flask extension instances — imported here to avoid circular
# imports between app.py and models.
# ============================================================

from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

# SQLAlchemy instance — bound to app in create_app()
db = SQLAlchemy()

# Flask-Migrate for Alembic database migrations
migrate = Migrate()
