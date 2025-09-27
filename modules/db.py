# modules/db.py
from flask_sqlalchemy import SQLAlchemy

# single db instance to import across modules
db = SQLAlchemy()
