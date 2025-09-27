# modules/models.py
from .db import db
from datetime import datetime
import json

class Case(db.Model):
    __tablename__ = "cases"
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.String(100), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    description = db.Column(db.String(255), nullable=True)

    artifacts = db.relationship("Artifact", backref="case", lazy=True, cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "case_id": self.case_id,
            "created_at": (self.created_at.isoformat() + "Z") if self.created_at else None,
            "artifact_count": len(self.artifacts)
        }

class Artifact(db.Model):
    __tablename__ = "artifacts"
    id = db.Column(db.Integer, primary_key=True)
    artifact_id = db.Column(db.String(64), unique=True, nullable=False)
    case_id = db.Column(db.String(100), db.ForeignKey('cases.case_id'), nullable=False)
    original_filename = db.Column(db.String(255))
    saved_filename = db.Column(db.String(512))
    saved_path = db.Column(db.String(1024))
    uploaded_by = db.Column(db.String(100))
    uploaded_at = db.Column(db.DateTime)
    size_bytes = db.Column(db.Integer)
    analysis = db.Column(db.Text)  # JSON stored as string

    def to_dict(self):
        return {
            "artifact_id": self.artifact_id,
            "case_id": self.case_id,
            "original_filename": self.original_filename,
            "saved_filename": self.saved_filename,
            "saved_path": self.saved_path,
            "uploaded_by": self.uploaded_by,
            "uploaded_at": (self.uploaded_at.isoformat() + "Z") if self.uploaded_at else None,
            "size_bytes": self.size_bytes,
            "analysis": json.loads(self.analysis) if self.analysis else None
        }
