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

    # NEW columns
    sha256 = db.Column(db.String(128), index=True, nullable=True)
    is_duplicate = db.Column(db.Boolean, default=False, nullable=False)
    duplicate_of = db.Column(db.String(64), nullable=True)  # artifact_id this duplicates

    analysis = db.Column(db.Text) # JSON stored as string


    def to_dict(self):
        analysis_parsed = None
        if self.analysis:
            try:
                if isinstance(self.analysis, str):
                    analysis_parsed = json.loads(self.analysis)
                elif isinstance(self.analysis, dict):
                    analysis_parsed = self.analysis
                else:
                    analysis_parsed = str(self.analysis)
            except Exception:
                analysis_parsed = self.analysis


        return {
            "artifact_id": self.artifact_id,
            "case_id": self.case_id,
            "original_filename": self.original_filename,
            "saved_filename": self.saved_filename,
            "saved_path": self.saved_path,
            "uploaded_by": self.uploaded_by,
            "uploaded_at": (self.uploaded_at.isoformat() + "Z") if self.uploaded_at else None,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "is_duplicate": bool(self.is_duplicate),
            "duplicate_of": self.duplicate_of,
            "analysis": analysis_parsed
        }

class ChainOfCustody(db.Model):
    __tablename__ = "chain_of_custody"
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.String(100), nullable=False, index=True)
    artifact_id = db.Column(db.String(64), nullable=False, index=True)
    actor = db.Column(db.String(100))
    action = db.Column(db.String(100))
    from_entity = db.Column(db.String(255))
    to_entity = db.Column(db.String(255))
    reason = db.Column(db.String(255))
    location = db.Column(db.String(255))
    details = db.Column(db.Text, nullable=True)
    signature = db.Column(db.String(256), nullable=True)
    ts = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "case_id": self.case_id,
            "artifact_id": self.artifact_id,
            "actor": self.actor,
            "action": self.action,
            "from": self.from_entity,
            "to": self.to_entity,
            "reason": self.reason,
            "location": self.location,
            "details": json.loads(self.details) if self.details else None,
            "signature": self.signature,
            "ts": (self.ts.isoformat() + "Z") if self.ts else None
        }

# Add this class definition near the bottom of modules/models.py (after Artifact)
class Audit(db.Model):
    __tablename__ = "audits"
    id = db.Column(db.Integer, primary_key=True)
    ts = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    case_id = db.Column(db.String(100), nullable=True, index=True)
    artifact_id = db.Column(db.String(64), nullable=True, index=True)
    actor = db.Column(db.String(100), nullable=True)
    action = db.Column(db.String(100), nullable=True)
    details = db.Column(db.Text, nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "ts": (self.ts.isoformat() + "Z") if self.ts else None,
            "case_id": self.case_id,
            "artifact_id": self.artifact_id,
            "actor": self.actor,
            "action": self.action,
            "details": json.loads(self.details) if self.details else None
        }
