# modules/hashing.py
import hashlib
import os
import json
import logging

from modules.utils import (
    ensure_case_dirs,
    append_integrity_record_to_metadata,
    record_audit,
    iso_time_now,
    write_signed_metadata
)
from modules.db import db
from modules.models import Artifact

logger = logging.getLogger(__name__)


def compute_sha256(file_path):
    """
    Compute SHA-256 of file at file_path in streaming fashion.
    Returns (hex digest string, total_bytes).
    """
    sha256 = hashlib.sha256()
    total = 0
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            total += len(chunk)
            sha256.update(chunk)
    return sha256.hexdigest(), total


def find_artifact_by_sha(sha256_hex):
    """
    Return the Artifact DB row that has the given sha256 (most-recent).
    Returns None if not found.
    """
    try:
        return Artifact.query.filter_by(sha256=sha256_hex).first()
    except Exception:
        logger.exception("DB lookup failed for sha lookup")
        return None


def update_artifact_hash(case_id, artifact_id, sha256_hex, actor="system"):
    """
    Update per-artifact JSON and the DB artifact.analysis field
    to include the computed sha256. Will append an integrity history record and write an audit entry.
    This function is careful to merge and sign on-disk metadata.
    """
    recorded_at = iso_time_now()

    # 1) Update artifact metadata JSON (evidence/<case>/artifacts/<artifact_id>.json)
    try:
        _, artifacts_dir = ensure_case_dirs(case_id)
        meta_path = os.path.join(artifacts_dir, f"{artifact_id}.json")
        if os.path.exists(meta_path):
            try:
                with open(meta_path, "r", encoding="utf-8") as f:
                    metadata = json.load(f)
            except Exception:
                metadata = {}

            # create an integrity record
            integrity_record = {
                "sha256": sha256_hex,
                "method": "sha256",
                "recorded_at": recorded_at,
                "recorded_by": actor,
                "file_size": metadata.get("size_bytes"),
                "note": "hash recorded/updated"
            }

            # append into artifact JSON (atomic)
            append_integrity_record_to_metadata(meta_path, integrity_record)

            # also ensure top-level sha256 and analysis.latest_sha256 for quick lookup, then sign the metadata
            try:
                if os.path.exists(meta_path):
                    with open(meta_path, "r", encoding="utf-8") as f:
                        updated = json.load(f)
                else:
                    updated = metadata or {}
                updated["sha256"] = sha256_hex
                updated.setdefault("analysis", {})
                # ensure integrity list exists
                updated["analysis"].setdefault("integrity", [])
                updated["analysis"]["latest_sha256"] = sha256_hex

                # write & sign artifact metadata atomically (preserves _meta signature)
                write_signed_metadata(meta_path, updated)
            except Exception:
                logger.exception("Failed to merge top-level sha256 into artifact metadata for %s/%s", case_id, artifact_id)

    except Exception:
        logger.exception("Failed updating artifact metadata JSON for %s/%s", case_id, artifact_id)

    # 2) Update DB Artifact.analysis JSON (store/merge sha256)
    try:
        artifact = Artifact.query.filter_by(artifact_id=artifact_id, case_id=case_id).first()
        if artifact:
            existing = {}
            if artifact.analysis:
                try:
                    existing = json.loads(artifact.analysis)
                except Exception:
                    existing = {}

            # append integrity history in DB-side analysis
            integrity = existing.get("integrity", [])
            integrity.append({
                "sha256": sha256_hex,
                "recorded_at": recorded_at,
                "recorded_by": actor
            })
            existing["integrity"] = integrity
            existing["latest_sha256"] = sha256_hex
            artifact.analysis = json.dumps(existing)
            artifact.sha256 = sha256_hex

            try:
                db.session.add(artifact)
                db.session.commit()
            except Exception:
                db.session.rollback()
                logger.exception("Failed committing artifact sha to DB for %s/%s", case_id, artifact_id)

            # record audit for success
            try:
                record_audit(db, case_id, artifact_id, actor, "hash_recorded", {"sha256": sha256_hex, "recorded_at": recorded_at})
            except Exception:
                logger.exception("Failed to write audit for hash_recorded %s/%s", case_id, artifact_id)
    except Exception:
        logger.exception("Failed updating DB artifact for %s", artifact_id)


def record_duplicate_detection(case_id, artifact_id, existing_artifact_id, sha256_hex, actor="system"):
    """
    Helper to record a duplicate detection audit entry and update DB artifact flag.
    """
    try:
        # mark the just-uploaded artifact as duplicate in DB
        art = Artifact.query.filter_by(artifact_id=artifact_id, case_id=case_id).first()
        if art:
            art.is_duplicate = True
            art.duplicate_of = existing_artifact_id
            art.sha256 = sha256_hex
            try:
                db.session.add(art)
                db.session.commit()
            except Exception:
                db.session.rollback()
                logger.exception("Failed to commit duplicate flag to DB for %s/%s", case_id, artifact_id)
    except Exception:
        logger.exception("Failed to mark DB artifact duplicate for %s/%s", case_id, artifact_id)

    # audit entry for duplicate detection
    try:
        record_audit(db, case_id, artifact_id, actor, "duplicate_detected", {"duplicate_of": existing_artifact_id, "sha256": sha256_hex})
    except Exception:
        logger.exception("Failed to write audit for duplicate_detected %s/%s", case_id, artifact_id)
