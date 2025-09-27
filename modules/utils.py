# modules/utils.py
import os
import uuid
import json
import logging
from datetime import datetime
from werkzeug.utils import secure_filename

logger = logging.getLogger(__name__)

BASE_EVIDENCE_DIR = "evidence"
ALLOWED_EXTENSIONS = None  # leave None to accept all; set list like {'exe','txt'} elsewhere if needed


def ensure_case_dirs(case_id):
    """
    Ensure directories exist for a case:
      evidence/<case_id>/artifacts/
    """
    case_dir = os.path.join(BASE_EVIDENCE_DIR, case_id)
    artifacts_dir = os.path.join(case_dir, "artifacts")
    os.makedirs(artifacts_dir, exist_ok=True)
    return case_dir, artifacts_dir


def generate_artifact_id():
    """Return a short unique artifact id"""
    return uuid.uuid4().hex


def iso_time_now():
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def allowed_file_extension(filename, allowed_set):
    """
    Return True if filename has an allowed extension or if allowed_set is None (no restriction).
    """
    if not allowed_set:
        return True
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in allowed_set


def save_uploaded_file(file_storage, case_id="case001", uploader="unknown", allowed_ext_set=None):
    """
    Save the uploaded file into evidence/<case_id>/artifacts/
    Returns metadata dict on success or raises an Exception on failure.
    """
    case_dir, artifacts_dir = ensure_case_dirs(case_id)

    original_filename = file_storage.filename or "unnamed"
    safe_basename = secure_filename(original_filename)

    # Check allowed extensions if provided
    if allowed_ext_set is not None and not allowed_file_extension(safe_basename, allowed_ext_set):
        raise ValueError(f"File extension not allowed for file: {original_filename}")

    artifact_id = generate_artifact_id()

    # Make a safe saved filename: <artifact_id>__<safe_basename>
    saved_filename = f"{artifact_id}__{safe_basename}"
    saved_path = os.path.join(artifacts_dir, saved_filename)

    try:
        # Save file to disk
        file_storage.save(saved_path)
        stat = os.stat(saved_path)
    except Exception as e:
        logger.exception("Failed to save uploaded file")
        # if partial file exists, try to remove it
        try:
            if os.path.exists(saved_path):
                os.remove(saved_path)
        except Exception:
            pass
        raise

    # Build metadata
    metadata = {
        "artifact_id": artifact_id,
        "original_filename": original_filename,
        "saved_filename": saved_filename,
        "saved_path": saved_path,
        "case_id": case_id,
        "uploaded_by": uploader,
        "uploaded_at": iso_time_now(),
        "size_bytes": stat.st_size,
        "analysis": None  # placeholder for future analysis results
    }

    # Write per-artifact metadata file: artifacts/<artifact_id>.json
    meta_path = os.path.join(artifacts_dir, f"{artifact_id}.json")
    try:
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)
    except Exception:
        logger.exception("Failed to write artifact metadata JSON")
        # cleanup saved file if metadata write fails
        try:
            if os.path.exists(saved_path):
                os.remove(saved_path)
            if os.path.exists(meta_path):
                os.remove(meta_path)
        except Exception:
            pass
        raise

    return metadata
