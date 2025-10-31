# modules/utils.py
import os
import uuid
import json
import logging
import hmac
import hashlib
import base64
import tempfile
import shutil
from glob import glob
from datetime import datetime
from werkzeug.utils import secure_filename
from typing import Tuple

logger = logging.getLogger(__name__)

BASE_EVIDENCE_DIR = "evidence"
ALLOWED_EXTENSIONS = None  # leave None to accept all; set list like {'exe','txt'} elsewhere if needed

# HMAC keys (use env vars in production)
MANIFEST_HMAC_KEY = os.environ.get("MANIFEST_HMAC_KEY", "changeme_local_dev_key")
COC_HMAC_KEY = os.environ.get("COC_HMAC_KEY", MANIFEST_HMAC_KEY)

META_FIELD = "_meta"


def ensure_case_dirs(case_id):
    """
    Ensure directories exist for a case:
      evidence/<case_id>/artifacts/
    Returns (case_dir, artifacts_dir).
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


# Cross-platform atomic JSON write using os.replace
def atomic_write_json(path, obj):
    """
    Atomically write JSON to `path` using a tmp file and os.replace.
    Ensures the file is flushed to disk before replacing.
    """
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2)
        fh.flush()
        try:
            os.fsync(fh.fileno())
        except Exception:
            # fsync may fail on some platforms (Windows, or non-regular files) — ignore but log
            logger.debug("fsync not available or failed for %s", tmp)
    os.replace(tmp, path)


# JSON canonicalization for stable HMACs
def canonical_json_bytes(obj):
    """
    Produce deterministic JSON bytes for `obj` (sort keys, remove whitespace).
    Used for HMAC calculations.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def hmac_for_obj(obj, key: str = None) -> str:
    """
    Compute HMAC-SHA256 hex over canonical JSON of `obj`.
    Default key is the manifest key; callers (eg. CoC) can pass a different key.
    """
    k = (key or MANIFEST_HMAC_KEY).encode("utf-8")
    return hmac.new(k, canonical_json_bytes(obj), hashlib.sha256).hexdigest()


# write signed metadata (attaches _meta with hmac and timestamp)
def write_signed_metadata(path, obj, hmac_key: str = None) -> str:
    """
    Write metadata JSON atomically and attach a _meta.hmac entry containing HMAC-of-content.
    The HMAC is computed over the object without the _meta key.
    Returns the computed signature (hex).
    """
    key = hmac_key or MANIFEST_HMAC_KEY
    # make a copy and remove existing _meta if present so signing covers only real content
    obj_copy = dict(obj)
    obj_copy.pop(META_FIELD, None)
    sig = hmac.new(key.encode("utf-8"), canonical_json_bytes(obj_copy), hashlib.sha256).hexdigest()
    meta = {
        "hmac": sig,
        "hmac_algo": "sha256",
        "hmac_at": iso_time_now()
    }
    obj_to_write = dict(obj_copy)
    obj_to_write[META_FIELD] = meta
    atomic_write_json(path, obj_to_write)
    return sig


def verify_signed_metadata(path, hmac_key: str = None) -> Tuple[bool, dict]:
    """
    Load JSON from path, return (ok:bool, details:dict).
    details contains 'expected' and 'observed' HMAC or an error.
    """
    key = hmac_key or MANIFEST_HMAC_KEY
    if not os.path.exists(path):
        return False, {"error": "file_missing", "path": path}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            obj = json.load(fh)
    except Exception as e:
        return False, {"error": "json_load_error", "exc": str(e)}

    meta = obj.get(META_FIELD)
    if not meta:
        return False, {"error": "no_meta"}
    observed = meta.get("hmac")
    if observed is None:
        return False, {"error": "meta_missing_hmac"}

    obj_copy = dict(obj)
    obj_copy.pop(META_FIELD, None)
    expected = hmac.new(key.encode("utf-8"), canonical_json_bytes(obj_copy), hashlib.sha256).hexdigest()
    ok = (observed == expected)
    return ok, {"expected": expected, "observed": observed}


# Audit recording helper (tries DB first, falls back to file)
def record_audit(db, case_id, artifact_id, actor, action, details=None):
    """
    Record an append-only audit entry. Tries DB (if Audit model present), otherwise falls back to file.
    Import errors won't abort execution.
    """
    try:
        # import inside try to allow modules.models to not have Audit in some dev states
        from modules.models import Audit  # may raise ImportError
    except Exception:
        Audit = None

    if Audit:
        try:
            a = Audit(case_id=case_id, artifact_id=artifact_id, actor=actor, action=action,
                      details=json.dumps(details) if details else None)
            db.session.add(a)
            db.session.commit()
            return
        except Exception:
            try:
                db.session.rollback()
            except Exception:
                pass
            logger.exception("DB audit write failed; falling back to file log")

    # Fallback: file append
    try:
        os.makedirs("data", exist_ok=True)
        with open(os.path.join("data", "audit.log"), "a", encoding="utf-8") as fh:
            fh.write(json.dumps({
                "ts": iso_time_now(),
                "case_id": case_id,
                "artifact_id": artifact_id,
                "actor": actor,
                "action": action,
                "details": details
            }) + "\n")
    except Exception:
        logger.exception("Failed to write fallback audit log")


def append_integrity_record_to_metadata(metadata_path, integrity_record, sign=True):
    """
    Append integrity record to the artifact metadata JSON (creates analysis.integrity list if missing).
    If `sign` is True, re-sign the resulting metadata using write_signed_metadata so the _meta.hmac stays correct.
    Uses atomic writes.
    """
    try:
        if os.path.exists(metadata_path):
            with open(metadata_path, "r", encoding="utf-8") as fh:
                meta = json.load(fh)
        else:
            meta = {}

        # Ensure analysis structure exists
        analysis = meta.get("analysis") or {}
        integrity = analysis.get("integrity") or []
        integrity.append(integrity_record)
        analysis["integrity"] = integrity
        meta["analysis"] = analysis

        if sign:
            try:
                write_signed_metadata(metadata_path, meta)
            except Exception:
                logger.exception("write_signed_metadata failed while appending integrity; falling back to atomic write")
                atomic_write_json(metadata_path, meta)
        else:
            atomic_write_json(metadata_path, meta)
    except Exception:
        logger.exception("Failed to append integrity record to %s", metadata_path)


# Save uploaded file (updated to use atomic metadata write and optionally set readonly)
def save_uploaded_file(file_storage, case_id="case001", uploader="unknown", allowed_ext_set=None, make_readonly=False):
    """
    Save incoming FileStorage into evidence/<case_id>/artifacts/.
    Returns metadata dict on success (and writes signed artifact JSON beside saved file).
    Raises on failure.
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
    except Exception:
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
        "analysis": {}
    }

    # Write per-artifact metadata file atomically and signed
    meta_path = os.path.join(artifacts_dir, f"{artifact_id}.json")
    try:
        write_signed_metadata(meta_path, metadata)
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

    # Optionally make evidence read-only and record audit later by caller
    if make_readonly:
        try:
            os.chmod(saved_path, 0o444)
        except Exception:
            logger.exception("Failed to chmod readonly for %s", saved_path)

    return metadata

def load_signed_metadata_safe(path):
    """
    Load signed metadata JSON from path. If the file is missing, invalid JSON,
    or not a dict, return an empty dict.
    """
    try:
        if not os.path.exists(path):
            return {}
        with open(path, "r", encoding="utf-8") as fh:
            obj = json.load(fh)
        if not isinstance(obj, dict):
            return {}
        return obj
    except Exception:
        logger.exception("Failed to load metadata safely for %s", path)
        return {}

def normalize_metadata_dict(meta):
    """
    Ensure `meta` is a dict and has an `analysis` dict. Returns a normalized dict.
    (Does not write changes to disk.)
    """
    if not isinstance(meta, dict):
        meta = {}
    if meta.get("analysis") is None or not isinstance(meta.get("analysis"), dict):
        meta["analysis"] = {}
    return meta

def add_coc_entry(db, case_id, artifact_id, actor="system", action="access",
                  from_entity=None, to_entity=None, reason=None, location=None, details=None):
    """
    Create a ChainOfCustody DB row AND append to on-disk artifact metadata (signed) if present.
    db: SQLAlchemy db instance (modules.db.db)
    Returns the created DB row id and signature string.
    """

    # 🧹 Skip analyzer entries — we only want user/investigator actions
    if actor == "system:analyzer" and action == "analyzed":
        logger.debug(f"Skipping CoC analyzer entry for {artifact_id}")
        return None, None

    meta_path = None

    # 🧩 If actor wasn't passed, try reading investigator name from metadata JSON
    try:
        from modules.utils import ensure_case_dirs
        _, artifacts_dir = ensure_case_dirs(case_id)
        meta_path = os.path.join(artifacts_dir, f"{artifact_id}.json")

        if os.path.exists(meta_path):
            import json
            with open(meta_path, "r", encoding="utf-8") as f:
                meta = json.load(f)
            # use the uploader name recorded during upload
            actor = meta.get("uploaded_by") or actor or "investigator"

    except Exception:
        logger.warning(f"Could not determine investigator name for {artifact_id}")
        if not actor:
            actor = "investigator"

    # ✅ Extract filename from metadata if available
    filename = "-"
    try:
        if meta_path and os.path.exists(meta_path):
            import json
            with open(meta_path, "r", encoding="utf-8") as f:
                meta = json.load(f)
            filename = meta.get("original_filename") or meta.get("saved_filename") or "-"
    except Exception:
        logger.warning(f"Could not read filename for {artifact_id}")

    # ✅ Build payload (fixed missing comma & invalid timestamp key)
    from datetime import datetime
    payload = {
        "ts": datetime.utcnow().isoformat() + "Z",
        "case_id": case_id,
        "artifact_id": artifact_id,
        "filename": filename,
        "actor": actor,
        "action": action,
        "from": from_entity,
        "to": to_entity,
        "reason": reason,
        "location": location,
        "details": details
    }

    try:
        # compute signature
        sig = hmac_for_obj(payload, key=COC_HMAC_KEY)

        from modules.models import ChainOfCustody

        # DB insert
        coc = ChainOfCustody(
            case_id=case_id,
            artifact_id=artifact_id,
            actor=actor,
            action=action,
            from_entity=from_entity,
            to_entity=to_entity,
            reason=reason,
            location=location,
            details=json.dumps(details, default=str) if details else None,
            signature=sig
        )
        db.session.add(coc)
        db.session.commit()

        # append to artifact metadata JSON on disk if exists
        try:
            _, artifacts_dir = ensure_case_dirs(case_id)
            meta_path = os.path.join(artifacts_dir, f"{artifact_id}.json")
            if os.path.exists(meta_path):
                meta = load_signed_metadata_safe(meta_path)
                meta = normalize_metadata_dict(meta)
                meta.setdefault("analysis", {}).setdefault("coc", [])
                entry = dict(payload)
                entry["signature"] = sig
                meta["analysis"]["coc"].append(entry)
                try:
                    write_signed_metadata(meta_path, meta)
                except Exception:
                    atomic_write_json(meta_path, meta)
        except Exception:
            logger.exception("Failed to append CoC to artifact JSON for %s/%s", case_id, artifact_id)

        return coc.id, sig

    except Exception:
        logger.exception("add_coc_entry failed for %s/%s", case_id, artifact_id)
        try:
            db.session.rollback()
        except Exception:
            pass
        return None, None
