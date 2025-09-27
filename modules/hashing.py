# modules/hashing.py
import hashlib
import os
import json
import logging

from modules.utils import ensure_case_dirs, BASE_EVIDENCE_DIR
from modules.db import db
from modules.models import Artifact

logger = logging.getLogger(__name__)

def compute_sha256(file_path):
    """
    Compute SHA-256 of file at file_path in streaming fashion.
    Returns hex digest string.
    """
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def update_artifact_hash(case_id, artifact_id, sha256_hex):
    """
    Update per-artifact JSON, the case manifest, and the DB artifact.analysis field
    to include the computed sha256.
    This function expects to be called inside a Flask request/app context so DB is available.
    """
    # 1) Update artifact metadata JSON (evidence/<case>/artifacts/<artifact_id>.json)
    try:
        _, artifacts_dir = ensure_case_dirs(case_id)
        meta_path = os.path.join(artifacts_dir, f"{artifact_id}.json")
        if os.path.exists(meta_path):
            with open(meta_path, "r", encoding="utf-8") as f:
                metadata = json.load(f)
            # write sha256 at top-level and also merge into analysis
            metadata["sha256"] = sha256_hex
            # merge into analysis field (keep existing keys if present)
            if metadata.get("analysis") is None:
                metadata["analysis"] = {"sha256": sha256_hex}
            else:
                try:
                    if isinstance(metadata["analysis"], dict):
                        metadata["analysis"]["sha256"] = sha256_hex
                    else:
                        # if string, try parse
                        parsed = json.loads(metadata["analysis"])
                        parsed["sha256"] = sha256_hex
                        metadata["analysis"] = parsed
                except Exception:
                    metadata["analysis"] = {"sha256": sha256_hex}

            # atomic write
            temp_meta = meta_path + ".tmp"
            with open(temp_meta, "w", encoding="utf-8") as f:
                json.dump(metadata, f, indent=2)
            os.replace(temp_meta, meta_path)
    except Exception:
        logger.exception("Failed updating artifact metadata JSON for %s/%s", case_id, artifact_id)

    # 2) Update manifest.json for the case
    try:
        manifest_path = os.path.join(BASE_EVIDENCE_DIR, case_id, "manifest.json")
        if os.path.exists(manifest_path):
            with open(manifest_path, "r", encoding="utf-8") as f:
                manifest = json.load(f)
            changed = False
            for entry in manifest.get("artifacts", []):
                if entry.get("artifact_id") == artifact_id:
                    entry["sha256"] = sha256_hex
                    # ensure analysis merged like above
                    if entry.get("analysis") is None:
                        entry["analysis"] = {"sha256": sha256_hex}
                    else:
                        try:
                            if isinstance(entry["analysis"], dict):
                                entry["analysis"]["sha256"] = sha256_hex
                            else:
                                parsed = json.loads(entry["analysis"])
                                parsed["sha256"] = sha256_hex
                                entry["analysis"] = parsed
                        except Exception:
                            entry["analysis"] = {"sha256": sha256_hex}
                    changed = True
            if changed:
                temp_manifest = manifest_path + ".tmp"
                with open(temp_manifest, "w", encoding="utf-8") as f:
                    json.dump(manifest, f, indent=2)
                os.replace(temp_manifest, manifest_path)
    except Exception:
        logger.exception("Failed updating manifest for case %s", case_id)

    # 3) Update DB Artifact.analysis JSON (store/merge sha256)
    try:
        artifact = Artifact.query.filter_by(artifact_id=artifact_id).first()
        if artifact:
            existing = {}
            if artifact.analysis:
                try:
                    existing = json.loads(artifact.analysis)
                except Exception:
                    existing = {}
            existing["sha256"] = sha256_hex
            artifact.analysis = json.dumps(existing)
            db.session.commit()
    except Exception:
        logger.exception("Failed updating DB artifact for %s", artifact_id)
