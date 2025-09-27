# modules/yara.py
"""
YARA integration for Cyber Triage Tool.

Features:
- compile_rules(rules_path) -> cached compiled rules (auto-recompile if file changed)
- scan_artifact(case_id, artifact_id, rules_path) -> run YARA on the artifact file,
  update artifact JSON + manifest + DB, and return structured matches.
- If yara-python is not installed, functions return empty results and log a warning.
"""
import os
import json
import logging
from modules.db import db
from modules.models import Artifact
from modules.utils import BASE_EVIDENCE_DIR, ensure_case_dirs

logger = logging.getLogger(__name__)

# Try to import yara; if not available we fall back gracefully
try:
    import yara
    YARA_AVAILABLE = True
except Exception:
    yara = None
    YARA_AVAILABLE = False

# Cached compiled rules + mtime
_COMPILED = None
_RULES_MTIME = None

# Size thresholds (bytes)
YARA_FULL_SCAN_FILESIZE_LIMIT = 10 * 1024 * 1024  # 10 MB - above this use snippet scan


def compile_rules(rules_path="data/yara_rules.yar"):
    """
    Compile yara rules and cache them. If file changes, recompile.
    Returns compiled rules object or None if compilation failed / not available.
    """
    global _COMPILED, _RULES_MTIME
    if not YARA_AVAILABLE:
        logger.warning("yara-python not installed; YARA scanning disabled")
        return None
    if not os.path.exists(rules_path):
        logger.warning("YARA rules file not found: %s", rules_path)
        return None
    try:
        mtime = os.path.getmtime(rules_path)
    except Exception:
        mtime = None
    if _COMPILED and _RULES_MTIME == mtime:
        return _COMPILED
    try:
        _COMPILED = yara.compile(filepath=rules_path)
        _RULES_MTIME = mtime
        logger.info("Compiled YARA rules from %s", rules_path)
        return _COMPILED
    except Exception:
        logger.exception("Failed to compile YARA rules: %s", rules_path)
        return None


def _find_saved_file(case_id, artifact_id):
    """
    Find the saved artifact file path using metadata JSON or prefix scan.
    """
    _, artifacts_dir = ensure_case_dirs(case_id)
    meta_path = os.path.join(artifacts_dir, f"{artifact_id}.json")
    saved_path = None
    if os.path.exists(meta_path):
        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                meta = json.load(f)
            saved_path = meta.get("saved_path")
        except Exception:
            logger.exception("Failed reading artifact metadata JSON %s", meta_path)
    if saved_path and os.path.exists(saved_path):
        return saved_path
    # fallback: find file by prefix <artifact_id>__
    try:
        for fname in os.listdir(artifacts_dir):
            if fname.startswith(artifact_id + "__"):
                return os.path.join(artifacts_dir, fname)
    except Exception:
        pass
    return None


def _parse_yara_matches(yara_matches):
    """
    Converts yara.Match objects into simple JSON-serializable dicts.
    """
    parsed = []
    try:
        for m in yara_matches:
            # m is a yara.match.Match
            item = {
                "rule": getattr(m, "rule", None),
                "tags": list(getattr(m, "tags", []) or []),
                "meta": getattr(m, "meta", {}) or {},
                "strings": []
            }
            for s in getattr(m, "strings", []) or []:
                try:
                    offset, sid, match_bytes = s
                    try:
                        decoded = match_bytes.decode("utf-8", errors="ignore")
                    except Exception:
                        decoded = None
                    item["strings"].append({
                        "offset": offset,
                        "id": sid,
                        "match": decoded if decoded else match_bytes.hex()
                    })
                except Exception:
                    item["strings"].append({"raw": repr(s)})
            parsed.append(item)
    except Exception:
        logger.exception("Failed parsing yara matches")
    return parsed


def scan_artifact(case_id, artifact_id, rules_path="data/yara_rules.yar"):
    """
    Run YARA on a single artifact file, update artifact JSON, manifest, and DB.
    Returns a dict with matches and some metadata.
    """
    result = {
        "case_id": case_id,
        "artifact_id": artifact_id,
        "yara_available": YARA_AVAILABLE,
        "matches": [],
        "compiled": False,
        "error": None
    }

    if not YARA_AVAILABLE:
        result["error"] = "yara-python not installed"
        return result

    compiled = compile_rules(rules_path)
    if compiled is None:
        result["error"] = "no compiled rules"
        return result
    result["compiled"] = True

    saved_path = _find_saved_file(case_id, artifact_id)
    if not saved_path or not os.path.exists(saved_path):
        result["error"] = "artifact file not found"
        return result

    try:
        # For very large files, scanning entire file via filepath can be slow.
        # Use a snippet-based scan if file exceeds threshold.
        filesize = os.path.getsize(saved_path)
        if filesize > YARA_FULL_SCAN_FILESIZE_LIMIT:
            # read leading snippet
            with open(saved_path, "rb") as fh:
                snippet = fh.read(1024 * 1024)  # 1 MB
            yara_matches = compiled.match(data=snippet)
        else:
            # scan whole file by filepath
            yara_matches = compiled.match(filepath=saved_path)
    except Exception:
        logger.exception("YARA scan failed on %s", saved_path)
        result["error"] = "scan failed"
        return result

    parsed = _parse_yara_matches(yara_matches)
    result["matches"] = parsed

    # Persist results: artifact JSON -> analysis.yara_matches
    try:
        _, artifacts_dir = ensure_case_dirs(case_id)
        meta_path = os.path.join(artifacts_dir, f"{artifact_id}.json")
        if os.path.exists(meta_path):
            with open(meta_path, "r", encoding="utf-8") as f:
                meta = json.load(f)
        else:
            meta = {"artifact_id": artifact_id}

        meta["analysis"] = meta.get("analysis") or {}
        meta["analysis"]["yara_matches"] = parsed

        # atomic write
        tmp = meta_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(meta, fh, indent=2)
        os.replace(tmp, meta_path)
    except Exception:
        logger.exception("Failed writing artifact metadata with yara matches for %s/%s", case_id, artifact_id)

    # Persist into manifest
    try:
        manifest_path = os.path.join(BASE_EVIDENCE_DIR, case_id, "manifest.json")
        if os.path.exists(manifest_path):
            with open(manifest_path, "r", encoding="utf-8") as f:
                manifest = json.load(f)
            changed = False
            for ent in manifest.get("artifacts", []):
                if ent.get("artifact_id") == artifact_id:
                    ent["analysis"] = ent.get("analysis") or {}
                    ent["analysis"]["yara_matches"] = parsed
                    changed = True
            if changed:
                tmpm = manifest_path + ".tmp"
                with open(tmpm, "w", encoding="utf-8") as fh:
                    json.dump(manifest, fh, indent=2)
                os.replace(tmpm, manifest_path)
    except Exception:
        logger.exception("Failed updating manifest with yara matches for %s/%s", case_id, artifact_id)

    # Persist into DB (Artifact.analysis)
    try:
        art = Artifact.query.filter_by(artifact_id=artifact_id).first()
        if art:
            existing = {}
            if art.analysis:
                try:
                    existing = json.loads(art.analysis)
                except Exception:
                    existing = {}
            existing["yara_matches"] = parsed
            art.analysis = json.dumps(existing)
            db.session.commit()
    except Exception:
        logger.exception("Failed updating DB artifact.analysis with yara matches for %s", artifact_id)

    return result
