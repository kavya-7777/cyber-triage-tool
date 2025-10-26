# modules/yara.py
"""
YARA integration for Cyber Triage Tool.
"""
import os
import json
import logging
import shutil

# Try to import yara; if not available we fall back gracefully
try:
    import yara  # noqa: F401
    YARA_AVAILABLE = True
except Exception:
    yara = None
    YARA_AVAILABLE = False

from modules.db import db
from modules.models import Artifact
from modules.utils import BASE_EVIDENCE_DIR, ensure_case_dirs

logger = logging.getLogger(__name__)

# Cached compiled rules + mtime
_COMPILED = None
_RULES_MTIME = None

# Size thresholds (bytes)
YARA_FULL_SCAN_FILESIZE_LIMIT = 10 * 1024 * 1024  # 10 MB - above this use snippet scan


def _load_analysis_field(x):
    if not x:
        return {}
    if isinstance(x, dict):
        return x
    try:
        return json.loads(x)
    except Exception:
        return {}


def compile_rules(rules_path="data/yara_rules.yar"):
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
    except yara.SyntaxError as e:
        msg = str(e)
        logger.error("YARA syntax error while compiling %s: %s", rules_path, msg)
        if "undefined identifier \"pe\"" in msg or "undefined identifier 'pe'" in msg:
            logger.error(
                "YARA rules reference the 'pe' module but the identifier is undefined. "
                "Ensure your rules include `import \"pe\"` and that yara-python/libyara was built with PE support."
            )
        _COMPILED = None
        return None
    except Exception:
        logger.exception("Failed to compile YARA rules: %s", rules_path)
        _COMPILED = None
        return None


def _find_saved_file(case_id, artifact_id):
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
        logger.exception("Failed listing artifacts dir %s", artifacts_dir)
    return None


def _parse_yara_matches(yara_matches):
    parsed = []
    if not yara_matches:
        return parsed
    try:
        for m in yara_matches:
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
        logger.debug("Skipping YARA scan for %s/%s because rules failed to compile.", case_id, artifact_id)
        return result
    result["compiled"] = True

    saved_path = _find_saved_file(case_id, artifact_id)
    if not saved_path or not os.path.exists(saved_path):
        result["error"] = "artifact file not found"
        return result

    try:
        filesize = os.path.getsize(saved_path)
        if filesize > YARA_FULL_SCAN_FILESIZE_LIMIT:
            with open(saved_path, "rb") as fh:
                snippet = fh.read(1024 * 1024)  # 1 MB
            yara_matches = compiled.match(data=snippet)
        else:
            yara_matches = compiled.match(filepath=saved_path)
    except Exception:
        logger.exception("YARA scan failed on %s", saved_path)
        result["error"] = "scan failed"
        return result

    parsed = _parse_yara_matches(yara_matches)
    result["matches"] = parsed

    # Persist results: artifact JSON -> analysis.yara_matches (safe merge)
    try:
        _, artifacts_dir = ensure_case_dirs(case_id)
        meta_path = os.path.join(artifacts_dir, f"{artifact_id}.json")
        if os.path.exists(meta_path):
            try:
                with open(meta_path, "r", encoding="utf-8") as f:
                    meta = json.load(f)
            except Exception:
                meta = {"artifact_id": artifact_id}
        else:
            meta = {"artifact_id": artifact_id}

        analysis = _load_analysis_field(meta.get("analysis"))
        analysis["yara_matches"] = parsed
        meta["analysis"] = analysis

        # atomic write
        tmp = meta_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(meta, fh, indent=2)
        os.replace(tmp, meta_path)
    except Exception:
        logger.exception("Failed writing artifact metadata with yara matches for %s/%s", case_id, artifact_id)

    # Persist into manifest (safe merge)
    try:
        manifest_path = os.path.join(BASE_EVIDENCE_DIR, case_id, "manifest.json")
        if os.path.exists(manifest_path):
            try:
                with open(manifest_path, "r", encoding="utf-8") as f:
                    manifest = json.load(f)
            except Exception:
                manifest = {"case_id": case_id, "artifacts": []}

            changed = False
            for ent in manifest.get("artifacts", []):
                if ent.get("artifact_id") == artifact_id:
                    existing = _load_analysis_field(ent.get("analysis"))
                    existing["yara_matches"] = parsed
                    ent["analysis"] = existing
                    changed = True
            if changed:
                tmpm = manifest_path + ".tmp"
                with open(tmpm, "w", encoding="utf-8") as fh:
                    json.dump(manifest, fh, indent=2)
                os.replace(tmpm, manifest_path)
    except Exception:
        logger.exception("Failed updating manifest with yara matches for %s/%s", case_id, artifact_id)

    # Persist into DB (Artifact.analysis) — filter by case_id as well
    try:
        art = Artifact.query.filter_by(artifact_id=artifact_id, case_id=case_id).first()
        if art:
            try:
                existing = {}
                if art.analysis:
                    try:
                        existing = json.loads(art.analysis)
                    except Exception:
                        existing = {}
                existing["yara_matches"] = parsed
                art.analysis = json.dumps(existing)
                db.session.add(art)
                db.session.commit()
            except Exception:
                logger.exception(
                    "Failed updating DB artifact.analysis with yara matches for %s/%s", artifact_id, case_id
                )
    except Exception:
        logger.exception("DB lookup failed while updating yara matches for %s/%s", artifact_id, case_id)

    return result