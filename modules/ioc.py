# modules/ioc.py
import os
import json
import re
import logging
from typing import List

from modules.utils import ensure_case_dirs, BASE_EVIDENCE_DIR
from modules.hashing import compute_sha256
from modules.db import db
from modules.models import Artifact

logger = logging.getLogger(__name__)

IOC_PATH_DEFAULT = os.path.join("data", "ioc.json")

# Small cache so load_iocs isn't re-reading file repeatedly during a run.
# You can call load_iocs(force_reload=True) to refresh from disk.
_ioc_cache = {"path": None, "mtime": None, "data": None}


def load_iocs(ioc_path=IOC_PATH_DEFAULT, force_reload: bool = False):
    """
    Load IOC file and normalize to sets.
    Expected structure (example):
    {
      "hashes": ["<sha256>", ...],
      "filenames": ["evil.exe", ...],
      "ips": ["1.2.3.4", ...],
      "domains": ["bad.example.com", ...]
    }
    """
    global _ioc_cache
    try:
        mtime = os.path.getmtime(ioc_path) if os.path.exists(ioc_path) else None
    except Exception:
        mtime = None

    if (not force_reload) and _ioc_cache["data"] is not None and _ioc_cache["path"] == ioc_path and _ioc_cache["mtime"] == mtime:
        return _ioc_cache["data"]

    if not os.path.exists(ioc_path):
        data = {"hashes": set(), "filenames": set(), "ips": set(), "domains": set()}
        _ioc_cache.update({"path": ioc_path, "mtime": mtime, "data": data})
        return data

    try:
        with open(ioc_path, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except Exception:
        logger.exception("Failed to load IOC file: %s", ioc_path)
        data = {"hashes": set(), "filenames": set(), "ips": set(), "domains": set()}
        _ioc_cache.update({"path": ioc_path, "mtime": mtime, "data": data})
        return data

    def as_set(key):
        items = raw.get(key, []) or []
        # normalize to lower-case strings for comparison
        return set([str(x).lower() for x in items if x is not None])

    data = {
        "hashes": as_set("hashes"),
        "filenames": as_set("filenames"),
        "ips": as_set("ips"),
        "domains": as_set("domains")
    }
    _ioc_cache.update({"path": ioc_path, "mtime": mtime, "data": data})
    return data


_IP_RE = re.compile(rb"(?:\d{1,3}\.){3}\d{1,3}")


def extract_ips_from_file_bytes(file_path, max_bytes=1024 * 1024) -> List[str]:
    """
    Read up to max_bytes of file and extract ASCII-like IPv4 addresses.
    Returns list of unique IP strings.
    """
    found = set()
    try:
        with open(file_path, "rb") as f:
            data = f.read(max_bytes)
        for m in _IP_RE.findall(data):
            try:
                ip = m.decode("utf-8")
            except Exception:
                try:
                    ip = m.decode("latin-1")
                except Exception:
                    continue
            parts = ip.split(".")
            if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                found.add(ip)
    except Exception:
        logger.exception("Failed extracting IPs from %s", file_path)
    return list(found)


def atomic_write_json(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)


def _normalize_filename(name: str) -> str:
    """
    Normalize filename for IOC comparisons: lowercase, strip surrounding whitespace.
    Keep full filename (including extension). This avoids false negatives due to case.
    """
    if not name:
        return ""
    return os.path.basename(name).strip().lower()


def _find_saved_file_if_missing(meta, case_id, artifact_id):
    """
    Helper: if saved_path missing, attempt to discover saved file in artifacts dir.
    """
    artifacts_dir = os.path.join(BASE_EVIDENCE_DIR, case_id, "artifacts")
    saved_path = meta.get("saved_path")
    if saved_path and os.path.exists(saved_path):
        return saved_path
    try:
        for fn in os.listdir(artifacts_dir):
            if fn.startswith(artifact_id + "__"):
                return os.path.join(artifacts_dir, fn)
    except Exception:
        logger.debug("Could not list artifacts dir %s", artifacts_dir)
    return None


def check_iocs_for_artifact(case_id, artifact_id, ioc_path=IOC_PATH_DEFAULT):
    """
    Run IOC checks for a single artifact.
    - Loads artifact metadata JSON (evidence/<case>/artifacts/<artifact_id>.json)
    - Ensures sha256 exists (computes if missing)
    - Loads iocs from ioc_path (cached) and matches on hash, filename, extracted ips/domains
    - Writes updates to artifact JSON (analysis.ioc_matches), case manifest, and DB Artifact.analysis
    Returns a dict with matches found.
    """
    matches = []
    artifact_meta_path = os.path.join(BASE_EVIDENCE_DIR, case_id, "artifacts", f"{artifact_id}.json")
    artifacts_dir = os.path.join(BASE_EVIDENCE_DIR, case_id, "artifacts")

    if not os.path.exists(artifact_meta_path):
        raise FileNotFoundError(f"Artifact metadata not found: {artifact_meta_path}")

    # load artifact metadata
    with open(artifact_meta_path, "r", encoding="utf-8") as f:
        meta = json.load(f)

    saved_path = _find_saved_file_if_missing(meta, case_id, artifact_id)

    # ensure sha256 exists
    sha = meta.get("sha256")
    if not sha:
        if saved_path and os.path.exists(saved_path):
            sha = compute_sha256(saved_path)
            meta["sha256"] = sha

    # load IOC data (cached automatically)
    iocs = load_iocs(ioc_path)

    # normalize artifact filename (original name provided at upload)
    filename_lower = _normalize_filename(meta.get("original_filename") or "")

    # 1) hash match (fast membership test)
    if sha and sha.lower() in iocs["hashes"]:
        matches.append({"type": "hash", "value": sha, "ioc": "hash", "match": True})

    # 2) filename match (exact or substring) - use normalized filename
    if filename_lower:
        for fn in iocs["filenames"]:
            if not fn:
                continue
            if fn == filename_lower or fn in filename_lower:
                matches.append({"type": "filename", "value": meta.get("original_filename"), "ioc": fn, "match": True})
                break

    # 3) extract IPs from file and match (use set intersection)
    ips_found = []
    if saved_path and os.path.exists(saved_path):
        try:
            ips_found = extract_ips_from_file_bytes(saved_path)
        except Exception:
            ips_found = []

    if ips_found:
        ip_set = set([ip.lower() for ip in ips_found])
        ip_iocs = iocs.get("ips", set())
        common_ips = ip_set & ip_iocs
        for ip in common_ips:
            matches.append({"type": "ip", "value": ip, "ioc": ip, "match": True})

    # 4) domain substring match inside a small snippet of the file (first 4KB)
    domains_found = []
    if saved_path and os.path.exists(saved_path):
        try:
            with open(saved_path, "rb") as f:
                snippet = f.read(4096)
            snippet_text = snippet.decode("utf-8", errors="ignore").lower()
            for d in iocs["domains"]:
                if d and d in snippet_text:
                    domains_found.append(d)
            for d in domains_found:
                matches.append({"type": "domain", "value": d, "ioc": d, "match": True})
        except Exception:
            logger.exception("Failed domain substring check on %s", saved_path)

    # write matches into artifact metadata (meta -> analysis.ioc_matches)
    try:
        meta["analysis"] = meta.get("analysis") or {}
        meta["analysis"]["ioc_matches"] = matches
        atomic_write_json(artifact_meta_path, meta)
    except Exception:
        logger.exception("Failed to write updated artifact metadata for %s/%s", case_id, artifact_id)

    # update manifest entry for this artifact (if present)
    try:
        manifest_path = os.path.join(BASE_EVIDENCE_DIR, case_id, "manifest.json")
        if os.path.exists(manifest_path):
            with open(manifest_path, "r", encoding="utf-8") as f:
                manifest = json.load(f)
            changed = False
            for entry in manifest.get("artifacts", []):
                if entry.get("artifact_id") == artifact_id:
                    entry["analysis"] = entry.get("analysis") or {}
                    entry["analysis"]["ioc_matches"] = matches
                    changed = True
            if changed:
                atomic_write_json(manifest_path, manifest)
    except Exception:
        logger.exception("Failed to update manifest with IOC matches for case %s", case_id)

    # update DB Artifact.analysis JSON
    try:
        art = Artifact.query.filter_by(artifact_id=artifact_id).first()
        if art:
            existing = {}
            if art.analysis:
                try:
                    existing = json.loads(art.analysis)
                except Exception:
                    existing = {}
            existing["ioc_matches"] = matches
            art.analysis = json.dumps(existing)
            db.session.commit()
    except Exception:
        logger.exception("Failed to update DB Artifact.analysis for %s", artifact_id)

    # return structured result
    return {
        "artifact_id": artifact_id,
        "case_id": case_id,
        "sha256": sha,
        "matches": matches,
        "found_ips": ips_found,
        "domains_found": domains_found
    }
