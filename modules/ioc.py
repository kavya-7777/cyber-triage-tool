# modules/ioc.py

import os
import json
import re
import logging
from typing import List, Dict, Any, Optional

from modules.utils import ensure_case_dirs, BASE_EVIDENCE_DIR
from modules.hashing import compute_sha256
from modules.db import db
from modules.models import Artifact

logger = logging.getLogger(__name__)

IOC_PATH_DEFAULT = os.path.join("data", "ioc.json")
_ioc_cache = {"path": None, "mtime": None, "data": None}
_IP_RE = re.compile(rb"(?:\d{1,3}\.){3}\d{1,3}")

def _value_of(item):
    """Return string value whether item is plain string or object with 'value' key."""
    if item is None:
        return None
    if isinstance(item, str):
        return item
    if isinstance(item, dict):
        # try common keys
        return item.get("value") or item.get("v") or None
    try:
        return str(item)
    except Exception:
        return None


def _as_set_of_values(raw_list):
    """
    Accepts either list of strings or list of objects like {"value": "..."}.
    Returns a set of normalized lower-case strings (where applicable).
    """
    out = set()
    for it in (raw_list or []):
        v = _value_of(it)
        if v is None:
            continue
        out.add(str(v).strip().lower())
    return out


def _as_list_of_values(raw_list):
    """Return plain list preserving order where possible (for e.g. regex rules)."""
    out = []
    for it in (raw_list or []):
        v = _value_of(it)
        if v is None:
            continue
        out.append(str(v))
    return out


def _normalize_domain_repr(d: str) -> str:
    """Convert common obfuscations like 'example[.]com' -> 'example.com' and lowercase."""
    if not d:
        return ""
    s = str(d).strip()
    s = s.replace("[.]", ".").replace("(.)", ".").replace("[dot]", ".")
    s = s.replace(" . ", ".")
    return s.lower()


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
    """Normalize filename for IOC comparisons: lowercase, strip surrounding whitespace."""
    if not name:
        return ""
    return os.path.basename(name).strip().lower()

def load_iocs(ioc_path=IOC_PATH_DEFAULT, force_reload: bool = False) -> Dict[str, Any]:
    """
    Load IOC file and normalize into a dictionary of useful sets/lists.
    """
    global _ioc_cache
    try:
        mtime = os.path.getmtime(ioc_path) if os.path.exists(ioc_path) else None
    except Exception:
        mtime = None

    if (not force_reload) and _ioc_cache["data"] is not None and _ioc_cache["path"] == ioc_path and _ioc_cache["mtime"] == mtime:
        return _ioc_cache["data"]

    if not os.path.exists(ioc_path):
        data = {
            "hashes": set(),
            "filenames": set(),
            "filename_regex": [],
            "filename_regex_patterns": [],
            "ips": set(),
            "domains": set(),
            "urls": set(),
            "extensions": set(),
            "yara_strings": set(),
            "raw": {}
        }
        _ioc_cache.update({"path": ioc_path, "mtime": mtime, "data": data})
        return data

    try:
        with open(ioc_path, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except Exception:
        logger.exception("Failed to load IOC file: %s", ioc_path)
        data = {
            "hashes": set(),
            "filenames": set(),
            "filename_regex": [],
            "filename_regex_patterns": [],
            "ips": set(),
            "domains": set(),
            "urls": set(),
            "extensions": set(),
            "yara_strings": set(),
            "raw": {}
        }
        _ioc_cache.update({"path": ioc_path, "mtime": mtime, "data": data})
        return data

    # Extract values (handles objects or plain strings)
    hashes = _as_set_of_values(raw.get("hashes", []))
    hashes = set([h.strip().lower() for h in hashes if h])

    filenames = _as_set_of_values(raw.get("filenames", []))

    ips = _as_set_of_values(raw.get("ips", []))

    # domains: keep normalized representation
    domains_raw = _as_list_of_values(raw.get("domains", []))
    domains = set()
    for d in domains_raw:
        nd = _normalize_domain_repr(d)
        if nd:
            domains.add(nd)

    # filename regex
    filename_regex_list = _as_list_of_values(raw.get("filename_regex", []))
    compiled_patterns = []
    for rx in filename_regex_list:
        try:
            compiled_patterns.append(re.compile(rx, flags=re.IGNORECASE))
        except re.error:
            logger.warning("Invalid filename_regex ignored: %s", rx)

    urls = _as_set_of_values(raw.get("urls", []))

    # normalize extensions, ensure they start with '.'
    exts_raw = _as_list_of_values(raw.get("extensions", []))
    extensions = set()
    for e in exts_raw:
        if not e:
            continue
        s = str(e).strip().lower()
        if not s:
            continue
        if not s.startswith("."):
            s = "." + s
        extensions.add(s)

    yara_strings = set([s.strip().lower() for s in _as_list_of_values(raw.get("yara_strings", [])) if s])

    data = {
        "hashes": hashes,
        "filenames": filenames,
        "filename_regex": filename_regex_list,
        "filename_regex_patterns": compiled_patterns,
        "ips": ips,
        "domains": domains,
        "urls": urls,
        "extensions": extensions,
        "yara_strings": yara_strings,
        "raw": raw
    }

    _ioc_cache.update({"path": ioc_path, "mtime": mtime, "data": data})
    return data

def _find_saved_file_if_missing(meta, case_id, artifact_id):
    """
    Try to locate the saved artifact file.
    Handles both normal and ZIP-extracted files under uploads/zip_* subdirs.
    """
    artifacts_dir = os.path.join(BASE_EVIDENCE_DIR, case_id, "artifacts")
    saved_path = meta.get("saved_path")

    # ✅ 1) If metadata already contains valid saved_path, return it
    if saved_path and os.path.exists(saved_path):
        return saved_path

    try:
        # ✅ 2) Search directly under artifacts/ for prefix match
        if os.path.isdir(artifacts_dir):
            for fn in os.listdir(artifacts_dir):
                if fn.startswith(artifact_id + "__") or fn.startswith(artifact_id):
                    candidate = os.path.join(artifacts_dir, fn)
                    if os.path.exists(candidate) and not candidate.lower().endswith(".json"):
                        return candidate

        # ✅ 3) Recursively walk uploads/zip_* subfolders
        uploads_dir = os.path.join(artifacts_dir, "uploads")
        if os.path.isdir(uploads_dir):
            for root, _, files in os.walk(uploads_dir):
                for fn in files:
                    # Match artifact prefix or exact filename stored in metadata
                    if fn.startswith(artifact_id) or fn == os.path.basename(meta.get("original_filename", "")):
                        candidate = os.path.join(root, fn)
                        if os.path.exists(candidate):
                            logger.info(f"Found ZIP-extracted file for {artifact_id}: {candidate}")
                            return candidate
    except Exception:
        logger.debug("Could not search artifacts dir %s for saved file (non-fatal)", artifacts_dir)

    return None

def _search_upload_manifest_for_artifact(case_id: str, artifact_id: str) -> Optional[str]:
    """
    Look for a manifest.json under artifacts/uploads and try to map artifact_id -> metadata or saved file.
    Returns a path to a JSON metadata if found, else None.
    """
    artifacts_dir = os.path.join(BASE_EVIDENCE_DIR, case_id, "artifacts")
    # scan uploads subfolders for manifest.json
    for root, dirs, files in os.walk(artifacts_dir):
        for fname in files:
            if fname.lower() == "manifest.json":
                path = os.path.join(root, fname)
                try:
                    with open(path, "r", encoding="utf-8") as fh:
                        m = json.load(fh)
                    # expect manifest to have "artifacts" list with dicts containing artifact_id and maybe saved_path
                    for ent in m.get("artifacts", []):
                        if ent.get("artifact_id") == artifact_id:
                            # prefer explicit metadata path if present
                            if ent.get("meta_path") and os.path.exists(ent.get("meta_path")):
                                return ent.get("meta_path")
                            # or saved_path
                            if ent.get("saved_path") and os.path.exists(ent.get("saved_path")):
                                # not metadata, but return None so caller can still find file via other helper
                                return None
                except Exception:
                    logger.debug("Skipping unreadable upload manifest %s", path)
    return None


def _find_artifact_meta_by_id(case_id: str, artifact_id: str) -> Optional[str]:
    artifacts_dir = os.path.join(BASE_EVIDENCE_DIR, case_id, "artifacts")
    # 1) canonical path
    possible = os.path.join(artifacts_dir, f"{artifact_id}.json")
    if os.path.exists(possible):
        return possible

    # 2) common extractor naming
    possible2 = os.path.join(artifacts_dir, f"extracted__{artifact_id}.json")
    if os.path.exists(possible2):
        return possible2

    # ensure artifacts_dir exists
    if not os.path.isdir(artifacts_dir):
        logger.debug("Artifacts directory missing for case %s: %s", case_id, artifacts_dir)
        return None

    # 3) recursive scan: search JSON file contents for artifact_id
    for root, _, files in os.walk(artifacts_dir):
        for fname in files:
            if not fname.lower().endswith(".json"):
                continue
            path = os.path.join(root, fname)
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    data = fh.read()
                # direct substring check is fast and often sufficient
                if artifact_id in data:
                    logger.debug("Found artifact meta by content search: %s -> %s", artifact_id, path)
                    return path
            except Exception as e:
                logger.debug("Skipping unreadable json %s: %s", path, e)

    # 4) filename-based fallback: find any file whose name contains the artifact_id (json preferred)
    for root, _, files in os.walk(artifacts_dir):
        for fname in files:
            if artifact_id in fname:
                candidate = os.path.join(root, fname)
                logger.debug("Found file by filename match for artifact_id: %s -> %s", artifact_id, candidate)
                if candidate.lower().endswith(".json"):
                    return candidate

    return None

def normalize_extracted_metadata(case_id: str) -> int:
    artifacts_dir = os.path.join(BASE_EVIDENCE_DIR, case_id, "artifacts")
    if not os.path.isdir(artifacts_dir):
        return 0
    normalized = 0
    for root, _, files in os.walk(artifacts_dir):
        for fname in files:
            # match extracted__<artifact_id>.json or extracted__<artifact_id>.<ext>.json
            if fname.startswith("extracted__") and fname.lower().endswith(".json"):
                full = os.path.join(root, fname)
                # derive artifact_id heuristically
                rest = fname[len("extracted__"):]
                artifact_id = rest.split(".")[0]
                canonical = os.path.join(artifacts_dir, f"{artifact_id}.json")
                try:
                    # load metadata and update saved_path if needed (if metadata references a file in subfolder)
                    with open(full, "r", encoding="utf-8") as fh:
                        meta = json.load(fh)
                    # if saved_path is missing or points to nested file, try to guess saved file
                    saved_guess = meta.get("saved_path")
                    if not saved_guess or not os.path.exists(saved_guess):
                        # try sibling file(s) in same directory with same prefix
                        possible_files = [f for f in os.listdir(root) if f.startswith(artifact_id)]
                        if possible_files:
                            # choose first; prefer non-json files as saved content
                            sel = None
                            for pf in possible_files:
                                if not pf.lower().endswith(".json"):
                                    sel = pf
                                    break
                            if not sel:
                                sel = possible_files[0]
                            saved_guess = os.path.join(root, sel)
                            meta["saved_path"] = os.path.abspath(saved_guess)
                    # persist into canonical path (atomic)
                    tmp = canonical + ".tmp"
                    with open(tmp, "w", encoding="utf-8") as fh:
                        json.dump(meta, fh, indent=2)
                    os.replace(tmp, canonical)
                    normalized += 1
                except Exception:
                    logger.exception("Failed normalizing metadata file %s", full)
    return normalized

def check_iocs_for_artifact(case_id, artifact_id, ioc_path=IOC_PATH_DEFAULT):
    matches = []

    # ensure artifact_meta_path is always defined
    artifact_meta_path = os.path.join(BASE_EVIDENCE_DIR, case_id, "artifacts", f"{artifact_id}.json")

    # If canonical metadata file doesn't exist, attempt a robust fallback search
    if not os.path.exists(artifact_meta_path):
        try:
            # 1) scan for metadata files or files mentioning the artifact id
            found = _find_artifact_meta_by_id(case_id, artifact_id)
            if found:
                artifact_meta_path = found
                logger.info("Fallback artifact metadata located for %s/%s -> %s", case_id, artifact_id, artifact_meta_path)
            else:
                # 2) try upload-manifest mapping (some extractors create their own manifest.json)
                try:
                    manifest_meta = _search_upload_manifest_for_artifact(case_id, artifact_id)
                    if manifest_meta:
                        artifact_meta_path = manifest_meta
                        logger.info("Found metadata via upload manifest for %s/%s -> %s", case_id, artifact_id, artifact_meta_path)
                    else:
                        logger.debug("Fallback search did not find metadata for %s/%s in %s", case_id, artifact_id, os.path.join(BASE_EVIDENCE_DIR, case_id, "artifacts"))
                except Exception:
                    logger.exception("Upload-manifest lookup failed for %s/%s", case_id, artifact_id)
        except Exception:
            logger.exception("Fallback artifact metadata scan failed for %s/%s", case_id, artifact_id)

    # If still missing, return a neutral structured result (do not raise)
    if not os.path.exists(artifact_meta_path):
        # Lower severity to warning because we may still find metadata in nested locations later;
        # caller uses fallbacks and this condition is not fatal.
        logger.warning("Artifact metadata not found for %s/%s (looked for %s)", case_id, artifact_id, artifact_meta_path)
        return {
            "artifact_id": artifact_id,
            "case_id": case_id,
            "sha256": None,
            "matches": [],
            "found_ips": [],
            "domains_found": [],
            "urls_found": [],
            "yara_strings_found": [],
            "error": "artifact_meta_not_found"
        }

    # load artifact metadata
    try:
        with open(artifact_meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
    except Exception:
        logger.exception("Failed loading artifact metadata JSON %s", artifact_meta_path)
        return {
            "artifact_id": artifact_id,
            "case_id": case_id,
            "sha256": None,
            "matches": [],
            "found_ips": [],
            "domains_found": [],
            "urls_found": [],
            "yara_strings_found": [],
            "error": "artifact_meta_read_error"
        }

    saved_path = _find_saved_file_if_missing(meta, case_id, artifact_id)

    # ensure sha256 exists
    sha = meta.get("sha256")
    if not sha:
        if saved_path and os.path.exists(saved_path):
            sha = compute_sha256(saved_path)
            meta["sha256"] = sha

    # persist sha into artifact meta immediately (atomic)
    try:
        meta_on_disk = {}
        if os.path.exists(artifact_meta_path):
            with open(artifact_meta_path, "r", encoding="utf-8") as fh:
                meta_on_disk = json.load(fh)
        meta_on_disk.update(meta)
        atomic_write_json(artifact_meta_path, meta_on_disk)
    except Exception:
        logger.exception("Failed persisting sha into artifact metadata for %s/%s", case_id, artifact_id)


    # load IOC data (cached automatically)
    iocs = load_iocs(ioc_path)

    # normalize artifact filename (original name provided at upload)
    filename_lower = _normalize_filename(meta.get("original_filename") or "")
    _, ext = os.path.splitext(filename_lower)

    # 1) hash match (fast membership test)
    if isinstance(sha, list) and sha:
        sha = sha[0]  # take the first hash if list provided
        
    if not isinstance(sha, str):
        sha = str(sha or "")

    if isinstance(sha, (bytes, bytearray)):
        try:
            sha = sha.decode("utf-8", errors="ignore")
        except Exception:
            sha = None

    if isinstance(sha, str) and sha.lower() in iocs["hashes"]:
        matches.append({
            "type": "hash",
            "value": sha,
            "ioc": "hash",
            "match": True
        })

    # 2) filename exact / substring match (use normalized filename)
    if filename_lower:
        for fn in iocs["filenames"]:
            if not fn:
                continue
            if fn == filename_lower or fn in filename_lower:
                matches.append({"type": "filename", "value": meta.get("original_filename"), "ioc": fn, "match": True})
                break

    # 2b) filename regex matches (use compiled patterns)
    for pat in iocs.get("filename_regex_patterns", []) or []:
        try:
            if filename_lower and pat.search(filename_lower):
                matches.append({"type": "filename_regex", "value": meta.get("original_filename"), "ioc": pat.pattern, "match": True})
                break
        except Exception:
            continue

    # 2c) extension match
    if ext and ext.lower() in iocs.get("extensions", set()):
        matches.append({"type": "extension", "value": ext.lower(), "ioc": "extension", "match": True})

    # 3) extract IPs from file and match (use set intersection)
    ips_found = []
    if saved_path and os.path.exists(saved_path):
        try:
            ips_found = extract_ips_from_file_bytes(saved_path)
        except Exception:
            ips_found = []

    if ips_found:
        ip_set = set()
        for ip in ips_found:
            if isinstance(ip, tuple):
                ip = ip[0]
            if isinstance(ip, bytes):
                try:
                    ip = ip.decode("utf-8", errors="ignore")
                except Exception:
                    continue
            if isinstance(ip, str):
                ip_set.add(ip.strip().lower())

        ip_iocs = set()
        for ip in iocs.get("ips", set()):
            if isinstance(ip, (list, tuple)):
                for sub in ip:
                    if isinstance(sub, str):
                        ip_iocs.add(sub.strip().lower())
            elif isinstance(ip, bytes):
                try:
                    ip_iocs.add(ip.decode("utf-8", errors="ignore").strip().lower())
                except Exception:
                    continue
            elif isinstance(ip, str):
                ip_iocs.add(ip.strip().lower())

        common_ips = ip_set & ip_iocs
        for ip in common_ips:
            matches.append({
                "type": "ip",
                "value": ip,
                "ioc": ip,
                "match": True
            })

    # 4) domain substring match inside a small snippet of the file (first 8KB)
    domains_found = []
    urls_found = []
    yara_found = []
    if saved_path and os.path.exists(saved_path):
        try:
            with open(saved_path, "rb") as f:
                snippet = f.read(8192)
            snippet_text = snippet.decode("utf-8", errors="ignore").lower()

            # --- Domains ---
            for d in iocs.get("domains", set()):
                val = _value_of(d)
                if not val:
                    continue
                val = str(val).strip().lower()
                if val and val in snippet_text:
                    domains_found.append(val)
                    matches.append({
                        "type": "domain",
                        "value": val,
                        "ioc": val,
                        "match": True
                    })

            # --- URLs ---
            for u in iocs.get("urls", set()):
                val = _value_of(u)
                if not val:
                    continue
                val = str(val).strip().lower()
                if val and val in snippet_text:
                    urls_found.append(val)
                    matches.append({
                        "type": "url",
                        "value": val,
                        "ioc": val,
                        "match": True
                    })

            # --- YARA strings ---
            for ys in iocs.get("yara_strings", set()):
                val = _value_of(ys)
                if not val:
                    continue
                val = str(val).strip().lower()
                if val and val in snippet_text:
                    yara_found.append(val)
                    matches.append({
                        "type": "yara_string",
                        "value": val,
                        "ioc": val,
                        "match": True
                    })

        except Exception:
            logger.exception("Failed domain/url/yara_string substring checks on %s", saved_path)

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
                    existing = entry.get("analysis") or {}
                    existing["ioc_matches"] = matches
                    entry["analysis"] = existing
                    changed = True
            if changed:
                atomic_write_json(manifest_path, manifest)
    except Exception:
        logger.exception("Failed to update manifest with IOC matches for case %s", case_id)

    # update DB Artifact.analysis
    try:
        art = Artifact.query.filter_by(artifact_id=artifact_id, case_id=case_id).first()
        if art:
            existing = {}
            if art.analysis:
                try:
                    existing = json.loads(art.analysis)
                except Exception:
                    existing = {}
            existing["ioc_matches"] = matches
            art.analysis = json.dumps(existing)
            db.session.add(art)
            try:
                db.session.commit()
            except Exception:
                db.session.rollback()
                logger.exception("Failed to commit DB Artifact.analysis for %s (rolled back)", artifact_id)
    except Exception:
        try:
            db.session.rollback()
        except Exception:
            pass
        logger.exception("Failed to update DB Artifact.analysis for %s", artifact_id)

    # return structured result
    return {
        "artifact_id": artifact_id,
        "case_id": case_id,
        "sha256": sha,
        "matches": matches,
        "found_ips": ips_found,
        "domains_found": domains_found,
        "urls_found": urls_found,
        "yara_strings_found": yara_found
    }


def scan_file_for_iocs(file_path):
    matches = []
    try:
        with open(file_path, "rb") as f:
            data = f.read(8192)
        text = data.decode("utf-8", errors="ignore").lower()

        ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
        url_re = re.compile(r"https?://[^\s'\"]+")
        email_re = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")

        for ip in ip_re.findall(text):
            matches.append({"type": "ip", "value": ip})
        for url in url_re.findall(text):
            matches.append({"type": "url", "value": url})
        for email in email_re.findall(text):
            matches.append({"type": "email", "value": email})
    except Exception as e:
        logger.error("scan_file_for_iocs failed: %s", e)

    return matches
