# modules/scoring.py
"""
Suspicion Scoring Engine (robust)
- Defensive extraction of IOC/YARA/Heuristics from artifact JSON shapes
- Component scoring functions + weighted final score
- Optional weights file: data/weights.json (overrides defaults)
- CLI for local testing: `python -m modules.scoring path/to/artifact.json`
"""

from typing import Dict, Any, List, Tuple, Optional
import json
import os
import logging

logger = logging.getLogger(__name__)

# Default weights (summing to 1.0)
DEFAULT_WEIGHTS = {
    "ioc": 0.40,
    "yara": 0.30,
    "heuristics": 0.30
}

# Per-IOC-type scores (0..100)
_IOC_TYPE_SCORES = {
    "hash": 100,
    "filename": 80,
    "ip": 60,
    "domain": 60,
    "default": 50
}

def _load_weights_from_disk(path: str = "data/weights.json") -> Dict[str, float]:
    """
    Optionally load weights from data/weights.json.
    Example:
      {"ioc": 0.5, "yara": 0.25, "heuristics": 0.25}
    If file missing or invalid, return DEFAULT_WEIGHTS.
    """
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            # validate simple keys
            w = {k: float(data.get(k, DEFAULT_WEIGHTS[k])) for k in DEFAULT_WEIGHTS}
            # normalize to sum=1.0 if not already
            total = sum(w.values()) or 1.0
            for k in w:
                w[k] = w[k] / total
            return w
    except Exception:
        logger.exception("Failed reading weights from %s; falling back to defaults", path)
    return DEFAULT_WEIGHTS.copy()

# --- defensive normalization of analysis blobs --- #
def _ensure_list(x):
    if not x:
        return []
    if isinstance(x, (list, tuple, set)):
        return list(x)
    # if string look like JSON list
    if isinstance(x, str):
        try:
            parsed = json.loads(x)
            if isinstance(parsed, list):
                return parsed
            # otherwise wrap
            return [parsed]
        except Exception:
            return [x]
    # single element -> wrap
    return [x]

def _normalize_analysis_blob(blob: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Return normalized dict with keys:
      - ioc_matches: list
      - yara_matches: list
      - heuristics: dict
    Accepts different shapes: artifact JSON (with 'analysis'), top-level analysis dict,
    or an 'analysis' JSON string.
    """
    if not blob:
        return {"ioc_matches": [], "yara_matches": [], "heuristics": {}}

    # If blob appears to be an artifact with an 'analysis' key, prefer that.
    analysis = None
    if isinstance(blob, dict) and "analysis" in blob:
        raw = blob.get("analysis")
        if isinstance(raw, str):
            try:
                analysis = json.loads(raw)
            except Exception:
                analysis = {}
        elif isinstance(raw, dict):
            analysis = raw
        else:
            analysis = {}
    elif isinstance(blob, dict) and any(k in blob for k in ("ioc_matches", "yara_matches", "heuristics")):
        analysis = blob
    else:
        # unknown shape -> try treating blob itself as analysis if dict
        if isinstance(blob, dict):
            analysis = blob
        else:
            analysis = {}

    # extract ioc_matches: allow several possible key names
    iocs = analysis.get("ioc_matches") or analysis.get("ioc") or analysis.get("iocs") or []
    iocs = _ensure_list(iocs)

    # extract yara_matches
    yaras = analysis.get("yara_matches") or analysis.get("yara") or analysis.get("yara_matches_list") or []
    yaras = _ensure_list(yaras)

    # heuristics
    heur = analysis.get("heuristics") or {}
    if isinstance(heur, str):
        try:
            heur = json.loads(heur)
        except Exception:
            heur = {}

    return {"ioc_matches": iocs, "yara_matches": yaras, "heuristics": heur}


# --- scoring functions for components --- #
def score_ioc(ioc_matches: Optional[List[Dict[str, Any]]]) -> Tuple[int, List[str]]:
    """
    Produce 0..100 IOC score and list of reasons (one per match).
    Logic:
      - If any hash match -> 100
      - Otherwise pick best available match type (filename > ip/domain > default)
    """
    if not ioc_matches:
        return 0, []

    best = 0
    reasons = []
    seen = set()
    for m in ioc_matches:
        if not isinstance(m, dict):
            # try normalize simple forms like strings
            t = "unknown"
            v = str(m)
        else:
            t = (m.get("type") or "unknown").lower()
            v = m.get("value") or m.get("ioc") or m.get("hash") or ""
        key = f"{t}:{v}"
        if key in seen:
            continue
        seen.add(key)
        reasons.append(f"IOC {t}: {v}")
        score_for_type = _IOC_TYPE_SCORES.get(t, _IOC_TYPE_SCORES["default"])
        if score_for_type > best:
            best = score_for_type

    return min(100, int(best)), reasons


def score_yara(yara_matches: Optional[List[Dict[str, Any]]]) -> Tuple[int, List[str]]:
    """
    0..100 YARA score and reasons.
    Heuristic: base 40 + 12 * n_rules (approx); capped at 100.
    Each rule contributes a readable reason with rule name and brief meta/tags.
    """
    if not yara_matches:
        return 0, []

    # normalize list forms where each match may be dict or string
    n = len(yara_matches)
    score = min(100, 40 + 12 * n)
    reasons = []
    for m in yara_matches:
        if isinstance(m, dict):
            rule = m.get("rule") or m.get("rule_name") or "<unnamed>"
            meta = m.get("meta") or {}
            tags = m.get("tags") or []
            snippet = ""
            if isinstance(meta, dict) and meta:
                try:
                    meta_snip = ",".join(f"{k}={v}" for k, v in list(meta.items())[:3])
                    snippet = f" (meta:{meta_snip})"
                except Exception:
                    snippet = ""
            if tags:
                snippet = snippet + (" tags:" + ",".join(map(str, tags)))
            reasons.append(f"YARA rule: {rule}{snippet}")
        else:
            reasons.append(f"YARA match: {str(m)}")
    return int(score), reasons


def score_heuristics(heur: Optional[Dict[str, Any]]) -> Tuple[int, List[str]]:
    """
    Map heuristics dict to 0..100 and reasons list.
    Expects heur to include 'suspicion_score' and 'reasons' where possible.
    """
    if not heur:
        return 0, []

    # try to get numeric suspicion_score (fallback to 0)
    try:
        raw = heur.get("suspicion_score", heur.get("score", 0))
        raw_val = int(round(float(raw)))
    except Exception:
        raw_val = 0

    reasons = []
    # collect reasons from multiple possible keys
    for key in ("reasons", "filename_reasons", "path_reasons"):
        r = heur.get(key)
        if isinstance(r, (list, tuple)):
            for item in r:
                try:
                    reasons.append(str(item))
                except Exception:
                    pass
    # add entropy summary if present
    if heur.get("entropy") is not None:
        try:
            reasons.append(f"entropy={float(heur.get('entropy')):.2f}")
        except Exception:
            pass
    if heur.get("filename_suspicious"):
        reasons.append("filename suspicious")
    if heur.get("unsigned_executable") is True:
        reasons.append("unsigned executable")
    return max(0, min(100, raw_val)), reasons


# --- main combiner --- #
def compute_final_score(analysis_blob: Optional[Dict[str, Any]],
                        weights: Optional[Dict[str, float]] = None,
                        weights_path: str = "data/weights.json") -> Dict[str, Any]:
    """
    Compute final 0..100 suspicion score.

    Inputs:
      - analysis_blob: artifact.analysis dict, or artifact dict (function will normalize)
      - weights: optional dict overriding defaults (keys: ioc,yara,heuristics)
      - weights_path: optional path to a JSON file that contains weights

    Returns:
      {
        "final_score": int,
        "breakdown": {"ioc_component": int, "yara_component": int, "heuristics_component": int},
        "weights": {...},
        "reasons": [...],
        "components": { "ioc": {...}, "yara": {...}, "heuristics": {...} }
      }
    """
    # load weights (priority: arg -> disk -> DEFAULT)
    if weights is None:
        try:
            weights = _load_weights_from_disk(weights_path)
        except Exception:
            weights = DEFAULT_WEIGHTS.copy()
    else:
        # normalize provided weights to sum=1.0
        try:
            total = sum(float(weights.get(k, DEFAULT_WEIGHTS[k])) for k in DEFAULT_WEIGHTS)
            if total <= 0:
                weights = DEFAULT_WEIGHTS.copy()
            else:
                weights = {k: float(weights.get(k, DEFAULT_WEIGHTS[k])) / total for k in DEFAULT_WEIGHTS}
        except Exception:
            weights = DEFAULT_WEIGHTS.copy()

    normalized = _normalize_analysis_blob(analysis_blob)
    ioc_matches = normalized["ioc_matches"]
    yara_matches = normalized["yara_matches"]
    heur = normalized["heuristics"]

    # component scores
    ioc_score, ioc_reasons = score_ioc(ioc_matches)
    yara_score, yara_reasons = score_yara(yara_matches)
    heur_score, heur_reasons = score_heuristics(heur)

    # apply weights (each component normalized 0..1 then weighted)
    w_i = float(weights.get("ioc", DEFAULT_WEIGHTS["ioc"]))
    w_y = float(weights.get("yara", DEFAULT_WEIGHTS["yara"]))
    w_h = float(weights.get("heuristics", DEFAULT_WEIGHTS["heuristics"]))

    comp_value = ( (ioc_score / 100.0) * w_i +
                   (yara_score / 100.0) * w_y +
                   (heur_score / 100.0) * w_h )

    final = int(round(max(0.0, min(1.0, comp_value)) * 100.0))

    # Build consolidated reasons (IOC -> YARA -> heuristics)
    reasons = []
    reasons.extend(ioc_reasons)
    reasons.extend(yara_reasons)
    reasons.extend(heur_reasons)

    # dedupe while preserving order
    seen = set()
    uniq_reasons = []
    for r in reasons:
        if r not in seen:
            seen.add(r)
            uniq_reasons.append(r)

    return {
        "final_score": final,
        "breakdown": {
            "ioc_component": int(ioc_score),
            "yara_component": int(yara_score),
            "heuristics_component": int(heur_score)
        },
        "weights": {"ioc": w_i, "yara": w_y, "heuristics": w_h},
        "reasons": uniq_reasons,
        "components": {
            "ioc": {"score": int(ioc_score), "reasons": ioc_reasons, "matches": ioc_matches},
            "yara": {"score": int(yara_score), "reasons": yara_reasons, "matches": yara_matches},
            "heuristics": {"score": int(heur_score), "reasons": heur_reasons, "raw": heur}
        }
    }


# CLI helper for quick testing
if __name__ == "__main__":
    import argparse, sys
    p = argparse.ArgumentParser(description="Compute final suspicion score for an artifact JSON")
    p.add_argument("jsonfile", help="artifact metadata JSON (artifact_id.json) or analysis JSON")
    p.add_argument("--weights", help="optional JSON file with weights (overrides data/weights.json)")
    args = p.parse_args()

    jf = args.jsonfile
    if not os.path.exists(jf):
        print("File not found:", jf)
        sys.exit(2)
    try:
        blob = json.load(open(jf, "r", encoding="utf-8"))
    except Exception as e:
        print("Failed loading JSON:", e)
        sys.exit(2)

    weights_path = args.weights or "data/weights.json"
    out = compute_final_score(blob, weights=None, weights_path=weights_path)
    print(json.dumps(out, indent=2))
