# modules/analysis.py
import json
from typing import Any, Dict
import os

def load_analysis_field(value) -> Dict:
    if not value:
        return {}
    if isinstance(value, dict):
        return value
    try:
        return json.loads(value)
    except Exception:
        return {}


def dump_analysis_field(obj: Any) -> str:
    try:
        return json.dumps(obj)
    except Exception:
        return json.dumps({})

def analyze_artifact(file_path, case_id=None, artifact_id=None):
    from modules import ioc, yara
    import heuristics

    try:
        # --- IOC analysis ---
        if case_id and artifact_id:
            ioc_result = ioc.check_iocs_for_artifact(case_id, artifact_id)
            ioc_matches = ioc_result.get("matches", [])
        else:
            ioc_matches = ioc.scan_file_for_iocs(file_path)

        # --- YARA analysis ---
        if case_id and artifact_id:
            yara_result = yara.scan_artifact(case_id, artifact_id)
            yara_matches = yara_result.get("matches", [])
        else:
            # fallback for direct file scan
            if hasattr(yara, "scan_file_with_yara"):
                yara_matches = yara.scan_file_with_yara(file_path)
            else:
                yara_matches = []
                print("[!] YARA module missing scan_file_with_yara() fallback.")
        
        # --- Heuristic analysis ---
        heuristics_report = heuristics.analyze_file(file_path)

    except Exception as e:
        print(f"[!] Analysis failed for {file_path}: {e}")
        return {"ioc_matches": [], "yara_matches": [], "heuristics": {}}

    return {
        "ioc_matches": ioc_matches,
        "yara_matches": yara_matches,
        "heuristics": heuristics_report
    }

def summarize_analysis(analysis_results: Dict) -> Dict:
    """
    Create a compact summary of IOC, YARA, and heuristic results.
    """
    summary = {
        "total_ioc_matches": len(analysis_results.get("ioc_matches", [])),
        "total_yara_matches": len(analysis_results.get("yara_matches", [])),
        "heuristics_summary": analysis_results.get("heuristics", {})
    }
    return summary

def merge_analysis_fields(field1: Dict, field2: Dict) -> Dict:
    merged = field1.copy()
    for key, value in field2.items():
        if key in merged:
            if isinstance(merged[key], list) and isinstance(value, list):
                merged[key].extend(value)
            elif isinstance(merged[key], dict) and isinstance(value, dict):
                merged[key] = merge_analysis_fields(merged[key], value)
            else:
                merged[key] = value 
        else:
            merged[key] = value
    return merged

def save_analysis_field(path: str, analysis_data: Dict):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(analysis_data, f, indent=2)
    except Exception as e:
        print(f"[!] Failed to save analysis data to {path}: {e}")
