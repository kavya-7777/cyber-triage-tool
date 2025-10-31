# modules/utils_events.py
"""
Safe helpers to read/write per-case events.json files under data/<case_id>/events.json
Uses atomic replace and creates backups. Non-destructive.
"""

import os
import json
import shutil
import uuid
from datetime import datetime, timezone

# Data directory sibling to modules/ -> project_root/modules/.. -> project_root/data
MODULE_DIR = os.path.dirname(__file__)
PROJECT_ROOT = os.path.abspath(os.path.join(MODULE_DIR, ".."))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
os.makedirs(DATA_DIR, exist_ok=True)


def iso_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def events_path_for_case(case_id: str) -> str:
    case_dir = os.path.join(DATA_DIR, case_id)
    os.makedirs(case_dir, exist_ok=True)
    return os.path.join(case_dir, "events.json")


def backup_events(case_id: str) -> str | None:
    p = events_path_for_case(case_id)
    if os.path.exists(p):
        bakdir = os.path.join(os.path.dirname(p), "backups")
        os.makedirs(bakdir, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        dst = os.path.join(bakdir, f"events_{ts}.json")
        shutil.copy2(p, dst)
        return dst
    return None


def atomic_write(path: str, data):
    """
    Write atomically by writing to .tmp then os.replace().
    This pattern is cross-platform.
    """
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.flush()
        try:
            os.fsync(f.fileno())
        except Exception:
            # os.fsync may not be available on some environments; ignore if it fails
            pass
    os.replace(tmp, path)


def load_events(case_id: str) -> dict:
    p = events_path_for_case(case_id)
    if not os.path.exists(p):
        return {"timeline_preview": []}
    try:
        with open(p, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        # if parse fails, return minimal structure
        return {"timeline_preview": []}


def append_event(case_id: str, artifacts):
    """
    Append an event for the given artifacts (a dict or list).
    Creates a timestamped backup before writing the new events.json.

    This version adds a small de-duplication guard: if the most recent
    timeline_preview item has the same type and the same first artifact_id
    we skip appending to avoid duplicates caused by callers double-writing.
    """
    if isinstance(artifacts, dict):
        artifacts = [artifacts]

    p = events_path_for_case(case_id)
    # load existing events structure
    ev = load_events(case_id)

    # determine event_type from artifacts payloads (same as before)
    event_type = "event"
    if isinstance(artifacts, list) and artifacts and isinstance(artifacts[0], dict):
        event_type = artifacts[0].get("type", "event")

    # --- dedupe guard: if latest preview already has same type & same artifact_id, skip ---
    try:
        latest = None
        if isinstance(ev.get("timeline_preview"), list) and ev["timeline_preview"]:
            latest = ev["timeline_preview"][0]
        if latest:
            latest_type = latest.get("type")
            latest_details = latest.get("details", {}) or {}
            latest_artifacts = latest_details.get("artifacts", []) or []
            # compare first artifact id (this mirrors how callers pass single-artifact events)
            if latest_type == event_type and latest_artifacts and artifacts and isinstance(artifacts[0], dict):
                latest_first_id = latest_artifacts[0].get("artifact_id")
                new_first_id = artifacts[0].get("artifact_id")
                if latest_first_id and new_first_id and latest_first_id == new_first_id:
                    # identical event already at front — skip writing duplicate
                    return
    except Exception:
        # if any error in dedupe logic, continue to write normally (fail-safe)
        pass

    event = {
        "id": str(uuid.uuid4()),
        "source": "processor",
        "type": event_type,
        "timestamp": iso_now(),
        "details": {
            "case_id": case_id,
            "created_at": iso_now(),
            "artifacts": artifacts
        }
    }

    # ensure timeline_preview exists and is a list
    if "timeline_preview" not in ev or not isinstance(ev["timeline_preview"], list):
        ev["timeline_preview"] = []

    # Prepend newest event into preview and write full file atomically
    ev["timeline_preview"].insert(0, event)

    # Keep preview length bounded (optional; keeps files small)
    try:
        MAX_PREVIEW = 200
        if len(ev["timeline_preview"]) > MAX_PREVIEW:
            ev["timeline_preview"] = ev["timeline_preview"][:MAX_PREVIEW]
    except Exception:
        pass

    # backup current file then write
    try:
        backup_events(case_id)
    except Exception:
        # non-fatal; continue
        pass

    atomic_write(p, ev)
