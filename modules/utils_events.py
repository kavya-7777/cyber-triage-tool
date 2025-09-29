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
    """
    if isinstance(artifacts, dict):
        artifacts = [artifacts]

    p = events_path_for_case(case_id)
    # load existing events structure
    ev = load_events(case_id)

    # create event structure compatible with your timeline expectations
    event = {
        "id": str(uuid.uuid4()),
        "source": "processor",
        "type": "event",
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

    # insert at front (most-recent-first) to match existing UIs that show preview[0]
    ev["timeline_preview"].insert(0, event)

    # backup then write
    try:
        backup_events(case_id)
    except Exception:
        # don't block on backup failure
        pass

    atomic_write(p, ev)
    return event
