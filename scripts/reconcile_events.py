# scripts/reconcile_events.py
"""
Rebuild/repair events.json for a case from DB and manifest.
Usage:
  python scripts/reconcile_events.py case001
This script creates a backup of the old events.json (if present) under data/<case_id>/backups/
and writes a new data/<case_id>/events.json containing a single event with all artifacts.
"""
import os
import sys
import json
from datetime import datetime, timezone
from modules.db import db  # requires environment where modules is importable
from modules import models
from modules.utils import ensure_case_dirs, manifest_path_for_case, load_manifest  # note: load_manifest is in app.py; we replicate minimal logic
from modules.models import Artifact

def iso_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()

def rebuild_events(case_id):
    # gather artifacts from DB
    arts = []
    try:
        rows = Artifact.query.filter_by(case_id=case_id).all()
        for r in rows:
            try:
                analysis = None
                if r.analysis:
                    try:
                        analysis = json.loads(r.analysis) if isinstance(r.analysis, str) else r.analysis
                    except Exception:
                        analysis = r.analysis
                arts.append({
                    "artifact_id": r.artifact_id,
                    "original_filename": r.original_filename,
                    "saved_filename": r.saved_filename,
                    "saved_path": r.saved_path,
                    "size_bytes": r.size_bytes,
                    "uploaded_at": r.uploaded_at.isoformat() + "Z" if r.uploaded_at else iso_now(),
                    "uploaded_by": r.uploaded_by,
                    "analysis": analysis
                })
            except Exception:
                print()
    except Exception:
        arts = []

    # fallback: read manifest if DB had none
    if not arts:
        manifest_p = os.path.join("evidence", case_id, "manifest.json")
        if os.path.exists(manifest_p):
            try:
                with open(manifest_p, "r", encoding="utf-8") as fh:
                    m = json.load(fh)
                for e in m.get("artifacts", []):
                    arts.append(e)
            except Exception:
                pass

    # write events.json
    case_dir = os.path.join("data", case_id)
    os.makedirs(case_dir, exist_ok=True)
    events_p = os.path.join(case_dir, "events.json")
    # backup
    if os.path.exists(events_p):
        bakdir = os.path.join(case_dir, "backups")
        os.makedirs(bakdir, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        shutil.copy2(events_p, os.path.join(bakdir, f"events_{ts}.json"))

    top = {
        "timeline_preview": [
            {
                "id": f"rebuild-{iso_now()}",
                "source": "reconcile_events.py",
                "type": "event",
                "timestamp": iso_now(),
                "details": {
                    "case_id": case_id,
                    "created_at": iso_now(),
                    "artifacts": arts
                }
            }
        ],
        "_reconciled_at": iso_now()
    }
    with open(events_p, "w", encoding="utf-8") as fh:
        json.dump(top, fh, indent=2)
    print(f"Wrote {events_p} with {len(arts)} artifacts.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scripts/reconcile_events.py <case_id>")
        sys.exit(2)
    cid = sys.argv[1]
    rebuild_events(cid)
