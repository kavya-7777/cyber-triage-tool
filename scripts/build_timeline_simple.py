#!/usr/bin/env python3
"""
Quick helper to build cached data/<case_id>/timeline.json using modules.timeline.build_timeline.
Usage:
  python scripts/build_timeline_simple.py [case_id]
"""
import os, json, sys
case = sys.argv[1] if len(sys.argv) > 1 else "case001"
case_dir = os.path.join("data", case)
os.makedirs(case_dir, exist_ok=True)
processes = os.path.join(case_dir, "processes.csv")
events = os.path.join(case_dir, "events.json")
try:
    from modules.timeline import build_timeline
except Exception as e:
    print("Failed to import modules.timeline:", e)
    raise
timeline = build_timeline(processes if os.path.exists(processes) else "", events if os.path.exists(events) else "", keep_na=True)
out = os.path.join(case_dir, "timeline.json")
with open(out, "w", encoding="utf-8") as fh:
    json.dump({"timeline": timeline}, fh, indent=2)
print("Wrote", out, "entries:", len(timeline))
