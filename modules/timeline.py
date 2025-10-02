# modules/timeline.py
from __future__ import annotations
import os
import csv
import json
import re
import sys
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

# Only import Flask pieces used for blueprint creation (no app object here)
from flask import Blueprint, jsonify, render_template, current_app, request

# try dateutil if available for robust parsing (optional)
try:
    from dateutil.parser import parse as dateutil_parse  # type: ignore
except Exception:
    dateutil_parse = None

TIMESTAMP_CANDIDATES = [
    "timestamp", "time", "ts", "date", "created_at", "created", "start_time", "end_time", "event_time", "epoch", "epoch_ms"
]

FALLBACK_MIN_DT = datetime(1970, 1, 1, tzinfo=timezone.utc)


def detect_timestamp_field(fieldnames: List[str]) -> Optional[str]:
    if not fieldnames:
        return None
    lower_map = {f.lower(): f for f in fieldnames}
    for cand in TIMESTAMP_CANDIDATES:
        if cand in lower_map:
            return lower_map[cand]
    for k in fieldnames:
        kl = k.lower()
        if "time" in kl or "date" in kl or kl == "ts":
            return k
    return None


def parse_timestamp(s: Optional[Any]) -> Optional[datetime]:
    if s is None:
        return None
    s = str(s).strip()
    if s == "":
        return None

    # numeric epoch (10 or 13 digits)
    if re.fullmatch(r"\d{10,13}", s):
        ts = int(s)
        if len(s) > 10:
            return datetime.fromtimestamp(ts / 1000.0, tz=timezone.utc)
        return datetime.fromtimestamp(ts, tz=timezone.utc)

    # try isoformat with trailing Z handling
    try:
        if s.endswith("Z"):
            base = s[:-1]
            dt = datetime.fromisoformat(base)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        pass

    # try common formats
    common_formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%m/%d/%Y %H:%M:%S",
        "%d/%m/%Y %H:%M:%S",
    ]
    for fmt in common_formats:
        try:
            dt = datetime.strptime(s, fmt)
            dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            pass

    # last resort: dateutil
    if dateutil_parse:
        try:
            dt = dateutil_parse(s)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            pass

    # couldn't parse
    raise ValueError(f"Unrecognized timestamp format: {s}")


def normalize_event_for_output(e: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(e)
    ts_dt = out.pop("timestamp_dt", None)
    out["timestamp"] = ts_dt.isoformat() if ts_dt is not None else None
    return out


def load_processes_csv(path: Optional[str]) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    if not path:
        # nothing to load
        return events
    try:
        with open(path, newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            ts_field = detect_timestamp_field(reader.fieldnames or [])
            for row in reader:
                ts_raw = row.get(ts_field) if ts_field else None
                try:
                    ts_dt = parse_timestamp(ts_raw) if ts_raw else None
                except Exception as ex:
                    # warn but continue
                    print(f"Warning: cannot parse process timestamp '{ts_raw}': {ex}", file=sys.stderr)
                    ts_dt = None
                ev_type = row.get("event") or row.get("action") or "process"
                ev = {
                    "id": row.get("id") or str(uuid.uuid4()),
                    "source": "processes.csv",
                    "type": ev_type,
                    "pid": row.get("pid") or row.get("PID") or None,
                    "ppid": row.get("ppid") or row.get("PPID") or None,
                    "exe": row.get("exe") or row.get("command") or row.get("cmdline") or None,
                    "user": row.get("user") or row.get("username") or None,
                    "raw": row,
                    "timestamp_dt": ts_dt,
                }
                events.append(ev)
    except FileNotFoundError:
        # file missing — caller will handle empty list
        print(f"Warning: processes file not found: {path}", file=sys.stderr)
    return events


def load_events_json(path: str) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        print(f"Warning: events file not found: {path}", file=sys.stderr)
        return events

    # Accept either {"timeline_preview": [...]} or {"events": [...]} or a bare list
    arr = None
    if isinstance(data, dict):
        if isinstance(data.get("timeline_preview"), list):
            arr = data["timeline_preview"]
        elif isinstance(data.get("events"), list):
            arr = data["events"]
        else:
            for v in data.values():
                if isinstance(v, list):
                    arr = v
                    break
            if arr is None:
                raise ValueError("events.json does not contain an event list")
    elif isinstance(data, list):
        arr = data
    else:
        raise ValueError("events.json has unknown top-level type")

    for item in arr:
        ts_raw = None
        if isinstance(item, dict):
            for cand in TIMESTAMP_CANDIDATES:
                if cand in item:
                    ts_raw = item.get(cand)
                    break
            if ts_raw is None:
                for k in item.keys():
                    if "time" in k.lower() or "date" in k.lower() or k.lower() == "ts":
                        ts_raw = item.get(k)
                        break
        try:
            ts_dt = parse_timestamp(ts_raw) if ts_raw else None
        except Exception as ex:
            print(f"Warning: cannot parse events.json timestamp '{ts_raw}': {ex}", file=sys.stderr)
            ts_dt = None

        # Base event
        ev = {
            "id": (item.get("id") if isinstance(item, dict) else None) or str(uuid.uuid4()),
            "source": (item.get("source") if isinstance(item, dict) else "events.json"),
            "type": (item.get("type") if isinstance(item, dict) else "event") or "event",
            "details": item if isinstance(item, dict) else {"value": item},
            "timestamp_dt": ts_dt,
        }

        # Special-case expansion: accept nested forms like:
        # item["details"]["details"]["artifacts"]  (your current observed shape)
        try:
            details = ev.get("details") or {}
            inner = None
            # common candidate locations to find artifacts list:
            if isinstance(details, dict):
                if isinstance(details.get("details"), dict) and isinstance(details["details"].get("artifacts"), list):
                    inner = details["details"]
                elif isinstance(details.get("artifacts"), list):
                    inner = details
                elif isinstance(item.get("artifacts"), list):
                    inner = item
            if inner and isinstance(inner.get("artifacts"), list):
                for art_wrapper in inner.get("artifacts", []):
                    try:
                        # artifact might be inside {"artifact": {...}, "note":..., "type": ...}
                        art_obj = None
                        summary = None
                        if isinstance(art_wrapper, dict) and art_wrapper.get("artifact"):
                            art_obj = art_wrapper.get("artifact")
                        elif isinstance(art_wrapper, dict) and art_wrapper.get("summary"):
                            summary = art_wrapper.get("summary")
                            art_obj = art_wrapper.get("artifact") or {}
                        else:
                            art_obj = art_wrapper if isinstance(art_wrapper, dict) else {}

                        # build a compact summary (UI-friendly)
                        if not summary:
                            summary = {
                                "artifact_id": (art_obj or {}).get("artifact_id") or (art_obj or {}).get("id"),
                                "filename": (art_obj or {}).get("original_filename") or (art_obj or {}).get("saved_filename"),
                                "saved_filename": (art_obj or {}).get("saved_filename"),
                                "size_bytes": (art_obj or {}).get("size_bytes"),
                                "final_score": ((art_obj or {}).get("analysis") or {}).get("final_score")
                            }

                        single = {
                            "id": (art_wrapper.get("id") if isinstance(art_wrapper, dict) and art_wrapper.get("id") else str(uuid.uuid4())),
                            "source": "events.json",
                            "type": art_wrapper.get("type") or "artifact_uploaded",
                            "timestamp_dt": ts_dt,
                            "timestamp": ts_dt.isoformat() if ts_dt else None,
                            "case_id": inner.get("case_id") or item.get("case_id") or None,
                            "artifact_id": summary.get("artifact_id"),
                            "summary": summary,
                            "details": art_obj or art_wrapper
                        }
                        events.append(single)
                    except Exception:
                        # skip malformed artifact entries but continue
                        continue
                # expanded all artifacts for this top-level item
                continue
        except Exception:
            # ignore expansion errors and fall back to the raw event
            pass

        events.append(ev)

    return events


def build_timeline(processes_path: str, events_path: str, keep_na: bool = False) -> List[Dict[str, Any]]:
    all_events: List[Dict[str, Any]] = []
    all_events.extend(load_processes_csv(processes_path))
    all_events.extend(load_events_json(events_path))

    # sort by timestamp ascending; None timestamps go last
    all_events.sort(key=lambda ev: (ev["timestamp_dt"] is None, ev["timestamp_dt"] or FALLBACK_MIN_DT))
    out_list = [normalize_event_for_output(ev) for ev in all_events if (keep_na or ev["timestamp_dt"] is not None)]
    return out_list


# --- Flask Blueprint exposed as `bp` (this is what app.py imports) ---
bp = Blueprint("timeline_bp", __name__, template_folder="../templates")


@bp.route("/timeline")
@bp.route("/timeline/<case_id>")
def timeline_page(case_id=None):
    # prefer path param, then query param, then default
    case_id = case_id or request.args.get("case_id") or "case001"
    return render_template("timeline.html", case_id=case_id)


@bp.route("/api/timeline")
def api_timeline():
    # optional case_id parameter to fetch case-specific data
    case_id = request.args.get("case_id")
    if case_id:
        processes_path = f"data/{case_id}/processes.csv"
        events_path = f"data/{case_id}/events.json"
    else:
        processes_path = current_app.config.get("TIMELINE_PROCESSES_PATH", "data/processes.csv")
        events_path = current_app.config.get("TIMELINE_EVENTS_PATH", "data/events.json")
    timeline = build_timeline(processes_path, events_path, keep_na=False)
    return jsonify({"timeline": timeline})

@bp.route("/api/timeline/<case_id>", methods=["GET"])
def api_timeline_case(case_id):
    """
    Return timeline JSON for a specific case (reads data/<case_id>/timeline.json).
    Falls back to building the timeline on-the-fly from processes/events if needed.
    """
    case_data_dir = os.path.join("data", case_id)
    timeline_path = os.path.join(case_data_dir, "timeline.json")

    # If a cached timeline exists, return it
    if os.path.exists(timeline_path):
        try:
            with open(timeline_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            # ensure consistent shape
            if isinstance(data, dict) and "timeline" in data:
                return jsonify(data)
            # older code might have saved bare list
            if isinstance(data, list):
                return jsonify({"timeline": data})
            return jsonify({"timeline": [], "case_id": case_id, "note": "unexpected timeline format"}), 200
        except Exception as e:
            return jsonify({"timeline": [], "case_id": case_id, "error": f"failed reading timeline: {e}"}), 500

    # No cached file: try to build from processes.csv & events.json if present
    processes_path = os.path.join(case_data_dir, "processes.csv")
    events_path = os.path.join(case_data_dir, "events.json")

    try:
        # import builder lazily to avoid circular imports at module load
        from modules.timeline import build_timeline as _build_timeline
    except Exception:
        _build_timeline = None

    if _build_timeline and (os.path.exists(processes_path) or os.path.exists(events_path)):
        try:
            p_arg = processes_path if os.path.exists(processes_path) else ""
            e_arg = events_path if os.path.exists(events_path) else ""
            timeline = _build_timeline(p_arg, e_arg, keep_na=True)
            os.makedirs(case_data_dir, exist_ok=True)
            with open(timeline_path, "w", encoding="utf-8") as fh:
                json.dump({"timeline": timeline}, fh, indent=2)
            return jsonify({"timeline": timeline})
        except Exception as e:
            return jsonify({"timeline": [], "case_id": case_id, "error": f"failed to build timeline: {e}"}), 500

    # Nothing to return
    return jsonify({"timeline": [], "case_id": case_id, "note": "no timeline available"}), 404
