# modules/timeline_utils.py
import csv
import json
import os
import uuid
from typing import Dict

def append_json_events(src_json: str, out_json: str) -> int:
    def load_candidates(p):
        with open(p, "r", encoding="utf-8") as fh:
            return json.load(fh)

    src = load_candidates(src_json)
    if isinstance(src, dict) and isinstance(src.get("events"), list):
        items = src["events"]
    elif isinstance(src, list):
        items = src
    else:
        items = [src]

    existing = []
    if os.path.exists(out_json):
        try:
            with open(out_json, "r", encoding="utf-8") as fh:
                maybe = json.load(fh)
                if isinstance(maybe, list):
                    existing = maybe
                elif isinstance(maybe, dict) and isinstance(maybe.get("events"), list):
                    existing = maybe["events"]
        except Exception:
            existing = []

    # normalize each item to have an id
    appended = 0
    for it in items:
        if isinstance(it, dict):
            if not it.get("id"):
                it["id"] = str(uuid.uuid4())
        else:
            it = {"id": str(uuid.uuid4()), "value": it}
        existing.append(it)
        appended += 1

    # write back
    with open(out_json, "w", encoding="utf-8") as fh:
        json.dump(existing, fh, indent=2)

    return appended

def generate_case_processes_and_events(extract_root: str, out_processes: str, out_events: str, extracted_paths=None):
    import tempfile, shutil, time

    if extracted_paths is None:
        # walk extract_root and collect regular files
        extracted_paths = []
        for root, _, files in os.walk(extract_root):
            for f in files:
                extracted_paths.append(os.path.join(root, f))

    os.makedirs(os.path.dirname(out_processes), exist_ok=True)
    os.makedirs(os.path.dirname(out_events), exist_ok=True)

    # If out_processes exists, we'll append rows; otherwise create header later
    processes_temp = None
    processes_written = 0
    events_written = 0

    # If processes already exists, we'll preserve its header and append new rows
    existing_processes = os.path.exists(out_processes)
    if existing_processes:
        # create a temp file to accumulate new rows and then append
        processes_temp = tempfile.NamedTemporaryFile(mode="w", newline="", delete=False, encoding="utf-8")
    else:
        # if not exists, we'll write directly to out_processes (with header) later
        processes_temp = tempfile.NamedTemporaryFile(mode="w", newline="", delete=False, encoding="utf-8")

    try:
        # For events: ensure out_events exists as list
        if not os.path.exists(out_events):
            with open(out_events, "w", encoding="utf-8") as fh:
                json.dump([], fh)

        # process each extracted path
        for p in extracted_paths:
            lp = (p or "").lower()
            try:
                if lp.endswith(".csv") and is_sysmon_csv(p):
                    # Use existing parser to produce a temporary csv, then append rows (skip header)
                    with tempfile.NamedTemporaryFile(mode="w", newline="", delete=False, encoding="utf-8") as tmpcsv:
                        tmp_path = tmpcsv.name
                    try:
                        cnt = parse_sysmon_csv_to_processes(p, tmp_path)
                        if cnt > 0:
                            # read tmp_path and append rows (skip header)
                            with open(tmp_path, newline="", encoding="utf-8") as infh:
                                reader = csv.reader(infh)
                                header = next(reader, None)
                                for row in reader:
                                    # write to processes_temp as CSV row
                                    processes_temp.write(",".join([cell.replace("\n"," ").replace("\r"," ") for cell in row]) + "\n")
                                    processes_written += 1
                    finally:
                        try:
                            os.remove(tmp_path)
                        except Exception:
                            pass

                elif lp.endswith(".json"):
                    # append JSON events into out_events using your helper
                    try:
                        added = append_json_events(p, out_events)
                        events_written += added
                    except Exception:
                        # fallback: try to read single object and append
                        try:
                            with open(p, "r", encoding="utf-8") as fh:
                                maybe = json.load(fh)
                            if isinstance(maybe, dict):
                                # wrap
                                append_json_events(p, out_events)
                                events_written += 1
                        except Exception:
                            pass
                else:
                    # Generic file: create a simple event (file_saved)
                    ev = {
                        "id": str(uuid.uuid4()),
                        "timestamp": "",
                        "type": "file_saved",
                        "details": {
                            "path": os.path.relpath(p, extract_root),
                            "absolute_path": p
                        }
                    }
                    # append to out_events list (read/modify/write)
                    try:
                        with open(out_events, "r", encoding="utf-8") as fh:
                            existing = json.load(fh)
                            if not isinstance(existing, list):
                                existing = []
                    except Exception:
                        existing = []
                    existing.append(ev)
                    with open(out_events, "w", encoding="utf-8") as fh:
                        json.dump(existing, fh, indent=2)
                    events_written += 1
            except Exception:
                # skip problematic files but don't abort the whole process
                continue

        # finalize processes file: if existing had header, prepend header; otherwise create new with header
        processes_temp.flush()
        os.fsync(processes_temp.fileno())
        processes_temp_name = processes_temp.name
        processes_temp.close()

        # If no rows were written into temp, remove it and leave out_processes unchanged (or create empty header)
        if processes_written == 0:
            try:
                os.remove(processes_temp_name)
            except Exception:
                pass
        else:
            # If out_processes exists, append without header
            if existing_processes:
                with open(out_processes, "a", newline="", encoding="utf-8") as outfh, open(processes_temp_name, "r", encoding="utf-8") as infh:
                    # ensure existing file ends with newline
                    outfh.write("\n")
                    shutil.copyfileobj(infh, outfh)
            else:
                # create out_processes with header + rows.
                # Our temporary rows are CSV rows matching header order:
                header = ["timestamp","pid","ppid","exe","cmdline","user","event","id"]
                with open(out_processes, "w", newline="", encoding="utf-8") as outfh:
                    writer = csv.writer(outfh)
                    writer.writerow(header)
                    with open(processes_temp_name, "r", encoding="utf-8") as infh:
                        for line in infh:
                            outfh.write(line)
            try:
                os.remove(processes_temp_name)
            except Exception:
                pass

    finally:
        try:
            if not processes_temp.closed:
                processes_temp.close()
        except Exception:
            pass

    return processes_written, events_written
