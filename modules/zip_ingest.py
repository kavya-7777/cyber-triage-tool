import os
import zipfile
import csv
import shutil
import logging
from typing import List, Dict

logger = logging.getLogger(__name__)

def safe_extract_zip(zip_path: str, dest_dir: str, case_id: str) -> List[str]:
    """
    Securely extract ZIP to dest_dir and copy extracted metadata to evidence/<case_id>/artifacts/.
    Returns a list of extracted file paths.
    """
    import json
    from modules.hashing import compute_sha256  # ✅ make sure hashing module is imported

    extracted = []
    os.makedirs(dest_dir, exist_ok=True)
    base = os.path.abspath(dest_dir)

    with zipfile.ZipFile(zip_path, "r") as z:
        for member in z.infolist():
            if member.is_dir():
                continue

            target_path = os.path.abspath(os.path.join(dest_dir, member.filename))
            if not target_path.startswith(base + os.path.sep):
                logger.warning("Skipping suspicious zip entry (zip-slip): %s", member.filename)
                continue

            os.makedirs(os.path.dirname(target_path), exist_ok=True)
            with z.open(member) as src, open(target_path, "wb") as out:
                shutil.copyfileobj(src, out)

            extracted.append(target_path)

            # ✅ Create minimal metadata JSON for this extracted file
            artifact_id = f"extracted__{os.path.splitext(os.path.basename(member.filename))[0]}"
            meta = {
                "artifact_id": artifact_id,
                "case_id": case_id,
                "original_filename": os.path.basename(member.filename),
                "saved_path": target_path,
                "sha256": compute_sha256(target_path),
                "size_bytes": os.path.getsize(target_path)
            }

            meta_path = os.path.join(dest_dir, f"{artifact_id}.json")
            try:
                with open(meta_path, "w", encoding="utf-8") as f:
                    json.dump(meta, f, indent=2)
                logger.info(f"✅ Created metadata JSON for extracted file: {meta_path}")
            except Exception as e:
                logger.error(f"Failed to create metadata for {member.filename}: {e}")

    # ✅ After extraction, move JSON metadata to main artifacts folder
    artifacts_dir = os.path.join("evidence", case_id, "artifacts")
    os.makedirs(artifacts_dir, exist_ok=True)

    for extracted_file in extracted:
        filename = os.path.basename(extracted_file)
        artifact_id = f"extracted__{os.path.splitext(filename)[0]}"
        src_meta = os.path.join(dest_dir, f"{artifact_id}.json")
        dst_meta = os.path.join(artifacts_dir, f"{artifact_id}.json")

        if os.path.exists(src_meta):
            shutil.copy2(src_meta, dst_meta)
            logger.info(f"📦 Copied metadata for {artifact_id} → {dst_meta}")
        else:
            logger.warning(f"⚠️ No metadata found for {artifact_id} (expected {src_meta})")

    return extracted

def _append_csv_to_processes(src_csv: str, dst_processes: str) -> int:
    """
    Append rows from src_csv into dst_processes. If dst doesn't exist copy header+rows.
    Return number of rows appended.
    """
    if not os.path.exists(src_csv):
        return 0
    appended = 0
    os.makedirs(os.path.dirname(dst_processes) or ".", exist_ok=True)
    # If destination not present, copy whole file
    if not os.path.exists(dst_processes):
        shutil.copy(src_csv, dst_processes)
        # count rows minus header
        with open(src_csv, "r", encoding="utf-8", errors="ignore") as fh:
            appended = sum(1 for _ in fh) - 1
        return max(0, appended)
    # Else append skipping header
    with open(src_csv, newline="", encoding="utf-8", errors="ignore") as src, open(dst_processes, "a", newline="", encoding="utf-8") as dst:
        rdr = csv.reader(src)
        wr = csv.writer(dst)
        first = True
        for row in rdr:
            if first:
                first = False
                continue
            wr.writerow(row)
            appended += 1
    return appended


def process_extracted_files(case_id: str, extracted_paths: List[str]) -> Dict:
    """
    Process extracted files to produce:
      - data/<case_id>/processes.csv
      - data/<case_id>/events.json

    Returns summary dict with counts.
    """
    out_dir = os.path.join("data", case_id)
    os.makedirs(out_dir, exist_ok=True)
    processes_path = os.path.join(out_dir, "processes.csv")
    events_path = os.path.join(out_dir, "events.json")

    summary = {"processed": 0, "csv_rows_written": 0, "events_appended": 0, "errors": []}

    for p in extracted_paths:
        summary["processed"] += 1
        try:
            low = p.lower()
            if low.endswith(".csv"):
                # if sysmon-like, parse to canonical processes.csv; else append generically
                if is_sysmon_csv and parse_sysmon_csv_to_processes and is_sysmon_csv(p):
                    written = parse_sysmon_csv_to_processes(p, processes_path)
                    summary["csv_rows_written"] += written
                else:
                    written = _append_csv_to_processes(p, processes_path)
                    summary["csv_rows_written"] += written

            elif low.endswith(".json"):
                if append_json_events:
                    try:
                        appended = append_json_events(p, events_path)
                        summary["events_appended"] += appended
                    except Exception:
                        logger.exception("Failed to append events from %s", p)
                else:
                    # fallback: try copying raw JSON into events.json if not present
                    if not os.path.exists(events_path):
                        try:
                            shutil.copy(p, events_path)
                            summary["events_appended"] += 1
                        except Exception:
                            logger.exception("Failed fallback-copying JSON events from %s", p)
            else:
                # not a timeline-format file — ignore for now
                pass

        except Exception as e:
            logger.exception("Error processing extracted file %s", p)
            summary["errors"].append({"path": p, "error": str(e)})

    # Ensure the canonical timeline files exist so downstream consumers don't complain.
    # If no CSV rows were written, create an empty file (touch) so build_timeline finds it.
    try:
        if not os.path.exists(processes_path):
            # create an empty file (header unknown) -- at least the file exists for the timeline builder
            open(processes_path, "a").close()
            logger.debug("Created empty processes.csv for case %s at %s", case_id, processes_path)
        if not os.path.exists(events_path):
            open(events_path, "a").close()
            logger.debug("Created empty events.json for case %s at %s", case_id, events_path)
    except Exception:
        logger.exception("Failed to ensure timeline files exist for case %s", case_id)

    return summary