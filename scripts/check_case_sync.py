# scripts/check_case_sync.py
"""
Check synchronization between DB, manifest, events, and artifact files for a case.
Usage:
  python scripts/check_case_sync.py <case_id>
Example:
  python scripts/check_case_sync.py case001
"""
import os, sys, json, sqlite3, traceback

def load_manifest_count(case):
    p = os.path.join("evidence", case, "manifest.json")
    if not os.path.exists(p):
        return None, p
    try:
        with open(p, "r", encoding="utf-8") as fh:
            m = json.load(fh)
        arts = m.get("artifacts", [])
        return len(arts), p
    except Exception:
        return "err", p

def load_events_count(case):
    p = os.path.join("data", case, "events.json")
    if not os.path.exists(p):
        return None, p
    try:
        with open(p, "r", encoding="utf-8") as fh:
            ej = json.load(fh)
        total = 0
        for ev in ej.get("timeline_preview", []):
            try:
                if ev.get("details", {}).get("case_id") == case:
                    total += len(ev.get("details", {}).get("artifacts", []) or [])
            except Exception:
                pass
        return total, p
    except Exception:
        return "err", p

def count_artifact_files(case):
    art_dir = os.path.join("evidence", case, "artifacts")
    if not os.path.exists(art_dir):
        return 0, art_dir, []
    items = []
    for root, dirs, files in os.walk(art_dir):
        for f in files:
            items.append(os.path.join(root, f))
    # Count JSON metadata files that look like <artifact_id>.json
    meta_files = [p for p in items if p.lower().endswith(".json")]
    return len([p for p in items if not p.lower().endswith(".json")]), art_dir, meta_files

def query_db_count(case):
    db_path = os.path.join("data", "triage.db")
    if not os.path.exists(db_path):
        return None, db_path, "db-missing"
    try:
        con = sqlite3.connect(db_path)
        cur = con.cursor()
        cur.execute("SELECT COUNT(*) FROM artifacts WHERE case_id=?", (case,))
        cnt = cur.fetchone()[0]
        # fetch sample rows (artifact_id, original_filename)
        cur.execute("SELECT artifact_id, original_filename, saved_filename, uploaded_at FROM artifacts WHERE case_id=? ORDER BY uploaded_at DESC LIMIT 200", (case,))
        rows = cur.fetchall()
        con.close()
        return cnt, db_path, rows
    except Exception as e:
        return "err", db_path, traceback.format_exc()

def main():
    if len(sys.argv) < 2:
        print("Usage: python scripts/check_case_sync.py <case_id>")
        sys.exit(2)
    case = sys.argv[1]
    print(f"Checking case: {case}\n")

    db_count, db_path, db_rows = query_db_count(case)
    print("DB:", db_path)
    print("  artifact_count:", db_count)
    if isinstance(db_rows, list):
        print("  sample rows (len):", len(db_rows))
        for r in db_rows[:10]:
            print("   ", r)
    else:
        print("  extra:", db_rows)
    print()

    man_count, man_path = load_manifest_count(case)
    print("Manifest:", man_path)
    print("  artifact_count:", man_count)
    print()

    ev_count, ev_path = load_events_count(case)
    print("Events (timeline):", ev_path)
    print("  artifact_count_in_timeline:", ev_count)
    print()

    file_count, art_dir, meta_files = count_artifact_files(case)
    print("Disk artifacts dir:", art_dir)
    print("  file_count (non-json files):", file_count)
    print("  metadata json files:", len(meta_files))
    if meta_files:
        for mf in meta_files[:10]:
            print("   ", mf)
    print()

    # Quick heuristic
    vals = {}
    vals["db_count"] = db_count if isinstance(db_count, int) else None
    vals["manifest_count"] = man_count if isinstance(man_count, int) else None
    vals["timeline_count"] = ev_count if isinstance(ev_count, int) else None
    vals["disk_count"] = file_count
    print("Summary counts:", vals)

if __name__ == "__main__":
    main()
