# scripts/list_artifacts_check.py
import os
from pathlib import Path

case = "case001"
base = Path("evidence") / case / "artifacts"
if not base.exists():
    print("Artifacts dir missing:", base)
    raise SystemExit(1)

print("Scanning:", base)
missing = []
for root, dirs, files in os.walk(base):
    for f in files:
        if f.startswith("extracted__"):
            artid = f.split("extracted__")[-1].rsplit(".", 1)[0]
            meta = Path(root) / f"{artid}.json"
            saved = Path(root) / f
            exists_meta = meta.exists()
            print(f"{f:60} saved_path: {saved.exists():5} meta: {exists_meta:5} -> metapath: {meta}")
            if not exists_meta:
                missing.append((artid, str(saved)))
print()
print(f"Missing metadata count: {len(missing)}")
if missing:
    print("Examples (artifact_id, saved_path):")
    for a, p in missing[:10]:
        print(" ", a, p)
