# tools/verify_all_hmacs.py
import os, json, hmac, hashlib
BASE = "evidence"
KEY = os.environ.get("MANIFEST_HMAC_KEY", "changeme_local_dev_key")
def canonical_json_bytes(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

def verify(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            obj = json.load(fh)
    except Exception as e:
        return (False, f"json_load_error: {e}")
    meta = obj.get("_meta")
    if not meta:
        return (False, "no _meta")
    observed = meta.get("hmac")
    obj_copy = dict(obj); obj_copy.pop("_meta", None)
    expected = hmac.new(KEY.encode("utf-8"), canonical_json_bytes(obj_copy), hashlib.sha256).hexdigest()
    return (observed == expected, {"expected": expected, "observed": observed})

bad = []
for root, _, files in os.walk(BASE):
    for f in files:
        if not f.endswith(".json"):
            continue
        p = os.path.join(root, f)
        ok, details = verify(p)
        if not ok:
            bad.append((p, details))
print("Checked", sum(1 for _ in open if False))
if not bad:
    print("All signatures OK for current key.")
else:
    print("Signatures failing for", len(bad), "files. Sample:")
    for p,d in bad[:10]:
        print(p, d)
