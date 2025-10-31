# scripts/generate_yara_from_ioc.py
import json
from pathlib import Path
ioc_path = Path("data/ioc.json")
out_yar = Path("data/auto_iocs.yar")

if not ioc_path.exists():
    print("No ioc.json found")
    raise SystemExit(1)

ioc = json.loads(ioc_path.read_text(encoding="utf-8"))
lines = []
lines.append("// auto-generated rules from data/ioc.json — regenerate as needed\n")

# filenames rule
filenames = sorted(set(ioc.get("filenames", [])))
if filenames:
    lines.append("rule CT_IOC_Filenames {\n  meta: description = \"IOCs: filenames\"\n  strings:")
    for i, fn in enumerate(filenames):
        # safe ascii
        s = fn.replace("\"", "\\\"")
        lines.append(f'    $f{i} = "{s}" ascii nocase')
    lines.append("  condition:\n    any of them\n}\n")

# domains and ips
domains = sorted(set(ioc.get("domains", [])))
ips = sorted(set(ioc.get("ips", [])))
if domains or ips:
    lines.append("rule CT_IOC_Domains_IPs {\n  meta: description = \"IOCs: domains and IPs\"\n  strings:")
    idx = 0
    for d in domains:
        s = d.replace("\"", "\\\"")
        lines.append(f'    $d{idx} = "{s}" ascii nocase')
        idx += 1
    for ip in ips:
        s = ip.replace("\"", "\\\"")
        lines.append(f'    $i{idx} = "{s}"')
        idx += 1
    lines.append("  condition:\n    any of them\n}\n")

# hashes: try to add as hex bytes if length suitable (optional)
hashes = ioc.get("hashes", [])
for h in hashes:
    if isinstance(h, str) and len(h) >= 16:
        name = h[:8]
        lines.append(f'rule CT_IOC_hash_{name} {{\n  meta: description = "IOC hash fragment"\n  strings:\n    $h = "{h}" ascii nocase\n  condition:\n    $h\n}}\n')

out_yar.write_text("\n".join(lines), encoding="utf-8")
print("Wrote", out_yar)