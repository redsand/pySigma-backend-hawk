"""Write reports/refresh_drifted.txt: production scores whose upstream rule changed after the 2023 sync."""
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
drift = json.loads((HERE / "reports" / "drifted_matched_rules.json").read_text(encoding="utf-8"))
conv = {}
for line in (HERE / "reports" / "converted.jsonl").read_text(encoding="utf-8").splitlines():
    if line.strip():
        r = json.loads(line)
        conv[r["_source"].replace("\\", "/")] = r
lines = []
miss = 0
for rel, mod, level in drift:
    rel = rel.replace("\\", "/")
    r = conv.get(rel)
    if r:
        lines.append(f"{r['hawk_id']}  # {r['filter_name']} | {rel} | modified {mod} | {level}")
    else:
        miss += 1
out = HERE / "reports" / "refresh_drifted.txt"
out.write_text("# production scores whose upstream Sigma rule changed after the 2023 sync; re-push keeps enabled state\n" + "\n".join(lines) + "\n", encoding="utf-8")
print("refresh list:", len(lines), "unmatched:", miss, "->", out)
