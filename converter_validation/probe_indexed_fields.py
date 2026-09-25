"""Which columns are actually searchable in the explore index right now?

field_caps says "searchable" for everything the mapping ever declared, but `_exists_:<field>`
over the last few hours is the honest test. Writes live/explore_indexed_fields.json.
"""
import concurrent.futures as cf
import json
import sys
from pathlib import Path

import requests
import urllib3

sys.path.insert(0, str(Path(__file__).resolve().parent))
from backtest_explore import BASE, IDX, api_key  # noqa: E402

urllib3.disable_warnings()
HERE = Path(__file__).resolve().parent
s = requests.Session()
s.headers["Authorization"] = "Bearer " + api_key()

# every column referenced by converted scores plus the taxonomy/gate columns
cols = set()
for line in (HERE / "reports" / "converted.jsonl").read_text(encoding="utf-8").splitlines():
    if not line.strip():
        continue
    rec = json.loads(line)

    def walk(n):
        if isinstance(n, list):
            for c in n:
                walk(c)
        elif isinstance(n, dict):
            if n.get("class") == "column" and n.get("key"):
                cols.add(n["key"])
            for c in n.get("children", []) or []:
                walk(c)
    walk(rec["rules"])
cols |= {"product_name", "vendor_id", "event_channel", "vendor_name", "product_source", "image", "command", "payload"}
cols = sorted(c for c in cols if c and " " not in c and '"' not in c)
print("columns to probe:", len(cols))


def probe(col):
    try:
        r = s.post(BASE + "explore/aggregate", data={"idx": IDX, "q": f"_exists_:{col}", "from": "now-6h", "to": "now",
                                                    "group_by": "product_name", "metric": "count", "size": "3"}, timeout=300, verify=False)
        rows = (r.json().get("results") or {}).get("rows") or []
        return col, sum(int(x.get("count", 0) or 0) for x in rows)
    except Exception as e:  # noqa: BLE001
        return col, -1


out = {}
with cf.ThreadPoolExecutor(max_workers=6) as ex:
    for col, n in ex.map(probe, cols):
        out[col] = n
(HERE / "live" / "explore_indexed_fields.json").write_text(json.dumps(out, indent=1, sort_keys=True), encoding="utf-8")
indexed = sorted(c for c, n in out.items() if n > 0)
print("indexed (searchable with data, 6h):", len(indexed))
print(indexed)
print("not indexed:", len([c for c, n in out.items() if n == 0]))
