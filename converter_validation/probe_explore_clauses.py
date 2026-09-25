"""Decompose a failing control query clause by clause against /explore/aggregate."""
import json
import sys
from pathlib import Path

import requests
import urllib3

sys.path.insert(0, str(Path(__file__).resolve().parent))
from backtest_explore import BASE, IDX, api_key  # noqa: E402

urllib3.disable_warnings()
s = requests.Session()
s.headers["Authorization"] = "Bearer " + api_key()

fields = json.loads((Path(__file__).resolve().parent / "live" / "explore_fields.json").read_text(encoding="utf-8"))
details = {d["name"]: d for d in (fields.get("results") or {}).get("details") or [] if isinstance(d, dict)}
for n in ("product_name", "vendor_id", "image", "image.keyword", "event_channel", "event_channel.keyword", "logon_type", "command", "command.keyword"):
    d = details.get(n)
    print(f"  {n:24s} {d.get('types') if d else None} agg={d.get('aggregatable') if d else None}")


def count(q, group_by="product_name"):
    r = s.post(BASE + "explore/aggregate", data={"idx": IDX, "q": q, "from": "now-6h", "to": "now", "group_by": group_by, "metric": "count", "size": "5"}, timeout=300, verify=False)
    j = r.json()
    rows = (j.get("results") or {}).get("rows")
    tot = sum(int(x.get("count", x.get("doc_count", 0)) or 0) for x in rows) if rows else None
    return tot, (j.get("details") if rows is None else None)


for q in [
    'product_name:"Sysmon"',
    'product_name:"Sysmon" AND vendor_id:"1"',
    'product_name:"Sysmon" AND vendor_id:1',
    'vendor_id:"1"',
    'product_name:"Sysmon" AND image.keyword:/.*svchost.*/',
    'product_name:"Sysmon" AND image:svchost',
    'product_name:"Sysmon" AND image.keyword:"C:\\\\Windows\\\\System32\\\\svchost.exe"',
    'product_name:"Sysmon" AND image:"C:\\\\Windows\\\\System32\\\\svchost.exe"',
    'event_channel:"Security"',
    'event_channel.keyword:"Security"',
    'product_name:"Security-Auditing" AND logon_type:3',
    'product_name:"Security-Auditing" AND logon_type:"3"',
    'command:cmd.exe',
    'command.keyword:/.*cmd\\.exe.*/',
]:
    print(f"{str(count(q)):28s} {q}")
