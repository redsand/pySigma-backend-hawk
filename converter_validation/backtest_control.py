"""Positive controls for backtest_explore: synthetic score trees that must return hits."""
import json
import sys
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent))
from backtest_explore import api_key, run_one  # noqa: E402


def leaf(key, value, regex=False, op="=", typ="str"):
    arg = {"value": value}
    if regex:
        arg["regex"] = True
    return {"key": key, "class": "column", "return": typ, "args": {"comparison": {"value": op}, typ: arg}}


CONTROLS = [
    ("sysmon process create svchost (contains)", [leaf("product_name", "Sysmon"), leaf("vendor_id", "1"), leaf("image", ".*svchost\\.exe.*", regex=True)]),
    ("sysmon process create endswith \\svchost.exe", [leaf("product_name", "Sysmon"), leaf("vendor_id", "1"), leaf("image", "\\\\svchost\\.exe$", regex=True)]),
    ("security 4624 logon type 3 (int)", [leaf("product_name", "Security-Auditing"), leaf("vendor_id", "4624"), leaf("logon_type", 3, typ="int")]),
    ("security 4688 command contains cmd.exe (case)", [leaf("event_channel", "Security"), leaf("vendor_id", "4688"), leaf("command", ".*cmd\\.exe.*", regex=True)]),
    ("security 4688 command contains CMD.EXE upper (case sensitivity probe)", [leaf("event_channel", "Security"), leaf("vendor_id", "4688"), leaf("command", ".*CMD\\.EXE.*", regex=True)]),
    ("dns-client any", [leaf("product_name", "DNS-Client")]),
    ("or gate: sysmon 1 OR security 4688, image endswith powershell.exe", [{"id": "or", "key": "Or", "children": [
        {"id": "and", "key": "And", "children": [leaf("product_name", "Sysmon"), leaf("vendor_id", "1")]},
        {"id": "and", "key": "And", "children": [leaf("product_name", "Security-Auditing"), leaf("vendor_id", "4688")]}]},
        leaf("image", "\\\\powershell\\.exe$", regex=True)]),
]

s = requests.Session()
s.headers["Authorization"] = "Bearer " + api_key()
for name, children in CONTROLS:
    rec = {"hawk_id": "control", "filter_name": name, "_level": "test", "correlation_action": 0,
           "rules": [{"id": "and", "key": "And", "children": [{"id": "and", "key": "And", "children": children}]}]}
    e = run_one(s, rec, 24)
    print(f"{e.get('status'):11s} hits={e.get('hits', '-'):>8} {name}  {e.get('error') or e.get('reason') or ''}")
    if e.get("status") == "ok":
        print("            by:", [(b["product"], b["hits"]) for b in e["by_product"][:4]], "| q:", e["q"][:160])
