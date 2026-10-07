"""Apply score_filters.yml exclusions to production scores that the Sigma sync does NOT manage.

sync_scores.py applies exclusions when it pushes converted SigmaHQ / hawk_rules logic. Scores
from elsewhere (custom portal scores, the Sigma-Rules threat-report packs) are never re-pushed,
so their exclusions are written once into the live logic here, through POST /scores/<score_id>
(the same path disable_scores.py uses; enabled, weight and dates are kept).

Idempotent: an exclusion whose "hawk_filter:<tier>:<name>" leaves are already present is skipped.
Each applied exclusion adds a dated FILTER note to the score's comments.

    python apply_filters_live.py                 # dry run: what would be added
    python apply_filters_live.py --execute
"""
import argparse
import datetime
import json
import time
from pathlib import Path

import requests
import urllib3

from disable_scores import BASE, api_key, row_to_form
from score_filters import exclusion_node, fetch_group_tree, load_filters

HERE = Path(__file__).resolve().parent
urllib3.disable_warnings()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--execute", action="store_true")
    args = ap.parse_args()
    s = requests.Session()
    s.headers["Authorization"] = "Bearer " + api_key()
    filters = load_filters(groups=fetch_group_tree(s, BASE))
    conv = {json.loads(l)["hawk_id"].lower() for l in (HERE / "reports" / "converted.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()}
    live = {str(r.get("hawk_id")).lower(): r for r in s.get(BASE + "scores?recursive=true&format=json", timeout=900, verify=False).json()["results"] if r.get("hawk_id")}
    today = datetime.date.today().isoformat()
    changed = []
    for hid, exclusions in filters.items():
        if hid in conv:
            continue  # managed by sync_scores.py
        row = live.get(hid)
        if not row:
            print(f"{hid}: not in production, skipped")
            continue
        rules = json.loads(row["rules"]) if isinstance(row["rules"], str) else row["rules"]
        text = json.dumps(rules)
        todo = [e for e in exclusions if f"hawk_filter:{e['tier']}:{e['name']}" not in text]
        if not todo:
            print(f"{row['score_id']:>7} {row['filter_name'][:60]}: up to date")
            continue
        top = rules[0] if isinstance(rules, list) else rules
        if str(top.get("key", "")).lower() != "and":
            top = {"id": "and", "key": "And", "children": [top]}
        kids = top.setdefault("children", [])
        first_fn = next((i for i, c in enumerate(kids) if c.get("class") == "function"), len(kids))
        top["children"] = kids[:first_fn] + [exclusion_node(e) for e in todo] + kids[first_fn:]
        new_rules = [top] if isinstance(rules, list) else top
        note = "\n".join(f"FILTER {today}: excluded {e['name']} ({e['tier']}{', ' + e['customer'] if e.get('customer') else ''})" for e in todo)
        old_note = str(row.get("comments") or "").strip()
        print(f"{'APPLY' if args.execute else 'DRY  '} {row['score_id']:>7} {row['filter_name'][:60]}: +{len(todo)} exclusion(s)")
        if args.execute:
            form = row_to_form(dict(row, rules=new_rules, comments=note + ("\n" + old_note if old_note else "")), bool(row.get("enabled")))
            r = s.post(BASE + f"scores/{row['score_id']}", data=form, timeout=120, verify=False)
            print(f"        -> {r.status_code} {(r.json() if 'json' in r.headers.get('content-type', '') else {}).get('status')}")
            changed.append((hid, row))
            time.sleep(0.2)
    if args.execute and changed:
        after = {str(r.get("hawk_id")).lower(): r for r in s.get(BASE + "scores?recursive=true&format=json", timeout=900, verify=False).json()["results"] if r.get("hawk_id")}
        for hid, before in changed:
            a = after[hid]
            ok = ("hawk_filter:" in json.dumps(a["rules"]) and a["enabled"] == before["enabled"]
                  and a["correlation_action"] == before["correlation_action"] and a["date_added"] == before["date_added"])
            print(f"verify {a['score_id']}: {'OK' if ok else 'MISMATCH'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
