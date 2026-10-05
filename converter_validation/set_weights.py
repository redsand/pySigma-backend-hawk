"""Change production score weights WITHOUT touching their logic, and record them in the ledger.

Posts each score's own live row back to POST /scores/<score_id> with correlation_action changed
and a dated "WEIGHT <date>: a -> b (reason)" note prepended to its comments (enabled, rules,
dates kept), the same path disable_scores.py uses. Safe for held scores,
whose logic a sync_scores.py push would replace. Every change is written to score_weights.json
so later syncs keep it.

    python set_weights.py --set 1307=5 --set 2409=10 --reason "fires 20/h on its own"          # dry run
    python set_weights.py --set 1307=5 --set 2409=10 --reason "fires 20/h on its own" --execute
"""
import argparse
import datetime
import json
import time

import requests
import urllib3

from disable_scores import BASE, api_key, row_to_form
from track_weights import load_ledger, save_ledger

urllib3.disable_warnings()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--set", action="append", required=True, help="score_id=weight (repeatable)")
    ap.add_argument("--reason", required=True)
    ap.add_argument("--execute", action="store_true")
    args = ap.parse_args()

    want = {int(k): float(v) for k, v in (s.split("=", 1) for s in args.set)}
    session = requests.Session()
    session.headers["Authorization"] = "Bearer " + api_key()
    live = {r["score_id"]: r for r in session.get(BASE + "scores?recursive=true&format=json", timeout=900, verify=False).json()["results"]}
    ledger = load_ledger()
    today = datetime.date.today().isoformat()

    for sid, weight in want.items():
        row = live.get(sid)
        if not row:
            print(f"{sid}: not found")
            continue
        before = float(row.get("correlation_action") or 0)
        print(f"{'SET ' if args.execute else 'DRY '} {sid:>7} {before} -> {weight}  {str(row.get('filter_name'))[:60]}")
        if not args.execute:
            continue
        old_note = str(row.get("comments") or "").strip()
        new_note = f"WEIGHT {today}: {before:g} -> {weight:g} ({args.reason})" + ("\n" + old_note if old_note else "")
        form = row_to_form(dict(row, correlation_action=weight, comments=new_note), bool(row.get("enabled")))
        r = session.post(BASE + f"scores/{sid}", data=form, timeout=120, verify=False)
        status = (r.json() if r.headers.get("content-type", "").startswith("application/json") else {}).get("status")
        print(f"        -> {r.status_code} {status}")
        if row.get("hawk_id"):
            ledger[str(row["hawk_id"]).lower()] = {"weight": weight, "reason": args.reason, "source": "local",
                                                   "recorded": today, "previous_weight": before,
                                                   "score_id": sid, "title": row.get("filter_name")}
        time.sleep(0.2)

    if args.execute:
        save_ledger(ledger)
        after = {r["score_id"]: r for r in session.get(BASE + "scores?recursive=true&format=json", timeout=900, verify=False).json()["results"]}
        bad = [sid for sid, w in want.items() if sid in after and abs(float(after[sid]["correlation_action"] or 0) - w) > 1e-6]
        moved = [sid for sid in want if sid in after and (after[sid]["enabled"] != live[sid]["enabled"]
                 or json.dumps(after[sid]["rules"], sort_keys=True) != json.dumps(live[sid]["rules"], sort_keys=True)
                 or after[sid]["date_added"] != live[sid]["date_added"])]
        print(f"verified: {len(want) - len(bad)}/{len(want)} weights set; enabled/rules/date changed on {len(moved)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
