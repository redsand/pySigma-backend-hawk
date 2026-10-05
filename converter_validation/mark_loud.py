"""Disable a score because it is too noisy, and say so where people will see it.

Marking a score LOUD:
  * disables it,
  * appends " (LOUD)" to its title, so the portal list shows why it is off,
  * prepends a dated note to its comments ("LOUD 2026-10-05: <reason>"), keeping existing notes.
sync_scores.py keeps the (LOUD) title on refresh, and disable_scores.py --enable refuses LOUD
scores unless --allow-loud, so a bulk enable cannot switch one back on by accident.

    python mark_loud.py --score-ids 1307,2214 --reason "157/h on its own, 7d" [--execute]
    python mark_loud.py --score-ids 1307 --clear --reason "tuned: filter on agent" [--execute]

--clear removes the title marker and adds a dated note; the score stays disabled (enable it
deliberately with disable_scores.py --enable --allow-loud).
"""
import argparse
import datetime
import time

import requests
import urllib3

from disable_scores import BASE, api_key, row_to_form

urllib3.disable_warnings()
MARK = " (LOUD)"


def is_loud(row: dict) -> bool:
    return "(LOUD)" in str(row.get("filter_name") or "")


def note(row: dict, text: str) -> str:
    old = str(row.get("comments") or "").strip()
    return text + ("\n" + old if old else "")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--score-ids", required=True)
    ap.add_argument("--reason", required=True)
    ap.add_argument("--clear", action="store_true")
    ap.add_argument("--execute", action="store_true")
    args = ap.parse_args()

    ids = [int(x) for x in args.score_ids.split(",") if x.strip()]
    s = requests.Session()
    s.headers["Authorization"] = "Bearer " + api_key()
    live = {r["score_id"]: r for r in s.get(BASE + "scores?recursive=true&format=json", timeout=900, verify=False).json()["results"]}
    today = datetime.date.today().isoformat()

    for sid in ids:
        row = live.get(sid)
        if not row:
            print(f"{sid}: not found")
            continue
        title = str(row.get("filter_name") or "")
        if args.clear:
            if not is_loud(row):
                print(f"{sid}: not marked LOUD, skipped")
                continue
            new = dict(row, filter_name=title.replace(MARK, "").replace("(LOUD)", "").strip(),
                       comments=note(row, f"LOUD cleared {today}: {args.reason}"))
            enabled = bool(row.get("enabled"))
        else:
            base = title if is_loud(row) else (title[:255 - len(MARK)] + MARK)
            new = dict(row, filter_name=base, comments=note(row, f"LOUD {today}: {args.reason}"))
            enabled = False
        print(f"{'DO ' if args.execute else 'DRY'} {sid:>7} enabled {bool(row.get('enabled'))}->{enabled}  {new['filter_name'][:80]}")
        if args.execute:
            r = s.post(BASE + f"scores/{sid}", data=row_to_form(new, enabled), timeout=120, verify=False)
            print(f"        -> {r.status_code} {(r.json() if 'json' in r.headers.get('content-type', '') else {}).get('status')}")
            time.sleep(0.2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
