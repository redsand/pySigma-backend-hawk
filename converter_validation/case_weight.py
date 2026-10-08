"""Does a score actually push events toward a case? Final event weight of the events it matched.

The engine adds every matching score's weight (Subtract scores take it away) into the event's
`weight`; cases come from the final weight, not from any one score. A score that fires a lot but
whose events are pulled back down by suppression scores (e.g. a customer's vulnerability-scanner suppression score)
is not a case source. Counts per final-weight band over the window.

    python case_weight.py --titles "Suricata IDS Risk" "Teams Messages Read Via API (Likely Malicious)" [--hours 24]
    python case_weight.py --from-fired reports/fired_explore.json --min-weight 15 --min-per-hour 1
"""
import argparse
import json
import re

import requests
import urllib3

from backtest_explore import BASE, IDX, api_key

urllib3.disable_warnings()
BANDS = [("<15", None, 15), ("15-19", 15, 20), ("20-29", 20, 30), ("30-49", 30, 50), (">=50", 50, None)]


def regex_query(title):
    # result_name is keyword; Lucene regexp over the whole value (anchored), so wrap in .*
    esc = re.sub(r'([.?+*|{}\[\]()"\\#@&<>~ ])', r"\\\1", title)
    return f"result_name:/.*{esc}.*/"


def bands(session, title, hours):
    j = session.post(BASE + "explore/aggregate", data={"idx": IDX, "q": regex_query(title), "from": f"now-{int(hours * 60)}m", "to": "now",
                     "group_by": "weight", "metric": "count", "size": "200"}, timeout=600, verify=False).json()
    rows = (j.get("results") or {}).get("rows") or []
    out = {b: 0 for b, _, _ in BANDS}
    for r in rows:
        try:
            w = float(r.get("weight"))
        except (TypeError, ValueError):
            continue
        for b, lo, hi in BANDS:
            if (lo is None or w >= lo) and (hi is None or w < hi):
                out[b] += int(r.get("count") or 0)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--titles", nargs="*", default=[])
    ap.add_argument("--from-fired")
    ap.add_argument("--min-weight", type=float, default=15)
    ap.add_argument("--min-per-hour", type=float, default=1)
    ap.add_argument("--hours", type=float, default=24)
    args = ap.parse_args()
    s = requests.Session()
    s.headers["Authorization"] = "Bearer " + api_key()
    titles = list(args.titles)
    if args.from_fired:
        d = json.load(open(args.from_fired, encoding="utf-8"))
        titles += [r["title"] for r in d["rows"] if r["enabled"] and r.get("action") != "Subtract (-)"
                   and r["weight"] >= args.min_weight and r["events"] / d["hours"] >= args.min_per_hour]
    rows = []
    for t in dict.fromkeys(titles):
        b = bands(s, t, args.hours)
        total = sum(b.values())
        high = b["20-29"] + b["30-49"] + b[">=50"]
        rows.append((high, t, total, b))
    for high, t, total, b in sorted(rows, reverse=True):
        print(f"{high / args.hours:>8.1f}/h at final weight >=20  ({total / args.hours:>8.1f}/h matched)  {t[:60]}  {b}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
