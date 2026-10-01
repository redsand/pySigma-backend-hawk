"""Per-score firing counts from explore, now that result_name is a keyword field (2026-10-01).

result_name holds every score that matched an event, comma-joined. One terms aggregation over
result_name returns each distinct combination with its event count; each combination is split
back into score names by matching the live score titles (titles can themselves contain commas,
so splitting on ", " alone is not safe). Also counts distinct hosts and groups per score.

    python fired_explore.py [--hours 24] [--size 20000]

Writes reports/fired_explore.json and prints the noisiest Sigma scores.
Only events stored after the mapping was applied (2026-10-01) carry a searchable result_name.
"""
import argparse
import collections
import json
import re
from pathlib import Path

import requests
import urllib3

from backtest_explore import BASE, IDX, api_key

HERE = Path(__file__).resolve().parent
urllib3.disable_warnings()


def aggregate(session, q, group_by, hours, size):
    j = session.post(BASE + "explore/aggregate", data={"idx": IDX, "q": q, "from": f"now-{int(round(hours * 60))}m", "to": "now",
                                                       "group_by": group_by, "metric": "count", "size": str(size)},
                     timeout=900, verify=False).json()
    rows = (j.get("results") or {}).get("rows")
    if rows is None:
        raise SystemExit(f"explore error: {str(j.get('details'))[:300]}")
    return [(str(r.get(group_by)), int(r.get("count") or 0)) for r in rows]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--hours", type=float, default=24)
    ap.add_argument("--size", type=int, default=20000)
    args = ap.parse_args()

    session = requests.Session()
    session.headers["Authorization"] = "Bearer " + api_key()
    live = session.get(BASE + "scores?recursive=true&format=json", timeout=900, verify=False).json()["results"]
    conv = {json.loads(l)["hawk_id"].lower() for l in (HERE / "reports" / "converted.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()}
    by_title = collections.defaultdict(list)
    for s in live:
        if s.get("filter_name"):
            by_title[s["filter_name"].strip()].append(s)
    # longest titles first so "X - PowerShell Module" wins over "X"
    titles = sorted(by_title, key=len, reverse=True)
    pattern = re.compile("|".join(re.escape(t) for t in titles))

    combos = aggregate(session, "_exists_:result_name", "result_name", args.hours, args.size)
    total_events = sum(n for _, n in combos)
    hits = collections.Counter()
    for combo, n in combos:
        for t in set(m.group(0) for m in pattern.finditer(combo)):
            hits[t] += n

    rows = []
    for t, n in hits.items():
        for s in by_title[t]:
            rows.append({"score_id": s["score_id"], "hawk_id": s.get("hawk_id"), "title": t, "enabled": bool(s.get("enabled")),
                         "weight": float(s.get("correlation_action") or 0), "action": s.get("actions_category_name"),
                         "sigma": str(s.get("hawk_id")).lower() in conv, "events": n, "per_hour": round(n / args.hours, 1)})
    rows.sort(key=lambda r: -r["events"])
    out = {"hours": args.hours, "combos": len(combos), "combos_truncated": len(combos) >= args.size,
           "events_with_result": total_events, "rows": rows}
    (HERE / "reports" / "fired_explore.json").write_text(json.dumps(out, indent=1), encoding="utf-8")

    print(f"{args.hours}h: {total_events} events with a result, {len(combos)} combinations"
          + (" (TRUNCATED, raise --size)" if out["combos_truncated"] else ""))
    sig = [r for r in rows if r["sigma"]]
    print(f"scores fired: {len(rows)} ({len(sig)} Sigma)")
    print("noisiest Sigma scores (events, weight, enabled, title):")
    for r in sig[:30]:
        print(f"  {r['events']:>8} w={r['weight']:<5} {'on ' if r['enabled'] else 'off'} {r['score_id']:>7} {r['title'][:70]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
