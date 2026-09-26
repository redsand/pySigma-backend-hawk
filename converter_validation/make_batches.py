"""Build the next push batches from the converted corpus.

Selects rules that are NOT yet in production (by hawk_id against the latest live pull), match the
requested levels/statuses, have a presence verdict of ok/low_presence, and are not deprecated.
Orders critical > high > medium and newest first, and writes reports/batch_<NNN>_draft.txt files
of at most --size rules, numbering from --start.

Usage:
    python make_batches.py --levels medium --statuses stable,test --start 4
"""
import argparse
import collections
import csv
import json
from pathlib import Path

import requests
import urllib3

HERE = Path(__file__).resolve().parent
BASE = "https://portal.hawk.io:8080/API/1.1/"
urllib3.disable_warnings()
LEVEL_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}


def api_key() -> str:
    for line in (HERE / "hawk.env").read_text(encoding="utf-8").splitlines():
        if line.startswith("HAWK_API_KEY="):
            return line.split("=", 1)[1].strip()
    raise SystemExit("HAWK_API_KEY missing")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--levels", default="critical,high")
    ap.add_argument("--statuses", default="stable,test")
    ap.add_argument("--start", type=int, default=1)
    ap.add_argument("--size", type=int, default=100)
    ap.add_argument("--live-refresh", action="store_true", help="re-pull the live score list first")
    args = ap.parse_args()

    live_path = HERE / "live" / "scores_latest.json"
    if args.live_refresh or not live_path.exists():
        r = requests.get(BASE + "scores?recursive=true&format=json", headers={"Authorization": "Bearer " + api_key()}, timeout=600, verify=False)
        live_path.write_text(json.dumps(r.json()), encoding="utf-8")
    live = json.loads(live_path.read_text(encoding="utf-8"))["results"]
    live_ids = {str(x.get("hawk_id")).lower() for x in live if x.get("hawk_id")}
    pres = {r["hawk_id"].lower(): r for r in csv.DictReader((HERE / "reports" / "stream_presence.csv").open(encoding="utf-8"))}
    levels = set(args.levels.split(","))
    statuses = set(args.statuses.split(","))
    cands = []
    for line in (HERE / "reports" / "converted.jsonl").read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        rec = json.loads(line)
        hid = rec["hawk_id"].lower()
        if hid in live_ids or rec["_source"].startswith("deprecated"):
            continue
        if rec["_level"] not in levels or rec["_status"] not in statuses:
            continue
        v = pres.get(hid, {}).get("verdict", "no_profile")
        cands.append((LEVEL_RANK.get(rec["_level"], 9), rec["_date"], hid, rec["filter_name"], rec["_source"], v, rec["correlation_action"]))
    ok = [c for c in cands if c[5] in ("ok", "low_presence")]
    ok.sort(key=lambda t: (t[0], -int(t[1][:4] or 0)))
    rest = [c for c in cands if c[5] not in ("ok", "low_presence")]
    print("pool:", len(cands), collections.Counter(c[5] for c in cands))
    n = args.start
    for j in range(0, len(ok), args.size):
        chunk = ok[j:j + args.size]
        p = HERE / "reports" / f"batch_{n:03d}_draft.txt"
        p.write_text(f"# batch {n:03d} draft: levels={args.levels} statuses={args.statuses}, verified column presence\n"
                     + "\n".join(f"{c[2]}  # {c[3]} | {c[4]} | {c[5]} | score {c[6]}" for c in chunk) + "\n", encoding="utf-8")
        print(f"batch_{n:03d}: {len(chunk)}", collections.Counter(c[5] for c in chunk))
        n += 1
    (HERE / "reports" / f"unverified_{args.levels.replace(',', '_')}.txt").write_text(
        "# not yet verifiable in the stream (no profile for the gated population)\n" + "\n".join(f"{c[2]}  # {c[3]} | {c[4]} | {c[5]}" for c in rest) + "\n", encoding="utf-8")
    print("unverified:", len(rest))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
