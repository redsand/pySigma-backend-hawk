"""Download a time-spread sample of real normalized events per (product_name, vendor_id) stratum.

Strata are the populations the selected scores gate on (product_name / vendor_id leaves of both
the live and the converted logic). Each stratum gets --per events, spread over --windows equal
slices of the last --hours, keeping only the columns those scores reference (live/eval_keys.json)
plus the gate columns. Also records each stratum's event rate (events/hour over the same span),
so local_eval.py can turn sample match fractions into events/hour.

    python sample_strata.py --select reports/refresh_hold_all.txt [--per 6000 --windows 6 --hours 24]
Writes live/samples/<stratum>.jsonl and live/samples/strata.json.
"""
import argparse
import json
import re
import time
from pathlib import Path

import requests
import urllib3

from backtest_explore import BASE, IDX, api_key

HERE = Path(__file__).resolve().parent
OUT = HERE / "live" / "samples"
urllib3.disable_warnings()
GATE = ["product_name", "vendor_id", "product_source", "event_channel", "vendor_name"]


def leaves(rules):
    rules = json.loads(rules) if isinstance(rules, str) else rules
    out = []

    def w(n):
        if isinstance(n, list):
            for c in n:
                w(c)
            return
        if n.get("class") in ("column", "function"):
            out.append(n)
        for c in n.get("children", []) or []:
            w(c)
    w(rules)
    return out


def eq_values(ls, key):
    vals = set()
    for l in ls:
        a = l.get("args") or {}
        if l.get("key") == key and (a.get("comparison") or {}).get("value") == "=" and not (a.get("str") or {}).get("regex") in (True, "true"):
            v = (a.get("str") or {}).get("value")
            if v is not None:
                vals.add(str(v))
    return vals


def strata_for(rules):
    ls = leaves(rules)
    prods, vids = eq_values(ls, "product_name"), eq_values(ls, "vendor_id")
    out = set()
    for p in prods:
        if vids:
            out |= {(p, v) for v in vids}
        else:
            out.add((p, "*"))
    return out


def name(st):
    return re.sub(r"[^A-Za-z0-9]+", "_", f"{st[0]}__{st[1]}").strip("_")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--select", required=True)
    ap.add_argument("--per", type=int, default=6000)
    ap.add_argument("--windows", type=int, default=6)
    ap.add_argument("--hours", type=int, default=24)
    ap.add_argument("--min-rate", type=float, default=0.0, help="skip strata below this many events/hour")
    args = ap.parse_args()

    ids = [l.strip().lower() for l in Path(args.select).read_text(encoding="utf-8").splitlines() if l.strip()]
    s = requests.Session()
    s.headers["Authorization"] = "Bearer " + api_key()
    live = {str(x.get("hawk_id")).lower(): x for x in s.get(BASE + "scores?recursive=true&format=json", timeout=900, verify=False).json()["results"] if x.get("hawk_id")}
    conv = {json.loads(l)["hawk_id"].lower(): json.loads(l) for l in (HERE / "reports" / "converted.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()}
    strata, keys = set(), set(GATE)
    for h in ids:
        for rules in ([live[h]["rules"]] if h in live else []) + ([conv[h]["rules"]] if h in conv else []):
            strata |= strata_for(rules)
            keys |= {l.get("key") for l in leaves(rules) if l.get("class") == "column"}
            keys |= {(l.get("args") or {}).get("column", {}).get("value") for l in leaves(rules) if l.get("class") == "function"}
    keys.discard(None)
    OUT.mkdir(parents=True, exist_ok=True)
    meta = {"hours": args.hours, "strata": {}}
    for st in sorted(strata):
        q = f'product_name:"{st[0]}"' + (f' AND vendor_id:"{st[1]}"' if st[1] != "*" else "")
        cnt = s.post(BASE + "explore/aggregate", data={"idx": IDX, "q": q, "from": f"now-{args.hours}h", "to": "now",
                     "group_by": "product_name", "metric": "count", "size": "3"}, timeout=600, verify=False).json()
        total = sum(int(r.get("count") or 0) for r in ((cnt.get("results") or {}).get("rows") or []))
        rate = total / args.hours
        if rate < args.min_rate or total == 0:
            meta["strata"][name(st)] = {"product_name": st[0], "vendor_id": st[1], "per_hour": rate, "sampled": 0}
            print(f"{name(st):<50} {rate:>10.1f}/h  skipped")
            continue
        per_window = max(1, min(10000, args.per // args.windows))
        span = args.hours / args.windows
        n = 0
        with (OUT / f"{name(st)}.jsonl").open("w", encoding="utf-8") as fh:
            for w in range(args.windows):
                frm, to = f"now-{int((w + 1) * span * 60)}m", f"now-{int(w * span * 60)}m"
                for attempt in range(3):
                    try:
                        j = s.post(BASE + "explore/search", data={"idx": IDX, "q": q, "from": frm, "to": to, "size": str(per_window)},
                                   timeout=600, verify=False).json()
                        break
                    except Exception:  # noqa: BLE001
                        time.sleep(5)
                else:
                    continue
                for row in (j.get("results") or {}).get("rows") or []:
                    fh.write(json.dumps({k: row[k] for k in keys if k in row and row[k] not in (None, "")}) + "\n")
                    n += 1
        meta["strata"][name(st)] = {"product_name": st[0], "vendor_id": st[1], "per_hour": rate, "sampled": n}
        print(f"{name(st):<50} {rate:>10.1f}/h  sampled {n}", flush=True)
    (OUT / "strata.json").write_text(json.dumps(meta, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
