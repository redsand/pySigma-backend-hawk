"""Daily threat hunt: run hunts.yml over Explore and report activity no detection matched.

result_name is on every event: it also carries the generic context scores (Priority N, Asset Risk,
Bayesian, Internal to Internal...). So an event is UNSCORED when none of the names in its result_name
is a Sigma/HAWK detection (a hawk_id in reports/converted.jsonl), worked out client-side from a sample
of up to SAMPLE events per hunt (image and command are text fields and cannot be aggregated).

For each hunt: all matching events, then from the sample the unscored share and its top hosts and
top values of the hunt's `report_by` column (default image). A host or value never seen
for that hunt in the last BASELINE_DAYS days is NEW: that is the hunting signal (a long-standing
unscored value is baseline, already looked at). Hunts with new unscored activity are candidates for a
score.

    python hunt_explore.py [--hours 24] [--only "<hunt name>"]

Writes reports/hunt/<date>/hunt.json + summary.md and keeps reports/hunt/baseline.json.
Exits 1 if any hunt failed (bad column, Explore error), after writing what did run.
"""
import argparse
import collections
import datetime
import json
import re
from pathlib import Path

import requests
import urllib3
import yaml

from backtest_explore import BASE, IDX, api_key, is_indexed, q_phrase

HERE = Path(__file__).resolve().parent
BASELINE_DAYS = 30
TOP = 10
SAMPLE = 1000
USER_DIR = re.compile(r"(?i)(\\Users\\)[^\\]+\\")
# per-run random names, so one installer is one value: {GUID} and {8-hex} folders, InstallShield _isXXXX.exe
RANDOM_PART = re.compile(r"(?i)\{[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\}|\{[0-9a-f]{8}\}|(?<=\\_is)[0-9a-f]{3,5}(?=\.exe$)")
urllib3.disable_warnings()


def normalize(v: str) -> str:
    return RANDOM_PART.sub("*", USER_DIR.sub(r"\1*\\", v))


def detection_pattern(session):
    """Regex over result_name that finds the title of any live score that is a Sigma/HAWK detection."""
    conv = {json.loads(l)["hawk_id"].lower() for l in (HERE / "reports" / "converted.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()}
    live = session.get(BASE + "scores?recursive=true&format=json", timeout=900, verify=False).json()["results"]
    titles = sorted({s["filter_name"].strip() for s in live if s.get("filter_name") and str(s.get("hawk_id")).lower() in conv}, key=len, reverse=True)
    if not titles:
        raise SystemExit("no Sigma/HAWK score titles found: cannot tell scored from unscored")
    return re.compile("|".join(re.escape(t) for t in titles))


def sample(session, q: str, hours: float) -> list:
    j = session.post(BASE + "explore/search", data={"idx": IDX, "q": q, "from": f"now-{int(round(hours * 60))}m", "to": "now",
                                                    "size": str(SAMPLE)}, timeout=900, verify=False).json()
    rows = (j.get("results") or {}).get("rows")
    if rows is None:
        raise RuntimeError(f"explore search error: {str(j.get('details'))[:300]}")
    return rows


def clause(spec: dict) -> str:
    (col, values), = spec.items()
    if not is_indexed(col):
        raise ValueError(f"column {col!r} is not searchable in Explore")
    return "(" + " OR ".join(q_phrase(col, v) for v in values) + ")"


def build_query(h: dict) -> str:
    q = " AND ".join(clause(c) for c in h["all"])
    for c in h.get("not", []):
        q += " AND NOT " + clause(c)
    return q


def top(session, q: str, group_by: str, hours: float) -> list:
    j = session.post(BASE + "explore/aggregate", data={"idx": IDX, "q": q, "from": f"now-{int(round(hours * 60))}m", "to": "now",
                                                       "group_by": group_by, "metric": "count", "size": str(TOP)},
                     timeout=900, verify=False).json()
    rows = (j.get("results") or {}).get("rows")
    if rows is None:
        raise RuntimeError(f"explore error ({group_by}): {str(j.get('details'))[:300]}")
    return [(str(r.get(group_by)), int(r.get("count") or 0)) for r in rows]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--hours", type=float, default=24)
    ap.add_argument("--only")
    args = ap.parse_args()
    today = datetime.date.today()
    out = HERE / "reports" / "hunt" / today.isoformat()
    out.mkdir(parents=True, exist_ok=True)
    base_path = HERE / "reports" / "hunt" / "baseline.json"
    baseline = json.loads(base_path.read_text(encoding="utf-8")) if base_path.exists() else {}
    cutoff = (today - datetime.timedelta(days=BASELINE_DAYS)).isoformat()
    first_run = not baseline

    session = requests.Session()
    session.headers["Authorization"] = "Bearer " + api_key()
    hunts = yaml.safe_load((HERE / "hunts.yml").read_text(encoding="utf-8"))["hunts"]
    detect = detection_pattern(session)
    results, failed = [], 0
    for h in hunts:
        if args.only and h["name"] != args.only:
            continue
        r = {"name": h["name"], "mitre": h.get("mitre")}
        try:
            q = build_query(h)
            by = h.get("report_by", "image")
            rows = sample(session, q, args.hours)
            scored = collections.Counter()
            unscored = []
            for e in rows:
                found = {m.group(0) for m in detect.finditer(str(e.get("result_name") or ""))}
                scored.update(found)
                if not found:
                    unscored.append(e)
            r.update(q=q, report_by=by, total=sum(n for _, n in top(session, q, "resource_name", args.hours)),
                     sampled=len(rows), unscored=len(unscored), scored_by=scored.most_common(5),
                     hosts=collections.Counter(str(e.get("resource_name")) for e in unscored).most_common(TOP),
                     values=collections.Counter(normalize(str(e.get(by))) for e in unscored).most_common(TOP))
            r["total"] = max(r["total"], r["sampled"])  # the host aggregation skips events without resource_name
            if h.get("expect_hits") and not r["total"]:
                raise RuntimeError("positive control returned no events: Explore search is broken, every hunt result is suspect")
            # NEW is judged on the behaviour (the report_by value), not on hosts: a known-benign binary on one
            # more laptop is not a finding. Per-user folders are masked so each user's copy is the same value.
            # A control is not a hunt: it never produces candidates or baseline entries.
            r["new"] = []
            for v, n in ([] if h.get("expect_hits") else r["values"]):
                key = f"{h['name']}|{by}|{v}"
                if baseline.get(key, "") < cutoff:
                    r["new"].append({by: v, "events": n})
                baseline[key] = today.isoformat()
        except (ValueError, RuntimeError, requests.RequestException) as e:
            r["error"] = f"{type(e).__name__}: {e}"
            failed += 1
        results.append(r)
        print(f"{'ERR ' if 'error' in r else 'ok  '} {h['name']}: total={r.get('total')} unscored={r.get('unscored')} "
              f"new={len(r.get('new', []))} {r.get('error', '')}", flush=True)

    baseline = {k: v for k, v in baseline.items() if v >= cutoff}
    base_path.write_text(json.dumps(baseline, indent=0, sort_keys=True), encoding="utf-8")
    (out / "hunt.json").write_text(json.dumps({"hours": args.hours, "first_run": first_run, "results": results}, indent=1), encoding="utf-8")

    md = [f"# Threat hunt, {today} (last {args.hours:g}h)", ""]
    if first_run:
        md += ["First run: everything below is NEW because there is no baseline yet; from tomorrow only changes are new.", ""]
    cands = [r for r in results if r.get("new")]
    md += [f"## Candidates (new unscored activity): {len(cands)} of {len(results)} hunts", ""]
    for r in cands:
        md += [f"### {r['name']} ({r['mitre']})", f"- events {r['total']}; of {r['sampled']} sampled, {r['unscored']} matched no detection; detections seen: "
               + (", ".join(f"{t[:60]} ({n})" for t, n in r["scored_by"]) or "nothing")]
        md += [f"- NEW {', '.join(f'{k}={v}' for k, v in n.items() if k != 'events')}: {n['events']} events" for n in r["new"]]
        md += ["- hosts: " + ", ".join(f"{v} ({n})" for v, n in r["hosts"][:5]), ""]
    md += ["## All hunts", "", "| hunt | events | sampled | no detection | new | status |", "|---|---|---|---|---|---|"]
    md += [f"| {r['name']} | {r.get('total', '')} | {r.get('sampled', '')} | {r.get('unscored', '')} | {len(r.get('new', []))} | {r.get('error', 'ok')} |"
           for r in results]
    (out / "summary.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print(f"\nreport: {out / 'summary.md'}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
