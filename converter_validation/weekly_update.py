"""Weekly Sigma -> HAWK update report. Changes NOTHING in production.

Steps:
  1. fetch SigmaHQ (remote `upstream`) into ../../sigma and fast-forward master
  2. convert the whole corpus (convert_corpus.py)
  3. record weights tuned in the portal into score_weights.json (track_weights.py --write; local only)
  4. plan refreshes (refresh_plan.py), minus the hold list
  5. list new rules not in production and deprecated rules still enabled
  6. backtest new + changed rules against explore (backtest_explore.py)
  7. per-score firing for the last 7 days (fired_explore.py) -> loud scores at weight >= 15

Writes reports/weekly/<date>/ (id lists ready for sync_scores.py / disable_scores.py) and
reports/weekly/<date>/summary.md. Pushing, enabling and weight changes stay manual:

    python sync_scores.py --select reports/weekly/<date>/refresh.txt --execute --verify   # refreshes
    python sync_scores.py --select reports/weekly/<date>/new.txt --execute --verify       # new, disabled
    python disable_scores.py --hawk-ids-file reports/weekly/<date>/deprecated_enabled.txt --execute
    python set_weights.py --set <score_id>=<w> ... --reason "..." --execute

Usage: python weekly_update.py [--hours 168] [--skip-fetch]
"""
import argparse
import csv
import datetime
import glob
import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SIGMA = (HERE / ".." / ".." / "sigma").resolve()
DIRS = "rules,rules-emerging-threats,rules-threat-hunting,rules-compliance,deprecated"


def run(cmd, cwd=HERE, timeout=3600):
    print("$", " ".join(str(c) for c in cmd), flush=True)
    p = subprocess.run([str(c) for c in cmd], cwd=cwd, capture_output=True, text=True, timeout=timeout)
    if p.returncode != 0:
        raise SystemExit(f"failed ({p.returncode}): {' '.join(map(str, cmd))}\n{p.stdout[-2000:]}\n{p.stderr[-2000:]}")
    return p.stdout


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--hours", type=float, default=168)
    ap.add_argument("--skip-fetch", action="store_true")
    args = ap.parse_args()

    day = datetime.date.today().isoformat()
    out = HERE / "reports" / "weekly" / day
    out.mkdir(parents=True, exist_ok=True)
    md = [f"# Sigma -> HAWK weekly update, {day}", ""]

    # 1. SigmaHQ
    before = run(["git", "rev-parse", "HEAD"], cwd=SIGMA).strip()
    if not args.skip_fetch:
        run(["git", "fetch", "-q", "upstream"], cwd=SIGMA)
        run(["git", "merge", "-q", "--ff-only", "upstream/master"], cwd=SIGMA)
    after = run(["git", "rev-parse", "HEAD"], cwd=SIGMA).strip()
    prs = run(["git", "log", "--format=- %ad %s", "--date=short", f"{before}..{after}"], cwd=SIGMA).strip()
    changed = run(["git", "diff", "--name-status", before, after, "--"] + DIRS.split(","), cwd=SIGMA).strip()
    md += ["## SigmaHQ", f"{before[:9]} -> {after[:9]}", "", prs or "- no new commits", ""]
    if changed:
        md += ["```", changed, "```", ""]

    # 2. convert
    conv_path = HERE / "reports" / "converted.jsonl"
    if conv_path.exists():
        conv_path.replace(HERE / "reports" / f"converted_before_{day}.jsonl")
    print(run([sys.executable, "convert_corpus.py", str(SIGMA), "--dirs", DIRS,
               "--extra-root", str(HERE.parent / "hawk_rules")]).strip().splitlines()[-1])
    print(run([sys.executable, "test_hawk_rules.py"]).strip())
    print(run([sys.executable, "test_score_filters.py"]).strip())
    conv = {json.loads(l)["hawk_id"].lower(): json.loads(l) for l in conv_path.read_text(encoding="utf-8").splitlines() if l.strip()}
    errs = HERE / "reports" / "converted.jsonl.errors.json"
    nerr = len(json.loads(errs.read_text(encoding="utf-8"))) if errs.exists() else 0
    md += ["## Conversion", f"{len(conv)} records, {nerr} conversion errors", ""]
    # hawk_rules entries contributed upstream keep their id; once SigmaHQ merges one, both copies
    # convert to the same hawk_id - delete the hawk_rules copy (e.g. SigmaHQ PR #6439).
    import collections as _c
    _ids = _c.Counter(json.loads(l)["hawk_id"].lower() for l in conv_path.read_text(encoding="utf-8").splitlines() if l.strip())
    _dups = sorted(h for h, n in _ids.items() if n > 1)
    if _dups:
        md += ["### ACTION: rule ids present in both SigmaHQ and hawk_rules (delete the hawk_rules copy)", ""] + [f"- {h}" for h in _dups] + [""]

    # 3. portal weight edits -> ledger
    tw = run([sys.executable, "track_weights.py", "--write", "--reason", f"portal edit, recorded {day}"])
    md += ["## Weights tuned in the portal (now in score_weights.json)", "```", tw.strip(), "```", ""]

    # 4. refreshes
    for f in glob.glob(str(HERE / "reports" / "refresh_group_*")):
        os.remove(f)
    run([sys.executable, "refresh_plan.py", "100000"])
    hold = {l.strip().lower() for l in (HERE / "reports" / "refresh_hold_all.txt").read_text(encoding="utf-8").splitlines() if l.strip()}
    diff = HERE / "reports" / "refresh_group_001_diff.csv"
    rows = list(csv.DictReader(diff.open(encoding="utf-8"))) if diff.exists() else []
    refresh = [r for r in rows if r["hawk_id"] not in hold]

    # 5. new / deprecated (live snapshot written by fired_explore below is not needed here)
    import requests, urllib3  # noqa: E401
    urllib3.disable_warnings()
    from backtest_explore import BASE, api_key
    live = {str(x.get("hawk_id")).lower(): x for x in requests.get(BASE + "scores?recursive=true&format=json",
            headers={"Authorization": "Bearer " + api_key()}, timeout=900, verify=False).json()["results"] if x.get("hawk_id")}
    new = [c for h, c in conv.items() if h not in live and not c["_source"].startswith("deprecated")]
    dep = [h for h, c in conv.items() if c["_source"].startswith("deprecated") and live.get(h, {}).get("enabled")]
    (out / "new.txt").write_text("\n".join(c["hawk_id"].lower() for c in new) + "\n", encoding="utf-8")
    (out / "refresh.txt").write_text("\n".join(r["hawk_id"] for r in refresh) + "\n", encoding="utf-8")
    (out / "push.txt").write_text("\n".join([c["hawk_id"].lower() for c in new] + [r["hawk_id"] for r in refresh]) + "\n", encoding="utf-8")
    (out / "deprecated_enabled.txt").write_text("\n".join(dep) + "\n", encoding="utf-8")
    md += ["## To push (push.txt = new.txt + refresh.txt)", f"{len(new)} new rules (go in disabled), {len(refresh)} refreshes "
           f"({len(rows) - len(refresh)} more differ but are on the hold list)", ""]
    for c in sorted(new, key=lambda c: c["_level"] or ""):
        md.append(f"- NEW [{c['_level']}/{c['_status']}] w={c['correlation_action']} {c['filter_name']}")
    for r in refresh:
        md.append(f"- REFRESH {r['score_id']} ({'enabled' if r['enabled'] == 'True' else 'disabled'}, {r['kind']}) {r['title']}")
    md += ["", f"## Deprecated in Sigma but enabled: {len(dep)} (deprecated_enabled.txt)", ""]
    for h in dep:
        md.append(f"- {live[h]['score_id']} {live[h]['filter_name']}")
    md.append("")

    # 6. backtest what would be pushed
    push_ids = (out / "push.txt").read_text(encoding="utf-8").split()
    if push_ids:
        run([sys.executable, "backtest_explore.py", "--select", out / "push.txt", "--hours", "72", "--out", out / "backtest.json"], timeout=7200)
        bt = json.loads((out / "backtest.json").read_text(encoding="utf-8"))
        bt = bt.get("results", bt) if isinstance(bt, dict) else bt
        md += ["## Backtest of push.txt (72h, explore; `upper` = upper bound)",
               "Rules at >= 10/h should stay disabled or be tuned before enabling.", ""]
        for e in sorted(bt, key=lambda e: -(e.get("hits_per_hour") or 0)):
            md.append(f"- {e.get('hits_per_hour', '-')}/h {e.get('bound', e.get('status'))} {e.get('title')}")
        md.append("")

    # 7. firing
    run([sys.executable, "fired_explore.py", "--hours", str(args.hours)], timeout=7200)
    fired = json.loads((HERE / "reports" / "fired_explore.json").read_text(encoding="utf-8"))
    (out / "fired.json").write_text(json.dumps(fired, indent=1), encoding="utf-8")
    # only scores that ADD weight raise incidents; "Subtract (-)" scores are suppressions
    loud = [r for r in fired["rows"] if r["enabled"] and r.get("action") != "Subtract (-)"
            and r["weight"] >= 15 and r["events"] / args.hours >= 1]
    sig = [r for r in fired["rows"] if r["sigma"] and r["enabled"]]
    md += [f"## Firing, last {args.hours:g}h", f"{len(sig)} enabled Sigma scores fired; "
           f"{len(loud)} enabled scores at weight >= 15 fire >= 1/h on their own (candidates for set_weights.py):", ""]
    for r in sorted(loud, key=lambda r: -r["events"]):
        md.append(f"- {r['events'] / args.hours:.1f}/h w={r['weight']:g} {r['score_id']} {r['title']}{'' if r['sigma'] else ' (not Sigma)'}")
    md.append("")

    # what actually reaches case territory: final event weight of the loud scores' events
    cw = run([sys.executable, "case_weight.py", "--from-fired", str(out / "fired.json"),
              "--min-weight", "15", "--min-per-hour", "1", "--hours", str(min(args.hours, 24))], timeout=7200)
    md += ["## Case sources: events at final weight >= 20 (after Subtract scores), last 24h",
           "A score that fires a lot but whose events end below 20 is suppressed elsewhere and is not a case source.",
           "```", cw.strip(), "```", ""]

    (out / "summary.md").write_text("\n".join(md), encoding="utf-8")
    print(f"\nreport: {out / 'summary.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
