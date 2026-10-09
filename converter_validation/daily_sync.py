"""Daily Sigma -> HAWK sync: bring every source up to date and push what changed.

Steps (all read-only unless --execute):
  1. git pull --ff-only this repo and the private content repo (siem/hawk-sigma-rules)
  2. fetch SigmaHQ (`upstream`) into ../../sigma, fast-forward master, push it to the fork (`origin`)
  3. convert SigmaHQ + our rules (content repo rules/) -> reports/converted.jsonl
  4. run test_hawk_rules.py and test_score_filters.py (stop on failure)
  5. plan against production: new rules, refreshes (logic or exclusions changed; hold list skipped),
     deprecated-in-Sigma scores still enabled -> reports/daily/<date>/*.txt and summary.md
  6. --execute: push new rules (they arrive DISABLED), push refreshes (enabled state, weights and
     LOUD titles are kept by sync_scores.py), disable deprecated scores; each verified against /scores

    python daily_sync.py              # update + plan, prints what would change
    python daily_sync.py --execute    # same, then pushes it

The weekly job (weekly_update.py) still does the slow part: backtests, firing stats, loud scores.
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

import requests
import urllib3

from backtest_explore import BASE, api_key
from score_filters import content_dir

HERE = Path(__file__).resolve().parent
SIGMA = (HERE / ".." / ".." / "sigma").resolve()
DIRS = "rules,rules-emerging-threats,rules-threat-hunting,rules-compliance,deprecated"
urllib3.disable_warnings()


def run(cmd, cwd=HERE, timeout=3600):
    print("$", " ".join(str(c) for c in cmd), flush=True)
    p = subprocess.run([str(c) for c in cmd], cwd=cwd, capture_output=True, text=True, timeout=timeout)
    if p.returncode != 0:
        raise SystemExit(f"FAILED ({p.returncode}): {' '.join(map(str, cmd))}\n{p.stdout[-3000:]}\n{p.stderr[-3000:]}")
    return p.stdout


def lines(path):
    return [l.strip().lower() for l in Path(path).read_text(encoding="utf-8").splitlines() if l.strip()] if Path(path).exists() else []


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--execute", action="store_true", help="push new/refreshed scores and disable deprecated ones")
    ap.add_argument("--no-fork-push", action="store_true", help="do not push the fast-forwarded SigmaHQ master to the fork")
    args = ap.parse_args()
    day = datetime.datetime.now(datetime.timezone.utc).date().isoformat()
    out = HERE / "reports" / "daily" / day
    out.mkdir(parents=True, exist_ok=True)
    md = [f"# Sigma -> HAWK daily sync, {day}", ""]

    # 1. our repos
    for repo in (HERE.parent, content_dir()):
        if run(["git", "status", "--porcelain", "--untracked-files=no"], cwd=repo).strip():
            raise SystemExit(f"{repo} has uncommitted changes - commit or stash them first")
        run(["git", "pull", "-q", "--ff-only"], cwd=repo)
        md.append(f"- {repo.name}: {run(['git', 'log', '-1', '--format=%h %s'], cwd=repo).strip()}")

    # 2. SigmaHQ
    before = run(["git", "rev-parse", "HEAD"], cwd=SIGMA).strip()
    run(["git", "fetch", "-q", "upstream"], cwd=SIGMA)
    run(["git", "checkout", "-q", "master"], cwd=SIGMA)
    run(["git", "merge", "-q", "--ff-only", "upstream/master"], cwd=SIGMA)
    after = run(["git", "rev-parse", "HEAD"], cwd=SIGMA).strip()
    if not args.no_fork_push and before != after:
        run(["git", "push", "-q", "origin", "master"], cwd=SIGMA)
    prs = run(["git", "log", "--format=- %ad %s", "--date=short", f"{before}..{after}"], cwd=SIGMA).strip()
    md += ["", "## SigmaHQ", f"{before[:9]} -> {after[:9]}", "", prs or "- no new upstream commits", ""]

    # 3. convert, 4. tests
    print(run([sys.executable, "convert_corpus.py", str(SIGMA), "--dirs", DIRS, "--extra-root", str(content_dir() / "rules")]).strip().splitlines()[-1])
    conv_path = HERE / "reports" / "converted.jsonl"
    conv = {}
    for l in conv_path.read_text(encoding="utf-8").splitlines():
        if l.strip():
            r = json.loads(l)
            conv[r["hawk_id"].lower()] = r
    errs = HERE / "reports" / "converted.jsonl.errors.json"
    nerr = len(json.loads(errs.read_text(encoding="utf-8"))) if errs.exists() else 0
    md += ["## Conversion", f"{len(conv)} rules, {nerr} conversion errors", ""]
    for t in ("test_hawk_rules.py", "test_score_filters.py"):
        res = run([sys.executable, t]).strip().splitlines()
        md.append(f"- {t}: {res[-1] if res else 'ok'}")
    md.append("")

    # 5. plan
    for f in glob.glob(str(HERE / "reports" / "refresh_group_*")):
        os.remove(f)
    run([sys.executable, "refresh_plan.py", "100000"])
    hold = set(lines(HERE / "reports" / "refresh_hold_all.txt"))
    diff = HERE / "reports" / "refresh_group_001_diff.csv"
    rows = list(csv.DictReader(diff.open(encoding="utf-8"))) if diff.exists() else []
    refresh = [r for r in rows if r["hawk_id"].lower() not in hold]
    live = {str(x.get("hawk_id")).lower(): x for x in requests.get(BASE + "scores?recursive=true&format=json",
            headers={"Authorization": "Bearer " + api_key()}, timeout=900, verify=False).json()["results"] if x.get("hawk_id")}
    new = [c for h, c in conv.items() if h not in live and not c["_source"].startswith("deprecated")]
    # a score with the same title under another id (custom copy, older id) would become a duplicate
    titles = {str(x.get("filter_name")).strip().lower(): x for x in live.values()}
    dup_title = [c for c in new if c["filter_name"].strip().lower() in titles]
    new = [c for c in new if c not in dup_title]
    dep = [h for h, c in conv.items() if c["_source"].startswith("deprecated") and live.get(h, {}).get("enabled")]
    (out / "new.txt").write_text("".join(c["hawk_id"].lower() + "\n" for c in new), encoding="utf-8")
    (out / "refresh.txt").write_text("".join(r["hawk_id"].lower() + "\n" for r in refresh), encoding="utf-8")
    (out / "deprecated_enabled.txt").write_text("".join(h + "\n" for h in dep), encoding="utf-8")
    md += [f"## New rules: {len(new)} (imported disabled)", ""]
    md += [f"- [{c['_level']}/{c['_status']}] w={c['correlation_action']} {c['filter_name']}  ({c['_source']})" for c in new]
    if dup_title:
        md += ["", f"### Not pushed: {len(dup_title)} new rule(s) whose title already exists in production under another id",
               "Compare them and delete or retitle one before pushing.", ""]
        md += [f"- {c['filter_name']} ({c['hawk_id']}) vs live {titles[c['filter_name'].strip().lower()]['score_id']}" for c in dup_title]
    md += ["", f"## Refreshes: {len(refresh)} ({len(rows) - len(refresh)} more differ but are on the hold list)", ""]
    md += [f"- {r['score_id']} {'ENABLED ' if r['enabled'] == 'True' else 'disabled'} {r['kind']}: {r['title']}" for r in refresh]
    md += ["", f"## Deprecated in Sigma but still enabled: {len(dep)}", ""]
    md += [f"- {live[h]['score_id']} {live[h]['filter_name']}" for h in dep]
    md.append("")

    # 6. push
    if args.execute:
        md += ["## Pushed", ""]
        if new:
            r = run([sys.executable, "sync_scores.py", "--select", out / "new.txt", "--batch-size", str(max(100, len(new))), "--execute", "--verify"], timeout=7200)
            md.append("- new: " + r.strip().splitlines()[-2])
        if refresh:
            r = run([sys.executable, "sync_scores.py", "--select", out / "refresh.txt", "--batch-size", str(max(100, len(refresh))), "--execute", "--verify"], timeout=7200)
            md.append("- refresh: " + r.strip().splitlines()[-2])
        if dep:
            r = run([sys.executable, "disable_scores.py", "--hawk-ids-file", out / "deprecated_enabled.txt", "--execute"], timeout=7200)
            md.append("- deprecated disabled: " + r.strip().splitlines()[-1])
        if not (new or refresh or dep):
            md.append("- nothing to push: production matches the repos")
        md.append("")
    else:
        md += ["Dry run. To push all of the above: `python daily_sync.py --execute`", ""]

    (out / "summary.md").write_text("\n".join(md), encoding="utf-8")
    print("\n".join(md))
    print(f"\nreport: {out / 'summary.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
