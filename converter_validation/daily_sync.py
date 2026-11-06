"""Daily Sigma -> HAWK sync: bring every source up to date and push what changed.

Steps (all read-only unless --execute):
  1. git pull --ff-only this repo and the private content repo (siem/hawk-sigma-rules)
  2. fetch SigmaHQ (`upstream`) into ../../sigma, fast-forward master, push it to the fork (`origin`)
  3. convert SigmaHQ + our rules (content repo rules/) -> reports/converted.jsonl
  4. run the tests: a rule failing test_hawk_rules.py is held back alone (not pushed, exit 2 so the mail
     says FAILED); any other test failure stops the run
  5. plan against production: new rules, refreshes (logic or exclusions changed; hold list skipped),
     deprecated-in-Sigma scores still enabled -> reports/daily/<date>/*.txt and summary.md
  6. --execute: push new rules (they arrive DISABLED), push refreshes (enabled state, weights and
     LOUD titles are kept by sync_scores.py), disable deprecated scores; each verified against /scores.
     Refreshes of ENABLED scores are backtested first (72h); any not clearly under GATE_PER_HOUR is
     held back in refresh_held.txt for a person instead of being pushed.
  7. list what is imported but disabled (not firing), with a 72h backtest, so enabling is a visible decision

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
GATE_PER_HOUR = 10  # same line the weekly backtest uses for "stay disabled or tune first"
DISABLED_LIST_DAYS = 14
urllib3.disable_warnings()


def run(cmd, cwd=HERE, timeout=3600, check=True):
    print("$", " ".join(str(c) for c in cmd), flush=True)
    p = subprocess.run([str(c) for c in cmd], cwd=cwd, capture_output=True, text=True, timeout=timeout)
    if not check:
        return p.returncode, p.stdout
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
    errs = HERE / "reports" / "converted.errors.json"
    nerr = len(json.loads(errs.read_text(encoding="utf-8"))) if errs.exists() else 0
    md += ["## Conversion", f"{len(conv)} rules, {nerr} conversion errors", ""]
    # A failing rule test holds back that rule only (2026-11-05: one rule blocked 37 new ones for a day).
    # A failure that names no rule is a broken test or input, and stops the run as before.
    failed_file = HERE / "reports" / "hawk_rules_failed.txt"
    failed_file.unlink(missing_ok=True)
    rc, res = run([sys.executable, "test_hawk_rules.py"], check=False)
    failed = set(lines(failed_file))
    if rc != 0 and not failed:
        raise SystemExit(f"FAILED ({rc}): test_hawk_rules.py named no failing rule\n{res[-3000:]}")
    md.append(f"- test_hawk_rules.py: {len(failed)} failing rule(s) held back" if failed else "- test_hawk_rules.py: all pass")
    for t in ("test_score_filters.py", "test_backtest_explore.py", "test_daily_hold.py"):
        res = run([sys.executable, t]).strip().splitlines()
        md.append(f"- {t}: {res[-1] if res else 'ok'}")
    md.append("")
    if failed:
        md += [f"## Held back: failed rule tests: {len(failed)} (fix the rule; see daily_last.log)", ""]
        md += [f"- {conv.get(h, {}).get('filter_name', h)}  ({conv.get(h, {}).get('_source', '?')})" for h in sorted(failed)]
        md.append("")

    # 5. plan
    for f in glob.glob(str(HERE / "reports" / "refresh_group_*")):
        os.remove(f)
    run([sys.executable, "refresh_plan.py", "100000"])
    hold = set(lines(HERE / "reports" / "refresh_hold_all.txt"))
    diff = HERE / "reports" / "refresh_group_001_diff.csv"
    rows = list(csv.DictReader(diff.open(encoding="utf-8"))) if diff.exists() else []
    refresh = [r for r in rows if r["hawk_id"].lower() not in hold and r["hawk_id"].lower() not in failed]
    live = {str(x.get("hawk_id")).lower(): x for x in requests.get(BASE + "scores?recursive=true&format=json",
            headers={"Authorization": "Bearer " + api_key()}, timeout=900, verify=False).json()["results"] if x.get("hawk_id")}
    new = [c for h, c in conv.items() if h not in live and h not in failed and not c["_source"].startswith("deprecated")]
    dep = [h for h, c in conv.items() if c["_source"].startswith("deprecated") and live.get(h, {}).get("enabled")]
    (out / "new.txt").write_text("".join(c["hawk_id"].lower() + "\n" for c in new), encoding="utf-8")
    (out / "refresh.txt").write_text("".join(r["hawk_id"].lower() + "\n" for r in refresh), encoding="utf-8")
    (out / "deprecated_enabled.txt").write_text("".join(h + "\n" for h in dep), encoding="utf-8")
    md += [f"## New rules: {len(new)} (imported disabled)", ""]
    md += [f"- [{c['_level']}/{c['_status']}] w={c['correlation_action']} {c['filter_name']}  ({c['_source']})" for c in new]
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
            # Unattended pushes change live detections, so an enabled score whose new logic the backtest
            # cannot clear (>= GATE_PER_HOUR, unbounded, error) is held back for a person, never pushed.
            run([sys.executable, "backtest_explore.py", "--select", out / "refresh.txt", "--hours", "72",
                 "--out", out / "backtest.json"], timeout=7200)
            bt = {e["hawk_id"].lower(): e for e in json.loads((out / "backtest.json").read_text(encoding="utf-8"))["results"]}
            held = [r for r in refresh if r["enabled"] == "True" and (bt.get(r["hawk_id"].lower(), {}).get("status") != "ok"
                    or bt[r["hawk_id"].lower()].get("hits_per_hour", 0) >= GATE_PER_HOUR)]
            held_ids = {r["hawk_id"].lower() for r in held}
            refresh = [r for r in refresh if r["hawk_id"].lower() not in held_ids]
            (out / "refresh.txt").write_text("".join(r["hawk_id"].lower() + "\n" for r in refresh), encoding="utf-8")
            (out / "refresh_held.txt").write_text("".join(h + "\n" for h in held_ids), encoding="utf-8")
            md += [f"- held back (enabled, backtest not clear, 72h): {len(held)}"]
            md += [f"  - {r['score_id']} {r['title']}: {bt.get(r['hawk_id'].lower(), {}).get('status', 'missing')} "
                   f"{bt.get(r['hawk_id'].lower(), {}).get('hits_per_hour', '')}/h" for r in held]
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

    md += disabled_section(conv, live, new, out)
    (out / "summary.md").write_text("\n".join(md), encoding="utf-8")
    print("\n".join(md))
    print(f"\nreport: {out / 'summary.md'}")
    # non-zero so the mail says FAILED: a held-back rule needs a person, even though the rest went out
    return 2 if failed else 0


def disabled_section(conv, live, new, out):
    """Imported is not firing: new rules arrive disabled and wait for a person. List them with a 72h
    backtest so the decision is in the mail (2026-11-05: 41 sat disabled and nobody saw them).
    Everything disabled is counted; our own rules and the last DISABLED_LIST_DAYS of imports are listed."""
    off = {h: x for h, x in live.items() if h in conv and not x.get("enabled") and not conv[h]["_source"].startswith("deprecated")}
    off.update({c["hawk_id"].lower(): {"score_id": "new", "filter_name": c["filter_name"], "date_added": "9999"} for c in new})
    cutoff = (datetime.date.today() - datetime.timedelta(days=DISABLED_LIST_DAYS)).isoformat()
    listed = sorted((h for h, x in off.items() if conv[h]["_source"].startswith("hawk/") or str(x.get("date_added") or "") >= cutoff),
                    key=lambda h: off[h]["filter_name"])
    by_src = {}
    for h in off:
        by_src[conv[h]["_source"].split("/")[0]] = by_src.get(conv[h]["_source"].split("/")[0], 0) + 1
    md = [f"## Imported but disabled (not firing): {len(off)}", "",
          "By source: " + ", ".join(f"{k} {v}" for k, v in sorted(by_src.items())), "",
          f"Our rules and imports from the last {DISABLED_LIST_DAYS} days ({len(listed)}); "
          "72h backtest is an upper bound, and 0 only means quiet if the rule's data reaches Explore:", ""]
    if listed:
        (out / "disabled_listed.txt").write_text("".join(h + "\n" for h in listed), encoding="utf-8")
        rc, _ = run([sys.executable, "backtest_explore.py", "--select", out / "disabled_listed.txt", "--hours", "72",
                     "--out", out / "disabled_backtest.json"], timeout=7200, check=False)
        p = out / "disabled_backtest.json"
        bt = {e["hawk_id"].lower(): e for e in json.loads(p.read_text(encoding="utf-8"))["results"]} if rc == 0 and p.exists() else {}
        for h in listed:
            e = bt.get(h, {})
            rate = f"{e['hits_per_hour']}/h" if e.get("status") == "ok" else e.get("status", "backtest failed")
            md.append(f"- {off[h]['score_id']} {off[h]['filter_name']}: {rate}")
    md.append("")
    return md


if __name__ == "__main__":
    raise SystemExit(main())
