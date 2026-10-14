r"""Portal half of the Sysmon COM / TypeLib hijack end-to-end test.

hawkagentd's tests/e2e/sysmon_com_hijack_e2e.ps1 makes inert registry writes and file drops on an agent host
(unique per-run marker GUID and tag) and checks Sysmon logged them. This script checks the rest of the chain
for the same run: the agent forwarded each event, the engine parsed it into the columns the Sigma rules use
(object / details / filename), and the scores the case table names fired on it.

    python e2e_sysmon_com_check.py --marker "{4841574B-E2E0-...}" --tag hawke2e... --host <resource_name> \
        --since 2026-10-14T00:00:00Z [--cases ..\..\hawkagentd\tests\fixtures\registry\sysmon_com_hijack_cases.json]

Exit 0 when every case behaves as the case table says; 1 otherwise; 2 when no event from the run arrived yet.
Scores fire only once enabled and loaded (engine reload every 30 min), so run it a few minutes after the e2e.
"""
import argparse
import json
import sys
from pathlib import Path

import requests
import urllib3

from backtest_explore import BASE, IDX, api_key

HERE = Path(__file__).resolve().parent
DEFAULT_CASES = HERE.parents[1] / "hawkagentd" / "tests" / "fixtures" / "registry" / "sysmon_com_hijack_cases.json"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--marker", required=True)
    ap.add_argument("--tag", required=True)
    ap.add_argument("--host", required=True, help="the agent's resource_name (lowercase host name)")
    ap.add_argument("--since", required=True, help="UTC start of the e2e run, e.g. 2026-10-14T00:00:00Z")
    ap.add_argument("--cases", default=str(DEFAULT_CASES))
    ap.add_argument("--out", default="")
    args = ap.parse_args()

    cases = json.loads(Path(args.cases).read_text(encoding="utf-8"))
    urllib3.disable_warnings()
    s = requests.Session()
    s.headers["Authorization"] = "Bearer " + api_key()

    q = f'resource_name:"{args.host.lower()}" AND product_name:"Sysmon" AND (vendor_id:"11" OR vendor_id:"12" OR vendor_id:"13" OR vendor_id:"14")'
    j = s.post(BASE + "explore/search", data={"idx": IDX, "q": q, "from": args.since, "to": "now", "size": "5000"}, timeout=300, verify=False).json()
    rows = (j.get("results") or {}).get("rows") or []
    marker, tag = args.marker.lower(), args.tag.lower()
    mine = [r for r in rows if marker in str(r.get("object", "")).lower() or tag in str(r.get("object", "")).lower()
            or tag in str(r.get("filename", "")).lower()]
    print(f"explore: {len(rows)} Sysmon file/registry events from {args.host} since {args.since}; {len(mine)} carry this run's marker")
    if not mine:
        print("no events from this run yet (agent forwarding delay, or the host is not a HAWK agent / Sysmon was not logging)")
        return 2

    live = s.get(BASE + "scores?recursive=true&format=json", timeout=600, verify=False).json()["results"]
    titles = {int(r["score_id"]): (r.get("filter_name") or "", bool(r.get("enabled"))) for r in live if str(r.get("score_id", "")).isdigit()}

    def fill(t: str) -> str:
        return t.replace("{MARKER}", args.marker).replace("{TAG}", args.tag)

    results, failed = [], 0
    for c in cases["registry"]:
        key, value = fill(c["key"]), fill(c["value"])
        tail = key[len("Software\\Classes\\"):] if key.lower().startswith("software\\classes\\") else key
        if value:
            tail += "\\" + value
        hits = [r for r in mine if tail.lower() in str(r.get("object", "")).lower()]
        results.append((c, hits))
    for c in cases["files"]:
        # match on the folder tail too: several cases share the file name (<tag>.jar in different folders)
        tail = fill(c["path"]).replace("{ProgramData}", "\\ProgramData").replace("{AppData}", "\\AppData\\Roaming").replace("{UserProfile}", "").lower()
        hits = [r for r in mine if str(r.get("vendor_id")) == "11" and str(r.get("filename", "")).lower().endswith(tail)]
        results.append((c, hits))

    report = []
    for c, hits in results:
        actual = "logged" if hits else "not logged"
        problems = []
        if actual != c["expect"]:
            problems.append(f"expected {c['expect']}, portal has {actual}")
        if hits and c.get("rule") and not any(c["rule"] in str(h.get("rule_name", "")) for h in hits):
            problems.append(f"rule_name lacks {c['rule']}: {sorted({str(h.get('rule_name')) for h in hits})}")
        if hits and "key" in c and not any(h.get("object") for h in hits):
            problems.append("object column empty - engine did not parse TargetObject")
        for sid in c.get("hawk_scores", []):
            title, enabled = titles.get(sid, ("", False))
            if not enabled:
                problems.append(f"score {sid} not enabled")
            elif not any(title and title in str(h.get("result_name", "")) for h in hits):
                problems.append(f"score {sid} '{title}' did not fire (result_name: {sorted({str(h.get('result_name'))[:160] for h in hits})})")
        failed += bool(problems)
        weights = sorted({str(h.get("weight")) for h in hits})
        print(f"  {'ok  ' if not problems else 'FAIL'} {c['id']:<34} {actual:<10} weight={','.join(weights) or '-'} {'; '.join(problems)}")
        report.append({"id": c["id"], "expect": c["expect"], "actual": actual, "ok": not problems, "problems": problems,
                       "events": [{k: h.get(k) for k in ("@timestamp", "vendor_id", "object", "details", "filename", "rule_name", "result_name", "weight")} for h in hits[:5]]})

    if args.out:
        Path(args.out).write_text(json.dumps({"marker": args.marker, "host": args.host, "failures": failed, "cases": report}, indent=1), encoding="utf-8")
    print(f"{'PASS' if not failed else 'FAIL'}: {len(report) - failed}/{len(report)} cases as expected in the portal")
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
