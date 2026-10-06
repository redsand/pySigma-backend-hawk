"""What is actually triggering a noisy score: top values per column over the window.

For each score title, aggregates explore events whose result_name contains it, by host and by the
columns its own logic uses (plus image/parent/command/user), so a score whose hits come from one
agent, one parent process or one user can be tuned with a filter instead of being cut.

    python loud_drilldown.py --score-ids 1307,2214 [--hours 72] [--top 6]
Writes reports/loud_drilldown.json.
"""
import argparse
import json
import re
from pathlib import Path

import requests
import urllib3

from backtest_explore import BASE, IDX, api_key, load_indexed

HERE = Path(__file__).resolve().parent
urllib3.disable_warnings()
ALWAYS = ["resource_name", "group_name", "product_name", "image", "parent_image", "command", "correlation_username",
          "http_user_agent", "http_host", "object", "target_image"]


def leaves(rules):
    rules = json.loads(rules) if isinstance(rules, str) else rules
    out = []

    def w(n):
        if isinstance(n, list):
            for c in n:
                w(c)
            return
        if n.get("class") == "column":
            out.append(n.get("key"))
        for c in n.get("children", []) or []:
            w(c)
    w(rules)
    return out


def q_title(title):
    # result_name is keyword: wildcard on the escaped title
    return "result_name:*" + re.sub(r'([+\-=&|><!(){}\[\]^"~*?:\\/ ])', r"\\\1", title) + "*"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--score-ids", required=True)
    ap.add_argument("--hours", type=int, default=72)
    ap.add_argument("--top", type=int, default=6)
    args = ap.parse_args()
    s = requests.Session()
    s.headers["Authorization"] = "Bearer " + api_key()
    live = {r["score_id"]: r for r in s.get(BASE + "scores?recursive=true&format=json", timeout=900, verify=False).json()["results"]}
    indexed = load_indexed()
    report = {}
    for sid in [int(x) for x in args.score_ids.split(",")]:
        row = live[sid]
        title = str(row["filter_name"]).replace(" (LOUD)", "")
        cols = [c for c in dict.fromkeys(ALWAYS + leaves(row["rules"])) if c in indexed or c in ALWAYS]
        q = q_title(title)
        entry = {"title": title, "weight": row["correlation_action"], "by": {}}
        print(f"\n# {sid} w={row['correlation_action']} {title}")
        for col in cols:
            j = s.post(BASE + "explore/aggregate", data={"idx": IDX, "q": q, "from": f"now-{args.hours}h", "to": "now",
                                                         "group_by": col, "metric": "count", "size": str(args.top)},
                       timeout=600, verify=False).json()
            rows = (j.get("results") or {}).get("rows")
            if not rows:
                continue
            total = None
            vals = [(str(r.get(col))[:110], int(r.get("count") or 0)) for r in rows]
            entry["by"][col] = vals
            print(f"  {col}: " + " | ".join(f"{v} ({n})" for v, n in vals))
        report[sid] = entry
    (HERE / "reports" / "loud_drilldown.json").write_text(json.dumps(report, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
