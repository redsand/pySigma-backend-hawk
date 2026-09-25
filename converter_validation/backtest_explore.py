"""Fast pre-sync noise estimate through /explore/search (same documents as the stream).

Translates a converted score's boolean tree into a Lucene query_string and asks Elastic for the
hit count over a window, per product_name. Regex leaves become Lucene regexp on the `.keyword`
sub-field (whole-value, case-sensitive), so counts for regex-heavy rules are an approximation;
streamd (backtest.py) remains the engine-exact check. Rules with function nodes are reported as
unsupported.

Usage:
    python backtest_explore.py --select reports/batch_001_draft.txt [--hours 24] [--workers 4]
"""
import argparse
import concurrent.futures as cf
import datetime
import json
import re
import sys
import time
from pathlib import Path

import requests
import urllib3

HERE = Path(__file__).resolve().parent
BASE = "https://portal.hawk.io:8080/API/1.1/"
IDX = "hawkio-da9d0285-4cda-11e9-835b-0cc47a0f9a88"
urllib3.disable_warnings()


class Unsupported(Exception):
    pass


def api_key() -> str:
    for line in (HERE / "hawk.env").read_text(encoding="utf-8").splitlines():
        if line.startswith("HAWK_API_KEY="):
            return line.split("=", 1)[1].strip()
    raise SystemExit("HAWK_API_KEY missing")


_LUCENE_SPECIAL = re.compile(r'([+\-!(){}\[\]^"~*?:\\/ ]|&&|\|\|)')


def q_term(value: str) -> str:
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


def pcre_to_lucene(rx: str) -> str:
    """Best-effort PCRE -> Lucene regexp (whole-value semantics on keyword fields)."""
    r = rx
    anchored_start = r.startswith("^")
    anchored_end = r.endswith("$") and not r.endswith("\\$")
    if anchored_start:
        r = r[1:]
    if anchored_end:
        r = r[:-1]
    if not anchored_start and not r.startswith(".*"):
        r = ".*" + r
    if not anchored_end and not r.endswith(".*"):
        r = r + ".*"
    # Lucene regexp has no \s / \d classes and no lookaround. Walk the pattern so an escaped
    # backslash followed by a letter (a literal "\system32") is not mistaken for a class.
    i = 0
    while i < len(r):
        if r[i] == "\\" and i + 1 < len(r):
            if r[i + 1] in "sdwSDWbB":
                raise Unsupported("regex class not expressible in Lucene")
            i += 2
            continue
        if r.startswith("(?", i):
            raise Unsupported("lookaround/group flags not expressible in Lucene")
        i += 1
    r = r.replace("/", "\\/")
    return "/" + r + "/"


def leaf_clause(leaf: dict) -> str:
    if leaf.get("class") == "function":
        raise Unsupported(f"function {leaf.get('key')}")
    key = leaf["key"]
    if not re.fullmatch(r"[A-Za-z0-9_.]+", key or ""):
        raise Unsupported(f"column {key!r}")
    args = leaf.get("args") or {}
    op = (args.get("comparison") or {}).get("value", "=")
    for t in ("str", "int", "float", "bool", "uns", "double", "ip"):
        if t in args:
            a = args[t]
            val = a.get("value")
            rx = str(a.get("regex", "")).lower() in ("true", "1")
            if rx:
                if op not in ("=", "!="):
                    raise Unsupported("regex with ordering op")
                clause = f"{key}.keyword:{pcre_to_lucene(str(val))}"
            elif t in ("int", "float", "uns", "double"):
                if op == "=":
                    clause = f"{key}:{val}"
                elif op == "!=":
                    clause = f"NOT {key}:{val}"
                else:
                    rng = {">": f">{val}", ">=": f">={val}", "<": f"<{val}", "<=": f"<={val}"}[op]
                    return f"{key}:{rng}"
            elif t == "bool":
                clause = f"{key}:{'true' if str(val).lower() in ('true', 'success', '1') else 'false'}"
            else:
                sval = str(val)
                if "/" in sval and re.fullmatch(r"[0-9a-fA-F:.]+/\d+", sval):
                    clause = f"{key}:{q_term(sval)}"  # ES understands CIDR on ip fields
                else:
                    clause = f"{key}.keyword:{q_term(sval)}"
            if op == "!=":
                return f"(NOT {clause})"
            return clause
    raise Unsupported(f"leaf without value: {key}")


def node_clause(node) -> str:
    if isinstance(node, list):
        parts = [node_clause(n) for n in node]
        return "(" + " AND ".join(parts) + ")" if len(parts) > 1 else parts[0]
    if node.get("class") in ("column", "function"):
        return leaf_clause(node)
    op = str(node.get("id", "and")).upper()
    if op not in ("AND", "OR"):
        raise Unsupported(f"group {op}")
    parts = [node_clause(c) for c in node.get("children", []) or []]
    if not parts:
        raise Unsupported("empty group")
    return "(" + f" {op} ".join(parts) + ")" if len(parts) > 1 else parts[0]


def run_one(session: requests.Session, rec: dict, hours: float) -> dict:
    entry = {"hawk_id": rec["hawk_id"], "title": rec.get("filter_name"), "level": rec.get("_level"), "score": rec.get("correlation_action")}
    try:
        q = node_clause(rec["rules"])
    except Unsupported as e:
        entry.update({"status": "unsupported", "reason": str(e)})
        return entry
    entry["q"] = q
    t0 = time.time()
    try:
        r = session.post(BASE + "explore/aggregate", data={"idx": IDX, "q": q, "from": f"now-{int(hours)}h", "to": "now",
                                                          "group_by": "product_name.keyword", "metric": "count", "size": "20"}, timeout=600, verify=False)
        j = r.json()
        rows = (j.get("results") or {}).get("rows")
        if rows is None:
            # product_name may be keyword-typed already
            r = session.post(BASE + "explore/aggregate", data={"idx": IDX, "q": q, "from": f"now-{int(hours)}h", "to": "now",
                                                              "group_by": "product_name", "metric": "count", "size": "20"}, timeout=600, verify=False)
            j = r.json()
            rows = (j.get("results") or {}).get("rows")
        if rows is None:
            entry.update({"status": "error", "error": str(j.get("details"))[:200], "elapsed": round(time.time() - t0, 1)})
            return entry
        by = [{"product": x.get("key", x.get("product_name")), "hits": int(x.get("count", x.get("doc_count", 0)) or 0)} for x in rows]
        total = sum(x["hits"] for x in by)
        entry.update({"status": "ok", "hits": total, "hits_per_hour": round(total / hours, 2), "by_product": by, "elapsed": round(time.time() - t0, 1)})
    except Exception as e:  # noqa: BLE001
        entry.update({"status": "error", "error": f"{type(e).__name__}: {str(e)[:160]}", "elapsed": round(time.time() - t0, 1)})
    return entry


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--converted", default=str(HERE / "reports" / "converted.jsonl"))
    ap.add_argument("--select")
    ap.add_argument("--ids")
    ap.add_argument("--hours", type=float, default=24)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--out")
    args = ap.parse_args()
    conv = {}
    for line in Path(args.converted).read_text(encoding="utf-8").splitlines():
        if line.strip():
            r = json.loads(line)
            conv[str(r["hawk_id"]).lower()] = r
    ids: list = []
    if args.select:
        ids += [l.split("#", 1)[0].strip().lower() for l in Path(args.select).read_text(encoding="utf-8").splitlines() if l.split("#", 1)[0].strip()]
    if args.ids:
        ids += [x.strip().lower() for x in args.ids.split(",") if x.strip()]
    ids = [i for i in dict.fromkeys(ids) if i in conv]
    stamp = datetime.datetime.now(datetime.UTC).strftime("%Y%m%dT%H%M%SZ")
    out_path = Path(args.out) if args.out else HERE / "reports" / f"backtest_explore_{stamp}.json"
    session = requests.Session()
    session.headers["Authorization"] = "Bearer " + api_key()
    results = []
    with cf.ThreadPoolExecutor(max_workers=args.workers) as ex:
        for entry in ex.map(lambda h: run_one(session, conv[h], args.hours), ids):
            results.append(entry)
            tag = entry.get("status")
            print(f"{tag:11s} {entry['hawk_id']} {str(entry.get('title'))[:55]!r} hits={entry.get('hits', '-')} ({entry.get('hits_per_hour', '-')}/h) {entry.get('reason') or entry.get('error') or ''}", flush=True)
            out_path.write_text(json.dumps({"hours": args.hours, "results": results}, indent=1), encoding="utf-8")
    noisy = [e for e in results if e.get("status") == "ok" and e.get("hits_per_hour", 0) >= 10]
    print(f"\n{len(results)} rules; ok={sum(e.get('status')=='ok' for e in results)} unsupported={sum(e.get('status')=='unsupported' for e in results)} error={sum(e.get('status')=='error' for e in results)}; >=10 hits/h: {len(noisy)}")
    print("wrote", out_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
