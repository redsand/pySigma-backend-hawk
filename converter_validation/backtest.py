"""Pre-sync noise check: replay a converted score's logic over the live event stream.

Translates the score's boolean tree into a streamd `where` expression (streamd builds its filter
with the same hawk-correlation.c expression tree the engine uses, so `=`, `!=` and `regex` mean
the same thing in both places) and counts matching events over a window, grouped by product and
group. A rule that lights up thousands of events a day is flagged before it is ever enabled.

Function nodes (counters, empty(), statistics) cannot be replayed; such rules are reported as
`unsupported` and need a manual look.

Usage:
    python backtest.py --select reports/batch_001.txt [--hours 24] [--out reports/backtest_<stamp>.json]
"""
import argparse
import datetime
import json
import re
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from streamd_client import query, ts  # noqa: E402


class Unsupported(Exception):
    pass


def esc(v: str) -> str:
    return str(v).replace("\\", "\\\\").replace("'", "\\'")


def leaf_clause(leaf: dict) -> str:
    if leaf.get("class") == "function":
        raise Unsupported(f"function {leaf.get('key')}")
    key = leaf["key"]
    if not re.fullmatch(r"[A-Za-z0-9_.]+", key or ""):
        raise Unsupported(f"column name {key!r}")
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
                return f"{key} {'regex' if op == '=' else '!regex'} '{esc(val)}'"
            if t in ("int", "float", "uns", "double"):
                return f"{key} {op} {val}"
            if t == "bool":
                return f"{key} {op} {'true' if str(val).lower() in ('true', 'success', '1') else 'false'}"
            return f"{key} {op} '{esc(val)}'"
    raise Unsupported(f"leaf without value: {key}")


def node_clause(node) -> str:
    if isinstance(node, list):
        parts = [node_clause(n) for n in node]
        return "(" + " and ".join(parts) + ")" if len(parts) > 1 else parts[0]
    if node.get("class") in ("column", "function"):
        return leaf_clause(node)
    op = str(node.get("id", "and")).lower()
    if op not in ("and", "or"):
        raise Unsupported(f"group op {op}")
    parts = [node_clause(c) for c in node.get("children", []) or []]
    if not parts:
        raise Unsupported("empty group")
    return "(" + f" {op} ".join(parts) + ")" if len(parts) > 1 else parts[0]


def score_to_where(rec: dict) -> str:
    return node_clause(rec["rules"])


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--converted", default=str(HERE / "reports" / "converted.jsonl"))
    ap.add_argument("--select")
    ap.add_argument("--ids")
    ap.add_argument("--hours", type=float, default=24)
    ap.add_argument("--lag-minutes", type=int, default=10)
    ap.add_argument("--timeout", type=int, default=300)
    ap.add_argument("--out")
    args = ap.parse_args()

    conv = {}
    for line in Path(args.converted).read_text(encoding="utf-8").splitlines():
        if line.strip():
            r = json.loads(line)
            conv[str(r["hawk_id"]).lower()] = r
    ids: list[str] = []
    if args.select:
        ids += [l.strip().lower() for l in Path(args.select).read_text(encoding="utf-8").splitlines() if l.strip() and not l.startswith("#")]
    if args.ids:
        ids += [x.strip().lower() for x in args.ids.split(",") if x.strip()]
    ids = [i for i in dict.fromkeys(ids) if i in conv]

    now = datetime.datetime.now(datetime.UTC)
    begin = ts(now - datetime.timedelta(hours=args.hours))
    end = ts(now - datetime.timedelta(minutes=args.lag_minutes))
    stamp = now.strftime("%Y%m%dT%H%M%SZ")
    out_path = Path(args.out) if args.out else HERE / "reports" / f"backtest_{stamp}.json"
    results = []
    for hid in ids:
        rec = conv[hid]
        entry = {"hawk_id": hid, "title": rec.get("filter_name"), "level": rec.get("_level"), "score": rec.get("correlation_action")}
        try:
            where = score_to_where(rec)
        except Unsupported as e:
            entry.update({"status": "unsupported", "reason": str(e)})
            results.append(entry)
            print(f"SKIP {hid} {str(rec.get('filter_name'))[:60]!r}: {e}")
            continue
        entry["where"] = where
        t0 = time.time()
        r = query(["group_name", "product_name", "count product_name"], where=[where], group_by="group_name,product_name",
                  order_by="product_name_count DESC", limit=200, begin=begin, end=end, timeout=args.timeout)
        rows = r["rows"]
        # streamd streams partial group rows; merge by key
        merged: dict = {}
        for row in rows:
            k = (row.get("group_name"), row.get("product_name"))
            merged[k] = merged.get(k, 0) + int(row.get("product_name_count") or 0)
        total = sum(merged.values())
        entry.update({
            "status": "error" if r["error"] else "ok",
            "error": r["error"],
            "hits": total,
            "hits_per_hour": round(total / args.hours, 2),
            "by_group_product": sorted(({"group": k[0], "product": k[1], "hits": v} for k, v in merged.items()), key=lambda x: -x["hits"])[:20],
            "elapsed": round(time.time() - t0, 1),
        })
        results.append(entry)
        print(f"{'ERR ' if r['error'] else 'OK  '} {hid} {str(rec.get('filter_name'))[:55]!r} hits={total} ({entry['hits_per_hour']}/h) {entry['elapsed']}s {r['error'] or ''}")
        out_path.write_text(json.dumps({"window": [begin, end], "results": results}, indent=1), encoding="utf-8")
    print("wrote", out_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
