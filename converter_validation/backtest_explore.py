"""Fast pre-sync noise estimate through /explore/aggregate (same documents as the stream).

The explore index stores every column but only *indexes* a subset for search (probe with
probe_indexed_fields.py -> live/explore_indexed_fields.json). Indexed text columns are analyzed
(tokenized, lower-cased), with no usable keyword sub-field. So the translation is deliberately an
UPPER BOUND on what the engine would match:

  * exact values   -> phrase query on the analyzed field (case-insensitive, token order kept)
  * regex values   -> AND of phrase queries for the literal fragments of the pattern; a pattern
                      with alternation/classes contributes nothing (dropped)
  * != / NOT       -> NOT (...) when expressible, else dropped
  * non-indexed column, function node -> dropped
  * OR with a dropped branch -> whole OR dropped

Dropping a constraint can only add hits, so a rule that scores 0 here is quiet for sure, and a
rule that scores high is a candidate for the engine-exact streamd check (backtest.py).

Usage:
    python backtest_explore.py --select reports/batch_001_draft.txt [--hours 24] [--workers 4]
"""
import argparse
import concurrent.futures as cf
import datetime
import json
import re
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


_INDEXED: set = set()
_INDEXED_LOADED = False


def load_indexed() -> set:
    """Columns that are searchable with data (from probe_indexed_fields.py). Empty set = unknown."""
    global _INDEXED, _INDEXED_LOADED
    if _INDEXED_LOADED:
        return _INDEXED
    p = HERE / "live" / "explore_indexed_fields.json"
    if p.exists():
        data = json.loads(p.read_text(encoding="utf-8"))
        _INDEXED = {c for c, n in data.items() if isinstance(n, int) and n > 0}
    _INDEXED_LOADED = True
    return _INDEXED


def is_indexed(col: str) -> bool:
    idx = load_indexed()
    return (col in idx) if idx else True


def q_phrase(field: str, value: str) -> str:
    v = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'{field}:"{v}"'


def regex_fragments(rx: str):
    """Literal fragments of a PCRE pattern, or None when the pattern has alternation/classes."""
    if "|" in rx or "[" in rx or "(?" in rx:
        return None
    r = rx
    if r.startswith("^"):
        r = r[1:]
    if r.endswith("$") and not r.endswith("\\$"):
        r = r[:-1]
    out = []
    buf = []
    i = 0
    while i < len(r):
        ch = r[i]
        if ch == "\\" and i + 1 < len(r):
            nxt = r[i + 1]
            if nxt in "sdwSDWbB":
                out.append("".join(buf))
                buf = []
            else:
                buf.append(nxt)
            i += 2
            continue
        if ch in ".*+?(){}":
            out.append("".join(buf))
            buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1
    out.append("".join(buf))
    # keep fragments of 2+ chars, and single non-ASCII chars (obfuscation rules key on them)
    frags = [f.strip() for f in out if len(f.strip()) >= 2 or (f.strip() and ord(f.strip()) > 127)]
    return frags


def leaf_clause(leaf: dict):
    """Return a Lucene clause, or None when the leaf must be dropped (upper bound)."""
    if leaf.get("class") == "function":
        return None
    key = leaf["key"]
    if not re.fullmatch(r"[A-Za-z0-9_.]+", key or ""):
        return None
    # A column that is stored but not indexed can still be bounded through `payload`, which
    # holds the raw event text (Key=Value pairs / raw JSON): the value must appear somewhere
    # in it for the engine leaf to match, so a payload phrase is a valid upper bound.
    via_payload = not is_indexed(key)
    if via_payload and not is_indexed("payload"):
        return None
    field = "payload" if via_payload else key
    args = leaf.get("args") or {}
    op = (args.get("comparison") or {}).get("value", "=")
    for t in ("str", "int", "float", "bool", "uns", "double", "ip"):
        if t not in args:
            continue
        a = args[t]
        val = a.get("value")
        rx = str(a.get("regex", "")).lower() in ("true", "1")
        if rx:
            frags = regex_fragments(str(val)) or []
            if via_payload:
                # a payload phrase must carry real signal; ".exe" or "/c" matches every event
                frags = [f for f in frags if len(f) >= 4 and f.lower() not in (".exe", ".dll", "http", "https")]
            if not frags:
                return None
            clause = " AND ".join(q_phrase(field, f) for f in frags)
            clause = f"({clause})" if len(frags) > 1 else clause
        elif t in ("int", "float", "uns", "double"):
            if op in (">", ">=", "<", "<="):
                return None if via_payload else f"{key}:{op}{val}"
            clause = q_phrase(field, str(val))
        elif t == "bool":
            if via_payload:
                return None
            clause = q_phrase(key, "true" if str(val).lower() in ("true", "success", "1") else "false")
        else:
            sval = str(val)
            if "/" in sval and re.fullmatch(r"[0-9a-fA-F:.]+/\d+", sval):
                if via_payload:
                    return None
                clause = f'{key}:"{sval}"'
            else:
                clause = q_phrase(field, sval)
        if op == "!=":
            # a negated payload phrase would over-constrain (the value may appear elsewhere)
            return None if via_payload else f"(NOT {clause})"
        return clause
    return None


def node_clause(node):
    if isinstance(node, list):
        node = {"id": "and", "children": node}
    if node.get("class") in ("column", "function"):
        return leaf_clause(node)
    op = str(node.get("id", "and")).upper()
    if op not in ("AND", "OR"):
        raise Unsupported(f"group {op}")
    parts = [node_clause(c) for c in node.get("children", []) or []]
    if op == "OR":
        if any(p is None for p in parts) or not parts:
            return None
    else:
        parts = [p for p in parts if p is not None]
        if not parts:
            return None
    return "(" + f" {op} ".join(parts) + ")" if len(parts) > 1 else parts[0]


def leaves(node):
    if isinstance(node, list):
        return [x for c in node for x in leaves(c)]
    if not isinstance(node, dict):
        return []
    if node.get("class") in ("column", "function"):
        return [node]
    return [x for c in node.get("children", []) or [] for x in leaves(c)]


def run_one(session: requests.Session, rec: dict, hours: float) -> dict:
    entry = {"hawk_id": rec["hawk_id"], "title": rec.get("filter_name"), "level": rec.get("_level"), "score": rec.get("correlation_action")}
    try:
        q = node_clause(rec["rules"])
    except Unsupported as e:
        entry.update({"status": "unsupported", "reason": str(e)})
        return entry
    cols = sorted({l.get("key") for l in leaves(rec["rules"]) if l.get("class") == "column"})
    entry["not_indexed"] = [c for c in cols if not is_indexed(c)]
    if q is None:
        entry.update({"status": "unbounded", "reason": "no indexed constraint survives; explore cannot bound this rule"})
        return entry
    entry["q"] = q
    t0 = time.time()
    try:
        r = session.post(BASE + "explore/aggregate", data={"idx": IDX, "q": q, "from": f"now-{int(hours)}h", "to": "now",
                                                          "group_by": "product_name", "metric": "count", "size": "20"}, timeout=600, verify=False)
        j = r.json()
        rows = (j.get("results") or {}).get("rows")
        if rows is None:
            entry.update({"status": "error", "error": str(j.get("details"))[:200], "elapsed": round(time.time() - t0, 1)})
            return entry
        by = [{"product": x.get("key", x.get("product_name")), "hits": int(x.get("count", x.get("doc_count", 0)) or 0)} for x in rows]
        total = sum(x["hits"] for x in by)
        entry.update({"status": "ok", "bound": "upper" if entry["not_indexed"] else "approx", "hits": total,
                      "hits_per_hour": round(total / hours, 2), "by_product": by, "elapsed": round(time.time() - t0, 1)})
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
    load_indexed()
    results = []
    with cf.ThreadPoolExecutor(max_workers=args.workers) as ex:
        for entry in ex.map(lambda h: run_one(session, conv[h], args.hours), ids):
            results.append(entry)
            tag = entry.get("status")
            print(f"{tag:10s} {entry['hawk_id']} {str(entry.get('title'))[:55]!r} hits={entry.get('hits', '-')} ({entry.get('hits_per_hour', '-')}/h) "
                  f"{'not_indexed=' + ','.join(entry['not_indexed']) if entry.get('not_indexed') else ''} {entry.get('reason') or entry.get('error') or ''}", flush=True)
            out_path.write_text(json.dumps({"hours": args.hours, "results": results}, indent=1), encoding="utf-8")
    noisy = [e for e in results if e.get("status") == "ok" and e.get("hits_per_hour", 0) >= 10]
    print(f"\n{len(results)} rules; ok={sum(e.get('status')=='ok' for e in results)} unbounded={sum(e.get('status')=='unbounded' for e in results)} "
          f"unsupported={sum(e.get('status')=='unsupported' for e in results)} error={sum(e.get('status')=='error' for e in results)}; >=10 hits/h: {len(noisy)}")
    print("wrote", out_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
