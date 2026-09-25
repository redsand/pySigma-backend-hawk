"""Parity check: converted Sigma scores vs the live production scores.

Matches converted records to production by hawk_id (the Sigma rule UUID), then compares the
detection logic in three views:

  strict  - whole rule tree identical (after normalizing volatile ids and ordering)
  core    - the set of detection leaves (column, op, value, regex, case) identical; enrichment
            leaves (event_channel, product_name, vendor_name, vendor_id, vendor_type) ignored
  columns - the set of columns referenced identical (value differences ignored)

Also reports, for every mismatch, which side has leaves the other lacks, so the differences
can be adjudicated as regression / approved growth / taxonomy gap.

Usage:
    python parity.py [--converted reports/converted.jsonl] [--prod live/scores_2026-09-25.json]
                     [--report reports/parity_report.json] [--csv reports/parity_details.csv]
"""
import argparse
import collections
import csv
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ENRICH_KEYS = {"event_channel", "product_name", "vendor_name", "vendor_id", "vendor_type", "hawk_source",
               "product_source", "class_type", "event_type"}


def load_prod(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    rows = data.get("results", data)
    out = {}
    for r in rows:
        hid = r.get("hawk_id")
        if not hid:
            continue
        rules = r.get("rules")
        if isinstance(rules, str):
            try:
                rules = json.loads(rules)
            except Exception:  # noqa: BLE001
                continue
        r = dict(r)
        r["rules"] = rules
        out[str(hid).lower()] = r
    return out


def load_converted(path: Path) -> dict:
    out = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        rec = json.loads(line)
        out[str(rec["hawk_id"]).lower()] = rec
    return out


def leaves(node) -> list:
    if isinstance(node, list):
        return [x for c in node for x in leaves(c)]
    if not isinstance(node, dict):
        return []
    if node.get("class") in ("column", "function"):
        return [node]
    return [x for c in node.get("children", []) or [] for x in leaves(c)]


def leaf_sig(leaf: dict) -> tuple:
    args = leaf.get("args") or {}
    op = (args.get("comparison") or {}).get("value", "=")
    if leaf.get("class") == "function":
        vals = tuple(sorted((k, json.dumps(v, sort_keys=True)) for k, v in args.items() if k != "comparison"))
        return ("fn:" + str(leaf.get("key")), op, vals, False, False)
    for tkey in ("str", "int", "float", "bool", "uns", "double", "ip"):
        if tkey in args:
            a = args[tkey]
            val = a.get("value")
            rx = str(a.get("regex", "")).lower() in ("true", "1")
            case = str(a.get("case", "")).lower() in ("true", "1")
            if isinstance(val, str):
                val = val if case or rx else val.lower()
            return (str(leaf.get("key")), op, json.dumps(val, sort_keys=True), rx, case)
    return (str(leaf.get("key")), op, "", False, False)


def norm_tree(node):
    """Order-insensitive canonical form of a BETree (for strict comparison)."""
    if isinstance(node, list):
        return sorted((norm_tree(c) for c in node), key=json.dumps)
    if not isinstance(node, dict):
        return node
    if node.get("class") in ("column", "function"):
        return {"leaf": leaf_sig(node)}
    return {"op": str(node.get("id", "")).lower(), "children": sorted((norm_tree(c) for c in node.get("children", []) or []), key=json.dumps)}


def compare(conv: dict, prod: dict) -> dict:
    c_leaves = leaves(conv["rules"])
    p_leaves = leaves(prod["rules"])
    c_core = {leaf_sig(l) for l in c_leaves if l.get("key") not in ENRICH_KEYS}
    p_core = {leaf_sig(l) for l in p_leaves if l.get("key") not in ENRICH_KEYS}
    c_cols = {s[0] for s in c_core}
    p_cols = {s[0] for s in p_core}
    strict = json.dumps(norm_tree(conv["rules"])) == json.dumps(norm_tree(prod["rules"]))
    return {
        "strict": strict,
        "core": c_core == p_core,
        "columns": c_cols == p_cols,
        "only_converted": sorted(map(list, c_core - p_core))[:40],
        "only_production": sorted(map(list, p_core - c_core))[:40],
        "cols_only_converted": sorted(c_cols - p_cols),
        "cols_only_production": sorted(p_cols - c_cols),
        "score_converted": conv.get("correlation_action"),
        "score_production": float(prod.get("correlation_action") or 0),
        "prod_enabled": bool(prod.get("enabled")),
        "prod_last_updated": prod.get("last_updated"),
        "prod_date_added": prod.get("date_added"),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--converted", default=str(HERE / "reports" / "converted.jsonl"))
    ap.add_argument("--prod", default=str(HERE / "live" / "scores_2026-09-25.json"))
    ap.add_argument("--report", default=str(HERE / "reports" / "parity_report.json"))
    ap.add_argument("--csv", default=str(HERE / "reports" / "parity_details.csv"))
    args = ap.parse_args()

    prod = load_prod(Path(args.prod))
    conv = load_converted(Path(args.converted))
    matched = sorted(set(prod) & set(conv))
    stats = collections.Counter()
    col_gaps = collections.Counter()
    rows = []
    for hid in matched:
        r = compare(conv[hid], prod[hid])
        stats["matched"] += 1
        for k in ("strict", "core", "columns"):
            stats[k] += bool(r[k])
        for c in r["cols_only_converted"]:
            col_gaps[("converted_only", c)] += 1
        for c in r["cols_only_production"]:
            col_gaps[("production_only", c)] += 1
        rows.append({
            "hawk_id": hid,
            "title": conv[hid].get("_title") or prod[hid].get("filter_name"),
            "source": conv[hid].get("_source"),
            "strict": r["strict"], "core": r["core"], "columns": r["columns"],
            "prod_enabled": r["prod_enabled"],
            "score_converted": r["score_converted"], "score_production": r["score_production"],
            "cols_only_converted": ";".join(r["cols_only_converted"]),
            "cols_only_production": ";".join(r["cols_only_production"]),
            "only_converted": json.dumps(r["only_converted"])[:1000],
            "only_production": json.dumps(r["only_production"])[:1000],
        })
    report = {
        "production_total": len(prod),
        "converted_total": len(conv),
        "matched_by_hawk_id": len(matched),
        "strict_match": stats["strict"],
        "core_match": stats["core"],
        "columns_match": stats["columns"],
        "core_match_pct": round(100.0 * stats["core"] / max(1, len(matched)), 2),
        "columns_match_pct": round(100.0 * stats["columns"] / max(1, len(matched)), 2),
        "top_column_gaps": [{"side": k[0], "column": k[1], "rules": v} for k, v in col_gaps.most_common(60)],
        "converted_not_in_production": len(set(conv) - set(prod)),
        "production_without_converted": len(set(prod) - set(conv)),
    }
    Path(args.report).write_text(json.dumps(report, indent=1), encoding="utf-8")
    with Path(args.csv).open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()) if rows else ["hawk_id"])
        w.writeheader()
        w.writerows(rows)
    print(json.dumps({k: v for k, v in report.items() if k != "top_column_gaps"}, indent=1))
    print("top column gaps:")
    for g in report["top_column_gaps"][:30]:
        print(f"  {g['side']:16s} {g['column']:32s} {g['rules']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
