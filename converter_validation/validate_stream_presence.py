"""Check converted scores against what the normalized event stream actually carries.

For each converted record:
  1. derive the event population it targets from its enrichment leaves
     (product_name / vendor_id / event_channel), e.g. Sysmon:1, Security-Auditing:4688, Entra:*;
  2. look that population up in live/stream_field_profiles.json (built by profile_stream.py from
     raw streamd documents);
  3. for every detection column, report the share of sampled documents that carry it.

A score whose detection columns never appear in its target population cannot fire. One whose
enrichment values never appear in the stream cannot fire either. Both are reported.

Usage:
    python validate_stream_presence.py [--converted reports/converted.jsonl]
                                       [--profiles live/stream_field_profiles.json]
                                       [--report reports/stream_presence.json]
                                       [--csv reports/stream_presence.csv]
"""
import argparse
import collections
import csv
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ENRICH = ("product_name", "vendor_id", "event_channel", "vendor_name", "vendor_type", "product_source")
CHANNEL_TO_PRODUCT = {
    "security": "Security-Auditing",
    "microsoft-windows-sysmon/operational": "Sysmon",
    "microsoft-windows-powershell/operational": "PowerShell",
    "windows powershell": "PowerShell",
    "system": "Service_Control_Manager",
    "microsoft-windows-taskscheduler/operational": "TaskScheduler",
    "microsoft-windows-codeintegrity/operational": "CodeIntegrity",
    "microsoft-windows-dns-client/operational": "DNS-Client",
    "microsoft-windows-windows firewall with advanced security/firewall": "Windows_Firewall_With_Advanced_Security",
    "microsoft-windows-wmi-activity/operational": "WMI-Activity",
}


def leaves(node) -> list:
    if isinstance(node, list):
        return [x for c in node for x in leaves(c)]
    if not isinstance(node, dict):
        return []
    if node.get("class") in ("column", "function"):
        return [node]
    return [x for c in node.get("children", []) or [] for x in leaves(c)]


def leaf_value(leaf: dict):
    args = leaf.get("args") or {}
    for t in ("str", "int", "float", "bool"):
        if t in args:
            return args[t].get("value")
    return None


def target_population(rec: dict) -> tuple:
    """Return (product_name, vendor_id or '*') derived from enrichment leaves."""
    product = None
    vid = "*"
    for leaf in leaves(rec["rules"]):
        k = leaf.get("key")
        v = leaf_value(leaf)
        if k == "product_name" and isinstance(v, str) and not (leaf.get("args", {}).get("str", {}).get("regex")):
            product = product or v
        elif k == "event_channel" and isinstance(v, str):
            product = product or CHANNEL_TO_PRODUCT.get(v.lower())
        elif k == "vendor_id" and v is not None and vid == "*":
            vid = str(v)
    return product, vid


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--converted", default=str(HERE / "reports" / "converted.jsonl"))
    ap.add_argument("--profiles", default=str(HERE / "live" / "stream_field_profiles.json"))
    ap.add_argument("--report", default=str(HERE / "reports" / "stream_presence.json"))
    ap.add_argument("--csv", default=str(HERE / "reports" / "stream_presence.csv"))
    args = ap.parse_args()

    profiles = json.loads(Path(args.profiles).read_text(encoding="utf-8"))
    by_pop = {k: v for k, v in profiles.items() if v.get("n")}
    rows = []
    summary = collections.Counter()
    col_missing = collections.Counter()
    for line in Path(args.converted).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        rec = json.loads(line)
        product, vid = target_population(rec)
        key = f"{product}:{vid}" if product else None
        # Only judge a rule against a profile of its exact event population; a Sysmon 12 rule
        # checked against Sysmon 1 documents would be reported dead for the wrong reason.
        prof = by_pop.get(key) or (by_pop.get(f"{product}:*") if product else None)
        det_cols = sorted({l.get("key") for l in leaves(rec["rules"]) if l.get("class") == "column" and l.get("key") not in ENRICH})
        if prof is None:
            summary["no_profile"] += 1
            rows.append({"hawk_id": rec["hawk_id"], "title": rec.get("_title"), "source": rec.get("_source"),
                         "population": key or "", "verdict": "no_profile", "missing": "", "low": "", "present": ";".join(det_cols)})
            continue
        n = prof["n"]
        fields = prof["fields"]
        missing = [c for c in det_cols if fields.get(c, 0) == 0]
        low = [f"{c}:{fields.get(c,0)}/{n}" for c in det_cols if 0 < fields.get(c, 0) < 0.5 * n]
        present = [c for c in det_cols if fields.get(c, 0) >= 0.5 * n]
        if det_cols and len(missing) == len(det_cols):
            verdict = "dead_all_columns_missing"
        elif missing:
            verdict = "partial_columns_missing"
        elif low:
            verdict = "low_presence"
        else:
            verdict = "ok"
        summary[verdict] += 1
        for c in missing:
            col_missing[(key, c)] += 1
        rows.append({"hawk_id": rec["hawk_id"], "title": rec.get("_title"), "source": rec.get("_source"),
                     "population": key, "verdict": verdict, "missing": ";".join(missing), "low": ";".join(low), "present": ";".join(present)})
    report = {
        "records": len(rows),
        "summary": dict(summary),
        "profiles_available": sorted(by_pop.keys()),
        "top_missing_columns": [{"population": k[0], "column": k[1], "rules": v} for k, v in col_missing.most_common(60)],
    }
    Path(args.report).write_text(json.dumps(report, indent=1), encoding="utf-8")
    with Path(args.csv).open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print(json.dumps({k: v for k, v in report.items() if k != "top_missing_columns"}, indent=1))
    for g in report["top_missing_columns"][:40]:
        print(f"  {g['population']:26s} {g['column']:28s} {g['rules']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
