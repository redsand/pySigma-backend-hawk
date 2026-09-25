#!/usr/bin/env python3
"""
hwk_inventory.py - inventory of normalized columns / taxonomy values emitted by
HAWK ECE .hwk normalization rules (hawk-ece-rules/sl_*.hwk).

Mirrors the engine's Source-string semantics (hawk-ece/src/hawkcorr/hawk-match.c,
HWKProcessSourceInfo / HWKPreProcessSourceInfo):
  * Source="k1: v1; k2: $2; ..."  -> split on ';', then on FIRST ':' ; trim both sides
  * tokens without ':' are silently dropped by the engine (recorded here as malformed)
  * '$N' in value (or key) is replaced by InfoMatch capture group N  -> "captured"
  * values '-' / '?' are skipped by the engine (recorded as skipped)
  * key is passed through the module translation table, else uncamel()
BeginTranslation From/To blocks are recorded as translation targets (captured).
Rule keywords HID/Alert/AlertType/Priority are recorded as implicit engine columns.

Usage: python hwk_inventory.py [--rules DIR] [--scripts DIR] [--columns-json FILE] [--out FILE]
"""
import argparse
import glob
import json
import os
import re
import sys
from collections import defaultdict, OrderedDict

TAXONOMY = ["product_name", "vendor_name", "vendor_id", "vendor_type", "class_type",
            "event_channel", "hawk_source", "product_source", "event_type", "event_name"]

# rule keywords that the engine itself materializes as columns (hawk-rules-hwk.c)
IMPLICIT_KEYWORDS = {"HID": "hid", "Alert": "alert_name", "AlertType": "alerts_type_category",
                     "Priority": "priority"}

BLOCK_BEGIN = {"BeginPreRule": "PreRule", "BeginFormatRule": "FormatRule",
               "BeginRule": "Rule", "BeginTranslation": "Translation", "BeginGroup": "Group"}
BLOCK_END = {"EndPreRule", "EndFormatRule", "EndRule", "EndTranslation", "EndGroup"}

KV_RE = re.compile(r'^([A-Za-z_]+)\s*=\s*"?(.*?)"?\s*$')
CAP_RE = re.compile(r'\$\d+')


def uncamel(key):
    """approximation of hawk-match.c uncamel(): CamelCase -> snake_case, separators -> '_'"""
    k = re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', key)
    k = re.sub(r'[ /\-]+', '_', k)
    return k.lower()


def parse_source(src):
    """Return list of dicts for each token of a Source string, engine-faithful."""
    out = []
    for tok in src.split(';'):
        if tok.strip() == "":
            continue
        if ':' not in tok:
            out.append({"raw": tok.strip(), "malformed": True})
            continue
        key, val = tok.split(':', 1)
        key, val = key.strip(), val.strip()
        if val == "":
            out.append({"raw": tok.strip(), "malformed": True})
            continue
        entry = {"key": key, "value": val, "malformed": False}
        entry["dynamic_key"] = bool(CAP_RE.search(key))
        entry["captured"] = bool(CAP_RE.search(val))
        entry["skipped"] = val in ("-", "?")
        out.append(entry)
    return out


def parse_hwk(path, translation_cache):
    """Parse one .hwk file. Returns per-file record + list of assignment events."""
    rec = OrderedDict()
    rec["file"] = os.path.basename(path)
    rec["RuleName"] = None
    rec["RuleKey"] = None
    rec["HostClassification"] = []
    rec["Trigger"] = []
    rec["NotTrigger"] = []
    rec["translations"] = []           # {from,to,line}
    rec["identity_prerules"] = []      # constants set in PreRule blocks (vendor/product/type)
    rec["malformed_source_tokens"] = []
    rec["counts"] = {"PreRule": 0, "FormatRule": 0, "Rule": 0, "Group": 0, "Translation": 0}
    assignments = []                   # {file,line,block,key,value,kind}

    block_stack = []
    cur_from = None
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for lineno, raw in enumerate(fh, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line in BLOCK_BEGIN:
                block_stack.append(BLOCK_BEGIN[line])
                rec["counts"][BLOCK_BEGIN[line]] += 1
                cur_from = None
                continue
            if line in BLOCK_END:
                if block_stack:
                    block_stack.pop()
                continue
            m = KV_RE.match(line)
            if not m:
                continue
            key, val = m.group(1), m.group(2)
            block = block_stack[-1] if block_stack else "Module"

            if key == "RuleName":
                rec["RuleName"] = val
            elif key == "RuleKey":
                rec["RuleKey"] = val
            elif key == "HostClassification":
                rec["HostClassification"].append(val)
            elif key == "Trigger":
                rec["Trigger"].append(val)
            elif key == "NotTrigger":
                rec["NotTrigger"].append(val)
            elif key == "From" and block == "Translation":
                cur_from = val
            elif key == "To" and block == "Translation":
                rec["translations"].append({"from": cur_from, "to": val, "line": lineno})
                assignments.append({"file": rec["file"], "line": lineno, "block": "Translation",
                                    "key": val, "value": None, "kind": "translation",
                                    "translated_from": cur_from})
            elif key in IMPLICIT_KEYWORDS and block in ("Rule", "Group"):
                assignments.append({"file": rec["file"], "line": lineno, "block": block,
                                    "key": IMPLICIT_KEYWORDS[key], "value": val, "kind": "implicit"})
            elif key.lower() == "source":
                for tok in parse_source(val):
                    if tok.get("malformed"):
                        rec["malformed_source_tokens"].append({"line": lineno, "token": tok["raw"]})
                        continue
                    if tok["dynamic_key"]:
                        assignments.append({"file": rec["file"], "line": lineno, "block": block,
                                            "key": tok["key"], "value": tok["value"],
                                            "kind": "dynamic_key"})
                        continue
                    # engine: translation table first, else uncamel()
                    k = tok["key"]
                    tr = {t["from"]: t["to"] for t in rec["translations"]}
                    k = tr.get(k, uncamel(k))
                    kind = "skipped" if tok["skipped"] else ("captured" if tok["captured"] else "constant")
                    assignments.append({"file": rec["file"], "line": lineno, "block": block,
                                        "key": k, "value": tok["value"], "kind": kind})
                    if block in ("PreRule", "FormatRule") and kind == "constant" and \
                            k in ("vendor_name", "product_name", "vendor_type"):
                        rec["identity_prerules"].append({"line": lineno, "key": k, "value": tok["value"]})
    return rec, assignments


PY_CONST_RE = re.compile(
    r"""(?:\[\s*['"](?P<k1>vendor_name|product_name|vendor_type|hawk_source|product_source|class_type|event_channel|vendor_id)['"]\s*\]\s*=\s*['"](?P<v1>[^'"]*)['"])"""
    r"""|(?:['"](?P<k2>vendor_name|product_name|vendor_type|hawk_source|product_source|class_type|event_channel|vendor_id)['"]\s*[:=]\s*['"](?P<v2>[^'"]*)['"])"""
    r"""|(?:\b(?P<k3>vendor_name|product_name|vendor_type|product_source|class_type|hawk_source)\s*=\s*['"](?P<v3>[^'"]*)['"])""")


def scan_python_collectors(scripts_dir):
    """Literal taxonomy constants set by hawk-ece/scripts/hawk_*.py collectors (bypass .hwk)."""
    out = defaultdict(lambda: defaultdict(list))
    for path in sorted(glob.glob(os.path.join(scripts_dir, "hawk_*.py"))):
        base = os.path.basename(path)
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for lineno, line in enumerate(fh, 1):
                    s = line.strip()
                    if s.startswith("#"):
                        continue
                    for m in PY_CONST_RE.finditer(line):
                        k = m.group("k1") or m.group("k2") or m.group("k3")
                        v = m.group("v1") if m.group("k1") else (m.group("v2") if m.group("k2") else m.group("v3"))
                        out[k][v].append("%s:%d" % (base, lineno))
        except OSError:
            pass
    return {k: dict(v) for k, v in out.items()}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rules", default=r"C:\Users\tshel\source\repos\hawk-ece-rules")
    ap.add_argument("--scripts", default=r"C:\Users\tshel\source\repos\hawk-ece\scripts")
    ap.add_argument("--columns-json", default=r"C:\Users\tshel\source\repos\hawk-ece\src\hawkcorr\tests\columns.json")
    ap.add_argument("--out", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "hwk_inventory.json"))
    args = ap.parse_args()

    files = sorted(glob.glob(os.path.join(args.rules, "sl_*.hwk")))
    per_file = []
    all_assign = []
    for f in files:
        rec, asg = parse_hwk(f, {})
        per_file.append(rec)
        all_assign.extend(asg)

    # (a) all columns any rule assigns, with per-column count of rule files and breakdown
    col_files = defaultdict(set)
    col_kinds = defaultdict(lambda: defaultdict(int))
    for a in all_assign:
        if a["kind"] == "dynamic_key":
            continue
        col_files[a["key"]].add(a["file"])
        col_kinds[a["key"]][a["kind"]] += 1
    columns = OrderedDict()
    for k in sorted(col_files, key=lambda x: (-len(col_files[x]), x)):
        columns[k] = {"rule_file_count": len(col_files[k]),
                      "assignment_kinds": dict(col_kinds[k]),
                      "files": sorted(col_files[k])}

    # (b) taxonomy columns: every distinct CONSTANT value with the files (and lines) that assign it
    taxonomy = OrderedDict()
    for col in TAXONOMY:
        consts = defaultdict(list)
        captured = defaultdict(int)
        translated = []
        for a in all_assign:
            if a["key"] != col:
                continue
            if a["kind"] == "constant":
                consts[a["value"]].append("%s:%d[%s]" % (a["file"], a["line"], a["block"]))
            elif a["kind"] == "captured":
                captured[a["file"]] += 1
            elif a["kind"] == "translation":
                translated.append("%s:%d <- %s" % (a["file"], a["line"], a["translated_from"]))
        taxonomy[col] = {
            "assigned_by_any_hwk": bool(consts or captured or translated),
            "distinct_constant_values": len(consts),
            "constants": OrderedDict((v, sorted(set(loc))) for v, loc in sorted(consts.items())),
            "captured_from_payload_files": dict(sorted(captured.items())),
            "translation_targets": translated,
        }

    # dynamic keys ("$2: $3") - whole key/value pairs lifted from payload
    dynamic = [{"file": a["file"], "line": a["line"], "key": a["key"], "value": a["value"]}
               for a in all_assign if a["kind"] == "dynamic_key"]

    # columns file vs live columns table
    columns_file = []
    cf_path = os.path.join(args.rules, "columns")
    if os.path.exists(cf_path):
        with open(cf_path, "r", encoding="utf-8", errors="replace") as fh:
            columns_file = [l.strip() for l in fh if l.strip()]
    live = {}
    if os.path.exists(args.columns_json):
        try:
            with open(args.columns_json, "r", encoding="utf-8") as fh:
                for r in json.load(fh)["results"]:
                    live[r["key"]] = {"type": r.get("type"), "description": r.get("description"),
                                      "enabled": r.get("enabled")}
        except (OSError, ValueError, KeyError):
            live = {}
    hwk_cols = set(columns)
    columns_section = {
        "columns_file_path": cf_path,
        "columns_file_count": len(columns_file),
        "columns_file_unique": len(set(columns_file)),
        "columns_file_duplicates": sorted({c for c in columns_file if columns_file.count(c) > 1}),
        "columns_file": columns_file,
        "live_columns_json_path": args.columns_json,
        "live_columns_count": len(live),
        "live_taxonomy_types": {k: live[k] for k in TAXONOMY + ["os_type_name", "class_name", "event_id", "hid", "alert_name", "alerts_type_name"] if k in live},
        "in_columns_file_not_live": sorted(set(columns_file) - set(live)) if live else None,
        "hwk_assigned_not_in_columns_file": sorted(hwk_cols - set(columns_file)),
        "hwk_assigned_not_in_live": sorted(hwk_cols - set(live)) if live else None,
    }

    py = scan_python_collectors(args.scripts) if os.path.isdir(args.scripts) else {}

    summary = OrderedDict()
    summary["rule_files"] = len(files)
    summary["total_source_assignments"] = sum(1 for a in all_assign if a["kind"] in ("constant", "captured", "skipped"))
    summary["constant_assignments"] = sum(1 for a in all_assign if a["kind"] == "constant")
    summary["captured_assignments"] = sum(1 for a in all_assign if a["kind"] == "captured")
    summary["translation_entries"] = sum(1 for a in all_assign if a["kind"] == "translation")
    summary["dynamic_key_assignments"] = len(dynamic)
    summary["malformed_source_tokens"] = sum(len(r["malformed_source_tokens"]) for r in per_file)
    summary["distinct_columns_assigned"] = len(columns)
    summary["taxonomy_columns_never_assigned_by_hwk"] = [c for c in TAXONOMY if not taxonomy[c]["assigned_by_any_hwk"]]
    summary["taxonomy_distinct_constants"] = {c: taxonomy[c]["distinct_constant_values"] for c in TAXONOMY}

    out = OrderedDict()
    out["_about"] = {
        "generator": os.path.basename(__file__),
        "rules_dir": args.rules,
        "semantics": "Source='k: v; ...' split on ';' then first ':'; '$N' = InfoMatch capture (captured); "
                     "'-'/'?' skipped; key -> BeginTranslation table else uncamel(). "
                     "class_type/os_type_name/class_name come from the resource (asset) record in "
                     "hawk-http-map.c, not from .hwk. hawk_source arrives inside the raw payload from the "
                     "collection agent. product_source is set only by hawk-ece/scripts/hawk_*.py collectors.",
    }
    out["summary"] = summary
    out["columns"] = columns
    out["taxonomy"] = taxonomy
    out["dynamic_key_assignments"] = dynamic
    out["files"] = per_file
    out["columns_file"] = columns_section
    out["python_collectors_out_of_hwk"] = py

    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=1)

    print("wrote", args.out)
    print(json.dumps(summary, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
