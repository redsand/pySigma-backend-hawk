"""Check our own rules (hawk_rules/) against real events and positive controls with engine semantics.

    python test_hawk_rules.py [converted.jsonl] [hits.json]
Default inputs: reports/converted.jsonl (records whose _source starts with hawk/) and live/yara_hits.json.
"""
import json
import sys
from pathlib import Path

from local_eval import node

HERE = Path(__file__).resolve().parent

POSITIVES = {
    "af032a17-2b22-4cd4-bb06-bc4efccd3b23": {"rule_name": "SIGNATURE_BASE_CobaltStrike_Beacon_Loader",
                                             "filename": r"C:\Program Files\Acme\agent.dll", "scan_context": "fim_change"},
    "e4f8ca92-403d-41dd-8358-461983719ee6": {"rule_name": "MALPEDIA_Win_Qakbot_Auto",
                                             "filename": r"C:\Users\bob\AppData\Local\Temp\inv.dll", "scan_context": "fim_change"},
    "065f9314-6f1c-4a39-9a3e-3d499161c909": {"rule_name": "CAPE_Lumma",
                                             "filename": r"D:\share\tools\run.exe", "scan_context": "process_create"},
    "17d4e717-1423-4c74-8a40-bf037e38c154": {"rule_name": "MALPEDIA_Win_Qakbot_Auto",
                                             "filename": r"C:\Users\bob\Downloads\inv.dll", "scan_context": "fim_change"},
}
NEGATIVES = [  # benign shapes seen 2026-10-05 must not match
    {"rule_name": "SIGNATURE_BASE_Reflectiveloader", "filename": r"C:\Program Files\SentinelOne\Sentinel Agent 26.1.2.177\InProcessClient64.dll", "scan_context": "fim_change"},
    {"rule_name": "MALPEDIA_Win_Snake_Disk_Auto", "filename": r"C:\Program Files (x86)\Adobe\Acrobat DC\Acrobat\acrotray.exe", "scan_context": "process_create"},
    {"rule_name": "CodeIntegrity_vulkan-1.dll", "filename": r"C:\Users\bob\AppData\Local\x\vulkan-1.dll", "scan_context": "code_integrity"},
]


def strip_functions(n):
    """Per-event check: drop stateful function leaves (counters)."""
    if isinstance(n, list):
        return [strip_functions(c) for c in n if not (isinstance(c, dict) and c.get("class") == "function")]
    n = dict(n)
    n["children"] = [strip_functions(c) for c in n.get("children", []) or [] if c.get("class") != "function"]
    return n


def main() -> int:
    conv = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / "reports" / "converted.jsonl"
    hits_path = Path(sys.argv[2]) if len(sys.argv) > 2 else HERE / "live" / "yara_hits.json"
    recs = [json.loads(l) for l in conv.read_text(encoding="utf-8").splitlines() if l.strip()]
    recs = [r for r in recs if str(r.get("_source", "")).startswith("hawk/")]
    hits = json.loads(hits_path.read_text(encoding="utf-8")) if hits_path.exists() else []
    # events recorded before ruleset cf41334 carry the raw names; apply that translation
    for h in hits:
        for raw, col in (("file_path", "filename"), ("file_sha256", "file_hash_sha256"), ("rule_tag", "rule_type")):
            if raw in h and col not in h:
                h[col] = h.pop(raw)
    gate = {"product_name": "HAWK-vTTAC-YARA", "vendor_id": "1001", "resource_name": "h1"}
    fails = 0
    for r in recs:
        logic = strip_functions(r["rules"])
        real = [h for h in hits if node(logic, h)]
        pos = POSITIVES.get(r["hawk_id"])
        pos_ok = node(logic, dict(gate, **pos)) if pos else None
        neg_bad = [n["rule_name"] for n in NEGATIVES if node(logic, dict(gate, **n))]
        ok = pos_ok is not False and not neg_bad
        fails += not ok
        print(f"{'OK  ' if ok else 'FAIL'} {r['filter_name'][:72]}\n"
              f"      real hits matched: {len(real)}/{len(hits)} {sorted({h.get('rule_name') for h in real})}"
              f" | positive control: {pos_ok} | benign shapes matched: {neg_bad or 'none'}")
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
