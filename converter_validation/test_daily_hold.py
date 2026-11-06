"""test_hawk_rules names exactly the failing rules. Run: python test_daily_hold.py

daily_sync holds back the rules listed in reports/hawk_rules_failed.txt and pushes the rest. If a
failing rule were not named, the run would stop and every other new rule would wait (2026-11-05: one
rule blocked 37 for a day); if a passing rule were named, it would never ship.
"""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
FAILED = HERE / "reports" / "hawk_rules_failed.txt"


def check(cond, msg):
    if not cond:
        raise SystemExit("FAIL " + msg)


def rec(hid, name_rx):
    return {"hawk_id": hid, "filter_name": "HAWK - test " + hid, "_source": "hawk/test.yml",
            "rules": [{"key": "rule_name", "class": "column", "return": "str",
                       "args": {"comparison": {"value": "="}, "str": {"value": name_rx, "regex": True}}}]}


# "bad" matches the benign vulkan shape in NEGATIVES; "good" matches nothing benign
with tempfile.TemporaryDirectory() as d:
    conv = Path(d) / "converted.jsonl"
    conv.write_text("\n".join(json.dumps(r) for r in (rec("bad-0001", "^CodeIntegrity_"), rec("good-0001", "^NoSuchRule_"))),
                    encoding="utf-8")
    p = subprocess.run([sys.executable, "test_hawk_rules.py", str(conv), str(Path(d) / "no_hits.json")],
                       cwd=HERE, capture_output=True, text=True)
named = FAILED.read_text(encoding="utf-8").split() if FAILED.exists() else []
FAILED.unlink(missing_ok=True)
check(p.returncode == 1, f"a failing rule must fail the test run (rc={p.returncode})")
check(named == ["bad-0001"], f"exactly the failing rule must be named, got {named}")
print("PASS daily_hold")
