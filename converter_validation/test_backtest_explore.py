"""backtest_explore: a regex fragment must be searched as part of a value. Run: python test_backtest_explore.py

The backtest gates unattended pushes, so its count must be an upper bound. "^CodeIntegrity_" searched
as a phrase matched 0 events in 72 h while 5.95 million Code Integrity rows were in the index
(2026-11-05): a phrase compares whole values/tokens, and the noisiest prefix rules looked quiet.
"""
from backtest_explore import leaf_clause


def check(cond, msg):
    if not cond:
        raise SystemExit("FAIL " + msg)


def leaf(rx):
    return {"key": "threat_name", "class": "column", "args": {"comparison": {"value": "="}, "str": {"value": rx, "regex": True}}}


prefix = leaf_clause(leaf("^CodeIntegrity_"))
check("threat_name:CodeIntegrity_*" in prefix, f"startswith must become a prefix wildcard: {prefix}")
check("threat_name:*CodeIntegrity_" not in prefix, f"an anchored start must not get a leading wildcard: {prefix}")
contains = leaf_clause(leaf("lsass"))
check("threat_name:*lsass*" in contains, f"contains must be open on both sides: {contains}")
exact = leaf_clause(leaf("^Exact$"))
check("threat_name:Exact)" in exact, f"an anchored value needs no wildcard: {exact}")
check("\\:" in leaf_clause(leaf("C:x")), "lucene specials in a fragment must be escaped")
print("PASS backtest_explore")
