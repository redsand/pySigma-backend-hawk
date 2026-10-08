"""score_filters.py: exclusions behave as intended under engine semantics (local_eval.node)."""
from local_eval import node
from score_filters import apply_filters

TREE = {"name": ".", "children": [
    {"name": "HAWK", "children": [{"name": "HAWK - Windows"}]},
    {"name": "CUST-A", "children": [{"name": "A - Site 2"}, {"name": "A - Cloud", "children": [{"name": "A-Shared"}]}]},
    {"name": "CUST-B"}]}

BASE = [{"key": "And", "children": [
    {"key": "image", "class": "column", "return": "str", "args": {"comparison": {"value": "="}, "str": {"value": r"\\cmd\.exe$", "regex": True}}}]}]
CORR = [{"key": "And", "children": [BASE[0]["children"][0],
         {"key": "atomic_counter", "class": "function", "args": {}}]}]


def F(*ex):
    from score_filters import subtree_names
    out = []
    for e in ex:
        if e["tier"] == "customer":
            e = dict(e, _groups=subtree_names(TREE, e["customer"]))
        out.append(e)
    return {"h": out}


def ev(**kw):
    return dict({"image": r"C:\Windows\System32\cmd.exe"}, **kw)


def test_generic_endswith():
    r = apply_filters("h", BASE, F({"tier": "generic", "name": "ssm", "match": {"parent_image": {"endswith": r"\ssm-document-worker.exe"}}}))
    assert not node(r, ev(parent_image=r"C:\Program Files\Amazon\SSM\ssm-document-worker.exe"))
    assert node(r, ev(parent_image=r"C:\Windows\explorer.exe"))
    assert node(r, ev()), "missing column is not excluded"


def test_customer_scope_only_hits_that_customer():
    r = apply_filters("h", BASE, F({"tier": "customer", "customer": "CUST-A", "name": "scanner",
                                    "match": {"correlation_username": {"equals": "scanacct"}}}))
    assert not node(r, ev(correlation_username="scanacct", group_name="cust-a"))
    assert not node(r, ev(correlation_username="SCANACCT", group_name="a-shared")), "subtree + case-insensitive"
    assert node(r, ev(correlation_username="scanacct", group_name="cust-b")), "other customer keeps coverage"
    assert node(r, ev(correlation_username="scanacct", group_name="hawk - windows"))
    assert node(r, ev(correlation_username="alice", group_name="cust-a"))


def test_multi_condition_is_and():
    r = apply_filters("h", BASE, F({"tier": "generic", "name": "ws", "match": {
        "resource_name": {"regex": "^wsamzn-"}, "parent_command": {"contains": "-ExecutionPolicy AllSigned"}}}))
    assert not node(r, ev(resource_name="wsamzn-abc", parent_command="powershell -ExecutionPolicy AllSigned -x"))
    assert node(r, ev(resource_name="wsamzn-abc", parent_command="powershell -enc AAAA"))
    assert node(r, ev(resource_name="laptop1", parent_command="powershell -ExecutionPolicy AllSigned -x"))


def test_inserted_before_function_leaf():
    r = apply_filters("h", CORR, F({"tier": "generic", "name": "x", "match": {"user": {"equals": "svc"}}}))
    kids = r[0]["children"]
    assert kids[-1]["class"] == "function" and kids[1]["description"].startswith("hawk_filter:generic:")


def test_unfiltered_score_unchanged():
    assert apply_filters("other", BASE, F({"tier": "generic", "name": "x", "match": {"user": {"equals": "svc"}}})) is BASE


def test_private_customer_files_merge(tmp_path=None):
    import os
    import tempfile
    from pathlib import Path
    from score_filters import load_filters
    tree = {"name": ".", "children": [dict(TREE["children"][1], guid="g-a"), dict(TREE["children"][2], guid="g-b")]}
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        (d / "pub.yml").write_text("filters:\n  - score: S1\n    exclusions:\n      - {name: g, tier: generic, match: {x: {equals: '1'}}}\n", encoding="utf-8")
        (d / "c" / "customers" / "g-a").mkdir(parents=True)
        (d / "c" / "customers" / "g-a" / "score_filters.yml").write_text(
            "filters:\n  - score: s1\n    exclusions:\n      - {name: c, tier: customer, customer: CUST-A, match: {x: {equals: '2'}}}\n", encoding="utf-8")
        os.environ["HAWK_SIGMA_RULES"] = str(d / "c")
        try:
            f = load_filters(d / "pub.yml", groups=tree)
            assert [e["name"] for e in f["s1"]] == ["g", "c"]
            (d / "c" / "customers" / "g-b").mkdir()
            (d / "c" / "customers" / "g-b" / "score_filters.yml").write_text(
                "filters:\n  - score: s2\n    exclusions:\n      - {name: wrong, tier: customer, customer: CUST-A, match: {x: {equals: '3'}}}\n", encoding="utf-8")
            try:
                load_filters(d / "pub.yml", groups=tree)
                raise AssertionError("customer file under another customer's guid must be rejected")
            except SystemExit:
                pass
            os.environ["HAWK_SIGMA_RULES"] = str(d / "missing")
            try:
                load_filters(d / "pub.yml", groups=tree)
                raise AssertionError("missing private checkout must be an error")
            except SystemExit:
                pass
        finally:
            del os.environ["HAWK_SIGMA_RULES"]


if __name__ == "__main__":
    for t in [v for k, v in dict(globals()).items() if k.startswith("test_")]:
        t()
    print("PASS score_filters")
