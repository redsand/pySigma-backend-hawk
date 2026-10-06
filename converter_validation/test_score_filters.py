"""score_filters.py: exclusions behave as intended under engine semantics (local_eval.node)."""
from local_eval import node
from score_filters import apply_filters

TREE = {"name": ".", "children": [
    {"name": "HAWK", "children": [{"name": "HAWK - Windows"}]},
    {"name": "HUNT", "children": [{"name": "DR - Disaster Recovery"}, {"name": "AWS - Amazon Cloud", "children": [{"name": "Prod-Shared"}]}]},
    {"name": "PBEX-Inc"}]}

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
    r = apply_filters("h", BASE, F({"tier": "customer", "customer": "HUNT", "name": "scanner",
                                    "match": {"correlation_username": {"equals": "hawkscan"}}}))
    assert not node(r, ev(correlation_username="hawkscan", group_name="hunt"))
    assert not node(r, ev(correlation_username="HAWKSCAN", group_name="prod-shared")), "subtree + case-insensitive"
    assert node(r, ev(correlation_username="hawkscan", group_name="pbex-inc")), "other customer keeps coverage"
    assert node(r, ev(correlation_username="hawkscan", group_name="hawk - windows"))
    assert node(r, ev(correlation_username="alice", group_name="hunt"))


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


if __name__ == "__main__":
    for t in [v for k, v in dict(globals()).items() if k.startswith("test_")]:
        t()
    print("PASS score_filters")
