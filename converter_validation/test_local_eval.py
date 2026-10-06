"""Unit checks: local_eval.py follows the engine's leaf semantics (see its docstring)."""
from local_eval import leaf, node


def L(key, v, op="=", regex=False, ret="str", **kw):
    return {"key": key, "class": "column", "return": ret,
            "args": {"comparison": {"value": op}, "str": {"value": v, "regex": regex, **kw}}}


D = {"image": r"C:\Windows\System32\CMD.exe", "ip_src": "136.226.5.4", "tags": ["a", "b"],
     "audit_login": True, "count": "42"}

CASES = [
    (leaf(L("image", r"\\cmd\.exe$", regex=True), D), True, "regex unanchored, case-insensitive"),
    (leaf(L("image", r"\\cmd\.exe$", regex=True, case=True), D), False, "case:true is case-sensitive"),
    (leaf(L("image", r"c:\windows\system32\cmd.exe"), D), True, "equality case-insensitive"),
    (leaf(L("image", "cmd.exe"), D), False, "equality is whole-string"),
    (leaf(L("missing", "x"), D), False, "missing column ="),
    (leaf(L("missing", "x", "!="), D), True, "missing column !="),
    (leaf(L("ip_src", "136.226.0.0/17", "!="), D), False, "CIDR != is inverted membership"),
    (leaf(L("ip_src", "136.226.0.0/17"), D), True, "CIDR = membership"),
    (leaf(L("tags", "a", "!="), D), True, "list != is any-element-differs"),
    (leaf(L("tags", "b"), D), True, "list = is any element"),
    (leaf({"key": "audit_login", "class": "column", "return": "boolean",
           "args": {"comparison": {"value": "="}, "bool": {"value": "success"}}}, D), True, "bool success"),
    (leaf({"key": "count", "class": "column", "return": "int",
           "args": {"comparison": {"value": ">"}, "int": {"value": 40}}}, D), True, "int strtol on string"),
    (leaf({"key": "empty", "class": "function", "args": {"comparison": {"value": "!="}, "column": {"value": "image"}}}, D), True, "empty != -> present"),
    (node({"key": "Or", "children": [L("missing", "x"), L("image", "cmd", regex=True)]}, D), True, "Or"),
    (node({"key": "And", "children": [L("image", "cmd", regex=True), L("missing", "x")]}, D), False, "And"),
]


def test_semantics():
    bad = [m for got, want, m in CASES if got != want]
    assert not bad, bad


if __name__ == "__main__":
    test_semantics()
    print(f"PASS {len(CASES)} cases")
