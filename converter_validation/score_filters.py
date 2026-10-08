"""Apply score_filters.yml exclusions to converted score logic (see that file for the format).

    from score_filters import load_filters, apply_filters
    filters = load_filters(groups=fetch_group_tree(session))   # customer scopes need the group tree
    rules = apply_filters(hawk_id, rules, filters)

Every added leaf carries description "hawk_filter:<tier>:<name>" so the exclusions are visible in the
portal and can be told apart from the Sigma logic. Exclusions are inserted before any stateful function
leaf (counters must not count excluded events); otherwise appended to the top-level And.
"""
import copy
import json
import os
import re
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
TIERS = ("generic", "hawk", "customer")


def fetch_group_tree(session, base):
    return session.get(base + "group?format=json", timeout=300, verify=False).json()["results"]


def subtree_names(tree, top):
    """All group names under (and including) the top-level group named `top` (case-insensitive)."""
    def find(n):
        if str(n.get("name", "")).lower() == top.lower():
            return n
        for c in n.get("children") or []:
            f = find(c)
            if f:
                return f
        return None

    def names(n):
        out = [n["name"]]
        for c in n.get("children") or []:
            out += names(c)
        return out
    node = find(tree)
    if node is None:
        raise SystemExit(f"score_filters: customer group {top!r} not found in the group tree")
    return names(node)


def content_dir():
    """Checkout of the private repo siem/hawk-sigma-rules (custom rules + customer content).
    HAWK_SIGMA_RULES overrides the default sibling checkout ../../hawk-sigma-rules."""
    return Path(os.environ.get("HAWK_SIGMA_RULES") or HERE.parents[1] / "hawk-sigma-rules")


def _customer_guid(groups, name):
    for g in (groups or {}).get("children") or []:
        if str(g.get("name", "")).lower() == str(name).lower():
            return str(g.get("guid"))
    return None


def load_filters(path=HERE / "score_filters.yml", groups=None, customers=True):
    """Public generic/hawk exclusions plus, unless customers=False, every customer's private
    customers/<group_guid>/score_filters.yml. A missing private checkout is an error: syncing
    without it would push scores with the customer exclusions stripped."""
    files = [Path(path)]
    if customers:
        cdir = content_dir() / "customers"
        if not cdir.is_dir():
            raise SystemExit(f"score_filters: private content repo not found at {cdir.parent} "
                             "(clone siem/hawk-sigma-rules there or set HAWK_SIGMA_RULES)")
        files += sorted(cdir.glob("*/score_filters.yml"))
    out = {}
    for fp in files:
        private = fp != Path(path)
        doc = yaml.safe_load(fp.read_text(encoding="utf-8")) or {}
        for f in doc.get("filters") or []:
            ex = []
            for e in f.get("exclusions") or []:
                tier = e.get("tier")
                if tier not in TIERS:
                    raise SystemExit(f"score_filters: {f['score']} / {e.get('name')}: tier must be one of {TIERS}")
                if private and tier != "customer":
                    raise SystemExit(f"{fp}: {e.get('name')}: only customer-tier exclusions belong in a customer file")
                if not private and tier == "customer":
                    raise SystemExit(f"{fp}: {e.get('name')}: customer-tier exclusions belong in the private repo")
                if tier == "customer":
                    if not e.get("customer"):
                        raise SystemExit(f"score_filters: {e.get('name')}: customer tier needs `customer:`")
                    if groups is None:
                        raise SystemExit("score_filters: customer-scoped exclusions need the group tree (groups=)")
                    if private and _customer_guid(groups, e["customer"]) != fp.parent.name:
                        raise SystemExit(f"{fp}: {e.get('name')}: customer {e['customer']!r} is not group {fp.parent.name}")
                    e = dict(e, _groups=subtree_names(groups, e["customer"]))
                ex.append(e)
            out.setdefault(str(f["score"]).lower(), []).extend(ex)
    return out


def _leaf(key, op, value, regex, desc):
    s = {"value": value}
    if regex:
        s["regex"] = True
    return {"key": key, "description": desc, "class": "column", "return": "str",
            "args": {"comparison": {"value": op}, "str": s}}


def _negated(key, spec, desc):
    (kind, value), = spec.items()
    if kind == "equals":
        return _leaf(key, "!=", value, False, desc)
    pat = {"startswith": "^" + re.escape(value), "endswith": re.escape(value) + "$",
           "contains": re.escape(value), "regex": value}[kind]
    return _leaf(key, "!=", pat, True, desc)


def exclusion_node(e):
    desc = f"hawk_filter:{e['tier']}:{e['name']}"
    conds = [_negated(k, v, desc) for k, v in e["match"].items()]
    node = conds[0] if len(conds) == 1 else {"id": "or", "key": "Or", "children": conds}
    if e["tier"] == "customer":
        outside = {"id": "and", "key": "And",
                   "children": [_leaf("group_name", "!=", g, False, desc) for g in e["_groups"]]}
        kids = node["children"] if node.get("key") == "Or" else [node]
        node = {"id": "or", "key": "Or", "children": [outside] + kids}
    return node


def apply_filters(hawk_id, rules, filters):
    ex = filters.get(str(hawk_id).lower())
    if not ex:
        return rules
    rules = copy.deepcopy(json.loads(rules) if isinstance(rules, str) else rules)
    nodes = [exclusion_node(e) for e in ex]
    top = rules[0] if isinstance(rules, list) else rules
    if str(top.get("key", "")).lower() != "and":
        top = {"id": "and", "key": "And", "children": [top]}
    kids = top.setdefault("children", [])
    first_fn = next((i for i, c in enumerate(kids) if c.get("class") == "function"), len(kids))
    top["children"] = kids[:first_fn] + nodes + kids[first_fn:]
    return [top] if isinstance(rules, list) else top
