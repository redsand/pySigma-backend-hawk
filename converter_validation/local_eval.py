"""Evaluate score logic locally on sampled real events, with the engine's own leaf semantics.

Semantics (hawk-ece src/hawkcorr/hawk-correlation-rules.c, hawk-correlation.c, hawkcore
hawk-betree.c / hawk-regex.c; mapped 2026-10-05):
  * groups: "And"/"Or" (case-insensitive), children in order, short-circuit; no Not
  * missing column: "=" false, "!=" true (any comparison starting with "!" is !=)
  * str/ip return: value from args.str. If the value parses as an IP/CIDR -> IPv4 membership;
    else regex (PCRE, unanchored search, case-insensitive unless case:true); else
    string_contains -> case-insensitive substring; else case-insensitive whole-string equality
  * list column: "=" any element matches; "!=" any element does not match
  * int: event value strtol'd; float/double: numeric event values only (strings -> 0)
  * bool: "success"/"true"/true -> 1, else 0, compared to the event's boolean
  * function "empty": column missing/empty; with "!=" -> present. Other functions: unsupported.

    python local_eval.py --select reports/refresh_hold_all.txt   # old (live) vs new (converted)
Writes reports/local_eval.json. Rates are events/hour = sum over gated strata of
(stratum events/hour x matched/sampled).
"""
import argparse
import ipaddress
import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
SAMPLES = HERE / "live" / "samples"


class Unsupported(Exception):
    pass


_re_cache = {}


def _rx(pattern, case):
    k = (pattern, case)
    if k not in _re_cache:
        try:
            _re_cache[k] = re.compile(pattern, 0 if case else re.IGNORECASE)
        except re.error as e:
            raise Unsupported(f"regex: {e}") from e
    return _re_cache[k]


def _net(v):
    try:
        if "/" in v or re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", v):
            n = ipaddress.ip_network(v, strict=False)
            return n if n.version == 4 else None
    except ValueError:
        return None
    return None


def _truthy(v):
    if v in (None, ""):
        return False
    if isinstance(v, (list, dict)):
        return len(v) > 0
    return True


def _strtol(v):
    if isinstance(v, bool):
        return int(v)
    if isinstance(v, (int, float)):
        return int(v)
    m = re.match(r"\s*([+-]?\d+)", str(v))
    return int(m.group(1)) if m else 0


def _cmp(op, a, b):
    return {"=": a == b, ">": a > b, "<": a < b, ">=": a >= b, "<=": a <= b}.get(op, a == b)


def leaf(n, doc):
    args = n.get("args") or {}
    comp = str((args.get("comparison") or {}).get("value") or "=")
    neg = comp.startswith("!")
    if n.get("class") == "function":
        if n.get("key") != "empty":
            raise Unsupported(f"function {n.get('key')}")
        col = (args.get("column") or {}).get("value")
        empty = not _truthy(doc.get(col))
        return (not empty) if neg else empty
    key = n.get("key")
    val = doc.get(key)
    if val in (None, ""):
        return neg
    ret = str(n.get("return") or "str").lower()
    vals = val if isinstance(val, list) else [val]

    if ret in ("str", "string", "ip"):
        sa = args.get("str")
        if not isinstance(sa, dict) or sa.get("value") is None:
            return False
        pat = str(sa["value"])
        net = _net(pat)
        regex = sa.get("regex") in (True, "true")
        case = sa.get("case") in (True, "true")

        def one(x):
            x = str(x)
            if net is not None:
                try:
                    return ipaddress.ip_address(x) in net
                except ValueError:
                    return False
            if regex:
                return _rx(pat, case).search(x) is not None
            if args.get("string_contains") in (True, "true") or sa.get("string_contains") in (True, "true"):
                return pat.lower() in x.lower()
            return x.lower() == pat.lower()
        if neg:
            return any(not one(x) for x in vals)
        return any(one(x) for x in vals)

    if ret in ("int", "integer", "unsigned integer"):
        a = args.get("int") or args.get("integer") or {}
        b = _strtol(a.get("value"))
        op = comp.lstrip("!") or "="
        res = any(_cmp(op, _strtol(x), b) for x in vals)
        return (not res) if neg and op == "=" else res
    if ret in ("float", "double"):
        a = args.get("float") or args.get("double") or {}
        try:
            b = float(a.get("value"))
        except (TypeError, ValueError):
            b = 0.0
        op = comp.lstrip("!") or "="
        res = any(_cmp(op, float(x) if isinstance(x, (int, float)) and not isinstance(x, bool) else 0.0, b) for x in vals)
        return (not res) if neg and op == "=" else res
    if ret in ("bool", "boolean"):
        a = (args.get("bool") or {}).get("value")
        want = 1 if a in (True, "true", "success") or str(a).lower().startswith("suc") else 0
        have = 1 if (val is True or str(val).lower().startswith("suc") or str(val).lower() == "true") else 0
        return (want != have) if neg else (want == have)
    raise Unsupported(f"return {ret}")


def node(n, doc):
    if isinstance(n, list):
        return all(node(c, doc) for c in n)
    if n.get("class") in ("column", "function"):
        return leaf(n, doc)
    k = str(n.get("key") or n.get("id") or "").lower()
    kids = n.get("children") or []
    if k == "or":
        return any(node(c, doc) for c in kids)
    return all(node(c, doc) for c in kids)


def load_meta():
    return json.loads((SAMPLES / "strata.json").read_text(encoding="utf-8"))["strata"]


def iter_docs(nm):
    p = SAMPLES / f"{nm}.jsonl"
    if p.exists():
        with p.open(encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    yield json.loads(line)


def gated(rules, strata):
    """Strata a score's gate covers (exact stratum names). Ungated logic -> every stratum,
    using a whole-product sample instead of its per-event-ID samples to avoid double counting."""
    from sample_strata import strata_for, name
    st = {name(x) for x in strata_for(rules)}
    if st:
        return [k for k in strata if k in st], True
    whole = {m["product_name"] for m in strata.values() if m["vendor_id"] == "*"}
    return [k for k, m in strata.items() if m["vendor_id"] == "*" or m["product_name"] not in whole], False


def main() -> int:
    """One stratum in memory at a time: for each stratum, every (score, old/new) logic that
    covers it is evaluated on that stratum's events, then the events are released."""
    ap = argparse.ArgumentParser()
    ap.add_argument("--select", required=True)
    args = ap.parse_args()
    strata = load_meta()
    live = {str(x.get("hawk_id")).lower(): x for x in json.loads((HERE / "live" / "scores_now.json").read_text(encoding="utf-8")) if x.get("hawk_id")}
    conv = {json.loads(l)["hawk_id"].lower(): json.loads(l) for l in (HERE / "reports" / "converted.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()}
    ids = [l.strip().lower() for l in Path(args.select).read_text(encoding="utf-8").splitlines() if l.strip()]
    entries, work = {}, []   # work: (hawk_id, tag, rules, strata covered)
    for h in ids:
        e = entries[h] = {"hawk_id": h, "score_id": live.get(h, {}).get("score_id"), "title": live.get(h, {}).get("filter_name"),
                          "enabled": bool(live.get(h, {}).get("enabled")), "weight": float(live.get(h, {}).get("correlation_action") or 0)}
        for tag, rules in (("old", live.get(h, {}).get("rules")), ("new", conv.get(h, {}).get("rules"))):
            if not rules:
                continue
            rules = json.loads(rules) if isinstance(rules, str) else rules
            cov, has_gate = gated(rules, strata)
            e[f"{tag}_per_h"], e[f"{tag}_gated"] = 0.0, has_gate
            e[f"{tag}_unsampled"] = [k for k in cov if not strata[k].get("sampled") and strata[k]["per_hour"] > 0]
            work.append((h, tag, rules, set(cov)))
    sampled = 0
    for k, meta in strata.items():
        todo = [w for w in work if k in w[3] and entries[w[0]].get(f"{w[1]}_error") is None]
        if not todo or not meta.get("sampled"):
            continue
        hits, n = [0] * len(todo), 0
        for doc in iter_docs(k):
            n += 1
            for i, (h, tag, rules, _) in enumerate(todo):
                if entries[h].get(f"{tag}_error"):
                    continue
                try:
                    if node(rules, doc):
                        hits[i] += 1
                except Unsupported as ex:
                    entries[h][f"{tag}_error"] = str(ex)
        sampled += n
        for i, (h, tag, _, _) in enumerate(todo):
            if n and not entries[h].get(f"{tag}_error"):
                entries[h][f"{tag}_per_h"] += meta["per_hour"] * hits[i] / n
        print(f"{k:<45} {n:>6} events, {len(todo)} logics", flush=True)
    for e in entries.values():
        for tag in ("old", "new"):
            if e.get(f"{tag}_error"):
                e[f"{tag}_per_h"] = None
            elif f"{tag}_per_h" in e:
                e[f"{tag}_per_h"] = round(e[f"{tag}_per_h"], 2)
    (HERE / "reports" / "local_eval.json").write_text(json.dumps(list(entries.values()), indent=1), encoding="utf-8")
    print(f"evaluated {len(entries)} scores on {sampled} sampled events in {len(strata)} strata")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
