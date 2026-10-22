"""Keep HAWK agent firmware lines out of the generic scores; firmware is scored only by the
known-bad firmware rules (BYOVD hash 6c1f4b8e, dbx rollback, boot_tamper story, unsafe BCD flags).

Adds `payload != regex 'HAWKFirmware: '` to each target score. The payload leaf covers both
parsed lines (HID102xx, product Agent / key HAWKFW) and lines from engines without the
sl_hawk_firmware parser (H0000, NLP-labelled e.g. 'Possible Worm/Trojan Activity').
2026-10-22: dbx_size:23455 inventory scored +20..+43 from the legacy malware scores and opened cases.

    python exclude_firmware_generic.py            # dry run + local engine check
    python exclude_firmware_generic.py --execute  # post + verify
"""
import copy, datetime, json, sys, uuid
import requests, urllib3
sys.path.insert(0, r"C:\Users\tshel\source\repos\pySigma-backend-hawk\converter_validation")
from disable_scores import BASE, api_key, row_to_form
import local_eval

_leaf = local_eval.leaf
local_eval.leaf = lambda n, d: True if (n.get("class") == "function" and n.get("key") != "empty") else _leaf(n, d)
node = local_eval.node
urllib3.disable_warnings(); sys.stdout.reconfigure(encoding="utf-8")

# legacy malware family (alerts_type 'Possible Worm/Trojan Activity'), priority tiers, destination-port count
TARGETS = [43, 44, 45, 46, 47, 63, 76, 83, 132, 176, 445, 851,
           89, 91, 92, 93, 97, 98, 128, 136,
           10]
PAT = "HAWKFirmware: "
COND = {"return": "str", "description": "Payload", "args": {"comparison": {"value": "!="}, "str": {"value": PAT, "regex": True}},
        "class": "column", "key": "payload"}
NOTE = ("%s: payload != 'HAWKFirmware: ' - agent firmware lines are scored only by the known-bad firmware rules "
        "(BYOVD known hash, dbx rollback, boot_tamper story, unsafe BCD flags); inventory lines like dbx_size were "
        "opening cases through this generic score" % datetime.date.today())


def has_cond(r):
    def walk(n):
        if isinstance(n, list):
            for c in n:
                yield from walk(c)
        elif isinstance(n, dict):
            yield n
            yield from walk(n.get("children") or [])
    return any(l.get("key") == "payload" and (l.get("args") or {}).get("str", {}).get("value") == PAT for l in walk(r["rules"]))


def patched(r):
    r2 = copy.deepcopy(r)
    top = r2["rules"][0]
    assert str(top.get("key") or top.get("id")).lower() == "and", r["score_id"]
    top["children"].append(dict(COND, rule_id=str(uuid.uuid4())))
    r2["comments"] = NOTE + ("\n" + r["comments"] if r.get("comments") else "")
    return r2


def load(fn):
    out = []
    for x in json.load(open(fn, encoding="utf-8")):
        x = x.get("_source", x)
        out.append(x)
    return out


def main():
    seen, fw = set(), []
    for fn in ("fw_1d.json", "fw_worm.json", "fw_h0000.json", "fw_dbx.json"):
        for e in load(fn):
            if e.get("event_id") not in seen:
                seen.add(e.get("event_id")); fw.append(e)
    other = load("reg_1d.json")
    for fn in ("case_624_5215.json", "case_627_3976.json", "case_623_3541.json"):
        other += [e for e in json.load(open(fn, encoding="utf-8"))["events"] if "HAWKFirmware" not in str(e.get("payload"))]
    s = requests.Session(); s.headers["Authorization"] = "Bearer " + api_key()
    rows = {x["score_id"]: x for x in s.get(BASE + "scores?recursive=true&format=json", timeout=600, verify=False).json()["results"]}
    for r in rows.values():
        if isinstance(r.get("rules"), str):
            r["rules"] = json.loads(r["rules"])
    todo = [rows[i] for i in TARGETS if rows[i]["enabled"] and not has_cond(rows[i])]
    print("firmware events:", len(fw), "| control (non-firmware) events:", len(other), "| scores to patch:", len(todo))
    ok = True
    for r in todo:
        p = patched(r)
        t0, t1 = r["rules"][0], p["rules"][0]
        fb = sum(bool(node(t0, e)) for e in fw); fa = sum(bool(node(t1, e)) for e in fw)
        ob = sum(bool(node(t0, e)) for e in other); oa = sum(bool(node(t1, e)) for e in other)
        good = fa == 0 and oa == ob
        ok &= good
        print("%-6s %-9s %-5s %-55s firmware %5d -> %-4d other %5d -> %-5d %s" % (r["score_id"], r["actions_category_name"], r["correlation_action"], r["filter_name"][:55], fb, fa, ob, oa, "ok" if good else "CHECK"))
    if "--execute" not in sys.argv or not ok:
        print("dry run" if ok else "NOT pushing: a check failed"); return
    for r in todo:
        resp = s.post(BASE + "scores/%s" % r["score_id"], data=row_to_form(patched(r), True), timeout=300, verify=False)
        print("POST", r["score_id"], resp.status_code, resp.text[:90])
    rows = {x["score_id"]: x for x in s.get(BASE + "scores?recursive=true&format=json", timeout=600, verify=False).json()["results"]}
    for r in todo:
        lv = rows[r["score_id"]]
        t = json.loads(lv["rules"]) if isinstance(lv["rules"], str) else lv["rules"]
        print("VERIFY", r["score_id"], "enabled", lv.get("enabled"), "weight", lv.get("correlation_action"),
              "firmware still matching:", sum(bool(node(t[0], e)) for e in fw), "| control:", sum(bool(node(t[0], e)) for e in other))


main()
