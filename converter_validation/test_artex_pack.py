"""Replay the ARTEX pack's own single-event test cases against the scores we convert from it.

    python test_artex_pack.py <pack_dir> [converted.jsonl]

The pack's cases use Sigma field names; FIELDS renames them to the HAWK columns the converter
targets, so this proves the converted logic (regexes, escaping, numbers) still decides each case
the way the pack says. It does not prove a customer's events carry those columns: that is the
backtest. Cases for rules we do not convert, and correlation counts, are reported as not run.
"""
import itertools
import json
import re
import sys
from pathlib import Path

import yaml

from local_eval import node
from test_hawk_rules import strip_functions

HERE = Path(__file__).resolve().parent
FIELDS = {
    "cs-uri-stem": "http_path", "cs-uri-query": "http_query", "cs-user-agent": "http_user_agent",
    "sc-status": "http_status_code", "cs-method": "http_method", "c-ip": "ip_src", "cs-host": "http_host",
    "Image": "image", "CommandLine": "command", "ParentImage": "parent_image", "TargetFilename": "filename",
    "query": "dns_query",
    # directory audit, or the Azure Activity Log: whichever column the rule's source uses
    "OperationName": ("activityDisplayName", "azureOperationName"), "operationName": ("activityDisplayName", "azureOperationName"),
    "InitiatedBy": "correlation_username", "AppId": "appId", "IPAddress": "ipAddress", "ResultType": "errorCode",
    # AWS CloudTrail and Kubernetes audit, as the collector field maps name them
    "eventSource": "product_name", "sourceIPAddress": "ip_src",
    "userIdentity.type": "aws_auth_type", "verb": "http_method", "objectRef.resource": "object_type",
}
GATES = ("vendor_name", "product_name", "product_source", "vendor_id")


def gate_values(n, found):
    if isinstance(n, list):
        for c in n:
            gate_values(c, found)
    elif isinstance(n, dict):
        if n.get("class") == "column" and n.get("key") in GATES:
            args = n.get("args") or {}
            value = next((v.get("value") for k, v in args.items() if k != "comparison" and isinstance(v, dict)), None)
            found.setdefault(n["key"], set()).add(value)
        for c in n.get("children") or []:
            gate_values(c, found)


def columns(n, found):
    if isinstance(n, list):
        for c in n:
            columns(c, found)
    elif isinstance(n, dict):
        if n.get("class") == "column":
            found.add(n.get("key"))
        for c in n.get("children") or []:
            columns(c, found)


def main() -> int:
    pack = Path(sys.argv[1])
    conv = Path(sys.argv[2]) if len(sys.argv) > 2 else HERE / "reports" / "converted.jsonl"
    records = {}
    for line in conv.read_text(encoding="utf-8").splitlines():
        if line.strip():
            r = json.loads(line)
            records[r["hawk_id"].lower()] = r
    by_name, single = {}, {}
    for path in (pack / "sigma").rglob("*.yml"):
        for doc in yaml.safe_load_all(path.read_text(encoding="utf-8")):
            if not isinstance(doc, dict):
                continue
            if "detection" in doc:
                by_name[doc["name"]] = str(doc["id"]).lower()
            elif len(doc["correlation"]["rules"]) == 1:   # its record is that one rule plus a counter
                single[doc["correlation"]["rules"][0]] = str(doc["id"]).lower()
    ran = wrong = skipped = 0
    for path in sorted((pack / "tests").glob("sigma_events*.json")):
        for case in json.loads(path.read_text(encoding="utf-8")):
            name = case.get("rule")
            record = records.get(by_name.get(name, "")) or records.get(single.get(name, ""))
            if "event" not in case or record is None:
                skipped += 1
                continue
            logic = strip_functions(record["rules"])
            used = set()
            columns(logic, used)
            event = {}
            for key, value in case["event"].items():
                column = FIELDS.get(key, key)
                if isinstance(column, tuple):
                    column = next((c for c in column if c in used), column[0])
                # the collectors flatten vendor keys; the converter names them the same way
                snake = re.sub(r"(?<=[a-z0-9])([A-Z])", r"_\1", key).replace(".", "_").lower()
                for candidate in (column, snake, key.replace(".", "_"), key):
                    if candidate in used:
                        column = candidate
                        break
                event[column] = value
                if key == "TargetResources":   # one Sigma field the converter spreads over three columns
                    event.update(targetResourceName=value, modifiedPropertyNewValue=value)
            gates = {}
            gate_values(logic, gates)
            keys = sorted(k for k in gates if k not in event)   # a source the event names is not assumed
            combos = [dict(zip(keys, c)) for c in itertools.product(*(sorted(map(str, gates[k])) for k in keys))] or [{}]
            got = any(node(logic, dict(event, **g)) for g in combos)
            ran += 1
            if got != bool(case["expect"]):
                wrong += 1
                print("WRONG %s %s: expected %s, got %s\n      %s" % (path.name, name, case["expect"], got,
                                                                     json.dumps(case["event"])[:300]))
    print("ARTEX pack cases: %d run, %d wrong, %d not run (rule not converted, or a sequence/count case)" % (ran, wrong, skipped))
    return 1 if wrong or not ran else 0


if __name__ == "__main__":
    raise SystemExit(main())
