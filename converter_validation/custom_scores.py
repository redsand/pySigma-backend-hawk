"""Hand-authored (non-Sigma) HAWK scores, pushed with the same upsert path as
sync_scores.py (insert-or-update by hawk_id; new rows land enabled=false).

Usage:
    python custom_scores.py --id HAWK-TENABLE-NESSUS-AGENT-PLUGIN            # dry run: print the form
    python custom_scores.py --id HAWK-TENABLE-NESSUS-AGENT-PLUGIN --execute  # push + verify
"""
import argparse
import json
import uuid

import requests
import urllib3

from sync_scores import BASE, api_key, fetch_live, push, to_form

urllib3.disable_warnings()


def leaf(key, desc, value, regex=True, ret="string"):
    return {
        "key": key, "description": desc, "class": "column", "return": ret,
        "args": {"comparison": {"value": "="}, "str": {"value": value, **({"regex": "true"} if regex else {})}},
        "rule_id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"hawk-custom/{key}/{value}")),
    }


NESSUS_DIR = r"\\ProgramData\\Tenable\\Nessus Agent\\nessus\\mod\\"

SCORES = {
    # Tenable Nessus Agent plugins (e.g. the inline-PowerShell software inventory
    # 'sajb {... $fileInclude ...}') run cmd.exe/powershell.exe as SYSTEM from the
    # agent's plugin directory, spawned by nessus-agent-module.exe. The older
    # customer scores 386/64673 only match '\TEMP\nessus_*' command lines, which the
    # current agent no longer uses — these scans raised PowerShell/obfuscation
    # analytics and became cases (#619:3891, #632:2239, #617:2825, 2026-09-30).
    # Directory spoofing alone does not pass: System integrity is required.
    "HAWK-TENABLE-NESSUS-AGENT-PLUGIN": {
        "hawk_id": "HAWK-TENABLE-NESSUS-AGENT-PLUGIN",
        "filter_name": "Reduce Tenable Nessus Agent plugin execution (Nessus Agent working directory)",
        "filter_details": ("Demotes Sysmon process creation by the Tenable Nessus Agent: System-integrity "
                           "process whose working directory (path / current_directory / parent_current_directory) "
                           "is C:\\ProgramData\\Tenable\\Nessus Agent\\nessus\\mod\\ or whose parent is "
                           "nessus-agent-module.exe. Covers the inline PowerShell software-inventory plugin."),
        "actions_category_name": "Subtract (-)",
        "correlation_action": 50,
        "references": "https://docs.tenable.com/nessus-agent/",
        "comments": "Hand-authored 2026-09-30 (octorepl review of pending cases). Backtest 24h: >=2000 events, 30 hosts, "
                    "506 Sysmon EID1 all integrity=System user=SYSTEM.",
        "tags": ["hawk-custom", "noise-reduction", "tenable"],
        "rules": [{
            "id": "and", "key": "And", "selected": "selected",
            "children": [
                leaf("product_name", "Product Name", "Sysmon", regex=False),
                leaf("vendor_id", "Vendor ID", "1", regex=False),
                leaf("integrity_level", "Integrity Level", "System", regex=False),
                {"id": "or", "key": "Or", "children": [
                    leaf("path", "Path", NESSUS_DIR),
                    leaf("current_directory", "Current Directory", NESSUS_DIR),
                    leaf("parent_current_directory", "Parent Current Directory", NESSUS_DIR),
                    leaf("parent_image", "Parent Image", r"\\Tenable\\Nessus Agent\\nessus-agent-module\.exe$"),
                ]},
            ],
        }],
    },
}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--id", required=True, choices=sorted(SCORES))
    ap.add_argument("--group", default=".")
    ap.add_argument("--execute", action="store_true")
    args = ap.parse_args()
    rec = SCORES[args.id]

    s = requests.Session()
    s.headers["Authorization"] = "Bearer " + api_key()
    live = fetch_live(s)
    prev = live.get(args.id.lower(), {})
    prev_date = str(prev.get("date_added") or "")
    form = to_form(rec, args.group, prev_date if prev_date and not prev_date.startswith("1970") else "")
    form["actions_category_name"] = rec["actions_category_name"]  # to_form defaults to Add (+)
    print(("PUSH " if args.execute else "DRY  ") + json.dumps({k: v for k, v in form.items() if k != "rules"}, indent=1))
    print("rules:", form["rules"][:1500])
    print("exists live:", bool(prev), "enabled:", prev.get("enabled") if prev else None)
    if not args.execute:
        return 0
    print("result:", push(s, form))
    row = fetch_live(s).get(args.id.lower())
    print("VERIFY:", json.dumps({k: row.get(k) for k in ("score_id", "hawk_id", "filter_name", "actions_category_name",
                                                           "correlation_action", "enabled", "group_name")} if row else None))
    return 0 if row else 1


if __name__ == "__main__":
    raise SystemExit(main())
