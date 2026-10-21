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


def not_leaf(key, desc, value, regex=True):
    n = leaf(key, desc, value, regex)
    n["args"]["comparison"]["value"] = "!="
    n["rule_id"] = str(uuid.uuid5(uuid.NAMESPACE_URL, f"hawk-custom/not/{key}/{value}"))
    return n


NESSUS_DIR = r"\\ProgramData\\Tenable\\Nessus Agent\\nessus\\mod\\"

# HAWK vTTAC YARA matches (product HAWK-vTTAC-YARA, event 1001). Agents 3.0.9+ add
# Signature / SignatureStatus (Sysmon vocabulary) for the matched file; HID10236 events carry
# the rule in threat_name, HID0000 (newer payload) in rule_name. Same family list as
# hawk-sigma-rules rules/yara/hawk_yara_high_impact_family.yml.
YARA_HIGH_IMPACT = (r"(?i)(ransom|webshell|web_shell|cobalt_?strike|beacon|sliver|mimikatz|meterpreter|"
                    r"brute_?ratel|havoc|lockbit|blackcat|alphv|conti|ryuk|akira)")
YARA_BASE = [leaf("product_name", "Product Name", "HAWK-vTTAC-YARA", regex=False),
             leaf("vendor_id", "Vendor ID", "1001", regex=False)]
NOT_CODE_INTEGRITY = [not_leaf("scan_context", "Scan Context", "code_integrity", regex=False),
                      not_leaf("rule_type", "Rule Type", "code_integrity", regex=False)]
S1_STATIC_ENGINE_DLL = (r"^C:\\(ProgramData\\Sentinel|Program Files\\SentinelOne\\Sentinel Agent [0-9.]+)"
                        r"\\StaticEngineLibrary\\[^\\]+\\SentinelStaticAI\.dll$")
MALPEDIA_AUTO = r"^MALPEDIA_[A-Za-z0-9_]+_Auto$"
PROGRAM_FILES = r"^C:\\Program Files( \(x86\))?\\"
CLAUDE_APP_EXE = r"^C:\\Users\\[^\\]+\\AppData\\Local\\AnthropicClaude\\(app-[0-9.]+\\)?claude\.exe$"

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
    # Low tier: a YARA match on a file whose Authenticode signature verified (Valid) is far more
    # often a broad rule hitting a vendor binary than malware - 2026-10-20 CAPE_Hijackloaderstub on
    # Anthropic claude.exe (Anthropic, PBC / Valid) and MALPEDIA_Win_Snake_Disk_Auto on Adobe
    # AcroTray.exe. Sized to cancel the path tiers (user-writable +15, outside install dirs +15).
    # High-impact family names keep their score even when signed (stolen/abused certificates).
    "HAWK-YARA-SIGNED-VALID": {
        "hawk_id": "HAWK-YARA-SIGNED-VALID",
        "filter_name": "HAWK - Reduce YARA Match On A Validly Signed File",
        "filter_details": ("Demotes a HAWK vTTAC YARA match whose file carries a verified Authenticode signature "
                           "(SignatureStatus Valid, agents 3.0.9+), unless the rule name is a high-impact family "
                           "(ransomware, webshell, C2 frameworks, credential dumpers)."),
        "actions_category_name": "Subtract (-)",
        "correlation_action": 30,
        "references": "",
        "comments": "Hand-authored 2026-10-20 (YARA tiering: low tier). Cases from CAPE_Hijackloaderstub on claude.exe.",
        "tags": ["hawk-custom", "noise-reduction", "yara"],
        "rules": [{
            "id": "and", "key": "And", "selected": "selected",
            "children": YARA_BASE + [
                leaf("signature_status", "Signature Status", "Valid", regex=False),
                not_leaf("rule_name", "Rule Name", YARA_HIGH_IMPACT),
                not_leaf("threat_name", "Threat Name", YARA_HIGH_IMPACT),
            ],
        }],
    },
    # Known false positive, scored down until the YARA package fix ships (hawkagentd
    # HAWK_CAPE_Hijackloaderstub_NoLargeApps): CAPE_Hijackloaderstub matches the Claude desktop app
    # (Squirrel install, AppData\Local\AnthropicClaude\claude.exe) through its wide "\app-" string.
    # 2026-10-07..21: 82 hits, 14 hosts, every version 2.26454 - 3.1623, nothing else matched the rule.
    # Path changes with no version, so it is path-pinned, not hash-pinned. Sized past the largest
    # observed sum (HID10236 parse: path tiers 30 + legacy malware scores 45 = 76). Agents 3.0.9+ that
    # report a signature must report Valid (an unsigned claude.exe on a new agent keeps its score).
    "HAWK-YARA-CAPE-HIJACKLOADER-CLAUDE-APP": {
        "hawk_id": "HAWK-YARA-CAPE-HIJACKLOADER-CLAUDE-APP",
        "filter_name": "HAWK - Reduce YARA CAPE_Hijackloaderstub Match On The Claude Desktop App",
        "filter_details": ("Demotes the CAPE_Hijackloaderstub YARA rule matching the Claude desktop app "
                           "(C:\\Users\\<user>\\AppData\\Local\\AnthropicClaude\\claude.exe or its app-<version> copy). "
                           "Known false positive on the Squirrel installer layout; when the agent reports a "
                           "signature it must be Valid."),
        "actions_category_name": "Subtract (-)",
        "correlation_action": 80,
        "references": "",
        "comments": "Hand-authored 2026-10-21 (short-term analytic fix ahead of the YARA package change).",
        "tags": ["hawk-custom", "noise-reduction", "yara"],
        "rules": [{
            "id": "and", "key": "And", "selected": "selected",
            "children": YARA_BASE + [
                {"id": "or", "key": "Or", "children": [
                    leaf("rule_name", "Rule Name", "CAPE_Hijackloaderstub", regex=False),
                    leaf("threat_name", "Threat Name", "CAPE_Hijackloaderstub", regex=False),
                ]},
                {"id": "or", "key": "Or", "children": [
                    leaf("filename", "Filename", CLAUDE_APP_EXE),
                    leaf("file_path", "File Path", CLAUDE_APP_EXE),
                ]},
                {"id": "or", "key": "Or", "children": [
                    leaf("signature_status", "Signature Status", "Valid", regex=False),
                    not_leaf("signature_status", "Signature Status", "."),  # older agents: not reported
                ]},
            ],
        }],
    },
    # SentinelOne's static AI engine library carries detection patterns for the families it
    # finds, so YARA-Forge rules match it each time SentinelOne rewrites it (fim_change) or loads
    # it: 2026-10-07..21, 691 hits on 53 hosts, SIGNATURE_BASE_SUSP_Xored_Mozilla_Oct19 and
    # SIGNATURE_BASE_Reflectiveloader, under both ProgramData\Sentinel\StaticEngineLibrary\StaticAILib_<n>\
    # and Program Files\SentinelOne\Sentinel Agent <ver>\StaticEngineLibrary\StaticEngineMain\.
    # High-impact family names keep their score; on agents that report a signature it must be Valid.
    "HAWK-YARA-SENTINELONE-STATIC-ENGINE": {
        "hawk_id": "HAWK-YARA-SENTINELONE-STATIC-ENGINE",
        "filter_name": "HAWK - Reduce YARA Match On The SentinelOne Static AI Engine Library",
        "filter_details": ("Demotes a HAWK vTTAC YARA match on SentinelStaticAI.dll in SentinelOne's StaticEngineLibrary "
                           "(C:\\ProgramData\\Sentinel\\ or C:\\Program Files\\SentinelOne\\Sentinel Agent <version>\\). "
                           "The engine embeds malware patterns. Ransomware, webshell and C2 rule names are kept."),
        "actions_category_name": "Subtract (-)",
        "correlation_action": 80,
        "references": "",
        "comments": "Hand-authored 2026-10-21. Sized past the HID10236 sum (YARA tiers 30 + legacy malware scores 45).",
        "tags": ["hawk-custom", "noise-reduction", "yara", "sentinelone"],
        "rules": [{
            "id": "and", "key": "And", "selected": "selected",
            "children": YARA_BASE + [
                {"id": "or", "key": "Or", "children": [
                    leaf("filename", "Filename", S1_STATIC_ENGINE_DLL),
                    leaf("file_path", "File Path", S1_STATIC_ENGINE_DLL),
                ]},
                not_leaf("rule_name", "Rule Name", YARA_HIGH_IMPACT),
                not_leaf("threat_name", "Threat Name", YARA_HIGH_IMPACT),
                {"id": "or", "key": "Or", "children": [
                    leaf("signature_status", "Signature Status", "Valid", regex=False),
                    not_leaf("signature_status", "Signature Status", "."),
                ]},
            ],
        }],
    },
    # MALPEDIA_*_Auto rules are generated by yara-signator from code similarity, not written by an
    # analyst, and match vendor binaries that share library code: 2026-10-20..21
    # MALPEDIA_Win_Snake_Disk_Auto matched Adobe Acrobat acrotray.exe (and PDFMaker add-ins) 1,000x
    # on 359 hosts. On HID10236-parsed events the legacy antivirus scores add 23-48, so every Acrobat
    # start became a case. Scope: files under C:\Program Files[ (x86)]\ (admin-writable only);
    # high-impact family names keep their score; agents that report a signature must report Valid.
    "HAWK-YARA-AUTO-RULE-PROGRAM-FILES": {
        "hawk_id": "HAWK-YARA-AUTO-RULE-PROGRAM-FILES",
        "filter_name": "HAWK - Reduce Auto-Generated MALPEDIA YARA Match On A File In Program Files",
        "filter_details": ("Demotes a HAWK vTTAC YARA match from an auto-generated MALPEDIA_*_Auto rule (yara-signator) on a "
                           "file under C:\\Program Files\\ or C:\\Program Files (x86)\\. Ransomware, webshell and C2 rule "
                           "names keep their score; on agents 3.0.9+ the file must be validly signed."),
        "actions_category_name": "Subtract (-)",
        "correlation_action": 50,
        "references": "https://github.com/danielplohmann/yara-signator",
        "comments": "Hand-authored 2026-10-21. Sized past the largest observed sum (48: legacy AV scores 45 + YARA tiers).",
        "tags": ["hawk-custom", "noise-reduction", "yara"],
        "rules": [{
            "id": "and", "key": "And", "selected": "selected",
            "children": YARA_BASE + NOT_CODE_INTEGRITY + [
                {"id": "or", "key": "Or", "children": [
                    leaf("rule_name", "Rule Name", MALPEDIA_AUTO),
                    leaf("threat_name", "Threat Name", MALPEDIA_AUTO),
                ]},
                {"id": "or", "key": "Or", "children": [
                    leaf("filename", "Filename", PROGRAM_FILES),
                    leaf("file_path", "File Path", PROGRAM_FILES),
                ]},
                not_leaf("rule_name", "Rule Name", YARA_HIGH_IMPACT),
                not_leaf("threat_name", "Threat Name", YARA_HIGH_IMPACT),
                {"id": "or", "key": "Or", "children": [
                    leaf("signature_status", "Signature Status", "Valid", regex=False),
                    not_leaf("signature_status", "Signature Status", "."),
                ]},
            ],
        }],
    },
    # The agent's byovd_driver_loaded finding fires on the driver file NAME (LOLDrivers list).
    # Agents before hawkagentd 4f1611c send every one as severity=ALERT; 2026-10-14..21: 208
    # events on 87 hosts (afd.sys, csc.sys, DellInstrumentation.sys, RtsPer.sys, KslD.sys), all
    # Priority 1, weight 33.5-56.5 from the legacy malware scores - and not one SHA-256 was a
    # known vulnerable build. This takes every finding back to ~0; the Sigma rule
    # hawk-sigma-rules rules/firmware/hawk_firmware_byovd_known_vulnerable_build.yml (6c1f4b8e,
    # ledger weight 60) adds the weight back when the hash is a known vulnerable/malicious build.
    "HAWK-FIRMWARE-BYOVD-NAME-MATCH": {
        "hawk_id": "HAWK-FIRMWARE-BYOVD-NAME-MATCH",
        "filter_name": "HAWK - Reduce Firmware BYOVD Finding On Driver Name Only",
        "filter_details": ("Demotes every HAWK agent byovd_driver_loaded finding: the agent matches the driver file name, "
                           "which on most hosts is the fixed vendor build. The known-vulnerable-build Sigma rule "
                           "(hash in LOLDrivers KnownVulnerableSamples) restores the weight for a confirmed build."),
        "actions_category_name": "Subtract (-)",
        "correlation_action": 55,
        "references": "https://www.loldrivers.io/",
        "comments": "Hand-authored 2026-10-21. Pairs with Sigma rule 6c1f4b8e-2d7a-4e93-9b5c-8a0e3f71d2c4 (weight 60).",
        "tags": ["hawk-custom", "noise-reduction", "firmware", "byovd"],
        "rules": [{
            "id": "and", "key": "And", "selected": "selected",
            "children": [
                leaf("product_name", "Product Name", "Agent", regex=False),
                leaf("key", "Key", "HAWKFW", regex=False),
                leaf("threat_name", "Threat Name", "byovd_driver_loaded", regex=False),
            ],
        }],
    },
    # GuardDuty re-sends a finding each time its count grows. Recon:EC2/PortProbeUnprotectedPort at
    # LOW severity (1.0-3.9) on an internet-facing instance is the background scanning of the
    # internet (Shadowserver, DigitalOcean/Linode VPSs); 2026-10-21 the same finding first seen
    # 2023-06-07 (Service_Count 11,632) raised a case on every update. A new finding (first report)
    # or any MEDIUM/HIGH severity, or any other finding type, keeps its score.
    "HAWK-GUARDDUTY-LOW-PORTPROBE-UPDATE": {
        "hawk_id": "HAWK-GUARDDUTY-LOW-PORTPROBE-UPDATE",
        "filter_name": "HAWK - Reduce GuardDuty Low-Severity Port Probe Finding Update",
        "filter_details": ("Demotes Amazon GuardDuty Recon:EC2/PortProbeUnprotectedPort / PortProbeEMRUnprotectedPort "
                           "findings of LOW severity (below 4.0) that are updates of an existing finding."),
        "actions_category_name": "Subtract (-)",
        "correlation_action": 20,
        "references": "https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html",
        "comments": "Hand-authored 2026-10-21 (case review: GuardDuty theme 43 of 601 cases in 24h).",
        "tags": ["hawk-custom", "noise-reduction", "aws", "guardduty"],
        "rules": [{
            "id": "and", "key": "And", "selected": "selected",
            "children": [
                leaf("product_name", "Product Name", "Amazon Guard Duty", regex=False),
                leaf("Type", "Type", r"^Recon:EC2/PortProbe(EMR)?UnprotectedPort$"),
                leaf("Severity", "Severity", r"^[0-3](\.[0-9]+)?$"),
                leaf("finding_is_update", "Finding Is Update", "1", regex=False),
            ],
        }],
    },
    # High tier boost: the rule's own severity (from its score meta, hawk-yara-severity.h:
    # >= 80 high, >= 90 critical) on a file that is not validly signed (unsigned, invalid, or an
    # agent older than 3.0.9 that does not report it). Code Integrity propagations excluded.
    "HAWK-YARA-HIGH-SEVERITY-UNSIGNED": {
        "hawk_id": "HAWK-YARA-HIGH-SEVERITY-UNSIGNED",
        "filter_name": "HAWK - YARA Match From A High-Severity Rule On A File Not Validly Signed",
        "filter_details": ("HAWK vTTAC YARA match whose rule maps to severity high/critical (Severity 3-4) on a file "
                           "without a verified signature. Code Integrity propagations are excluded."),
        "actions_category_name": "Add (+)",
        "correlation_action": 10,
        "references": "",
        "comments": "Hand-authored 2026-10-20 (YARA tiering: high tier boost).",
        "tags": ["hawk-custom", "yara"],
        "rules": [{
            "id": "and", "key": "And", "selected": "selected",
            "children": YARA_BASE + NOT_CODE_INTEGRITY + [
                leaf("severity", "Severity", r"^[34]$"),
                not_leaf("signature_status", "Signature Status", "Valid", regex=False),
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
