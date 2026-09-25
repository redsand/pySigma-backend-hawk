"""Regression tests for the 2026-09-25 converter fixes.

Each test pins a behaviour that was verified against the live hawk-ece engine and the
normalized event stream (see converter_validation/).
"""
import textwrap

NL = chr(10)

from sigma.backends.hawk import hawkBackend
from sigma.collection import SigmaCollection
from sigma.pipelines.hawk import hawk_pipeline


def _rule(detection: str, logsource: str = "product: windows|category: process_creation", tags: str = "") -> str:
    """Assemble a minimal Sigma rule. `logsource` uses | between lines; blocks are dedented."""
    ls_lines = NL.join("    " + part.strip() for part in logsource.split("|") if part.strip())
    det_lines = NL.join("    " + line for line in textwrap.dedent(detection).strip(NL).split(NL))
    doc = (
        "title: Test" + NL
        + "id: 11111111-2222-3333-4444-555555555555" + NL
        + "status: test" + NL
        + "level: high" + NL
        + "logsource:" + NL + ls_lines + NL
        + "detection:" + NL + det_lines + NL
    )
    if tags:
        tag_lines = NL.join("    " + line.strip() for line in textwrap.dedent(tags).split(NL) if line.strip())
        doc += "tags:" + NL + tag_lines + NL
    return doc

def _convert(rule_yaml: str, pipeline: bool = False) -> dict:
    backend = hawkBackend(processing_pipeline=hawk_pipeline()) if pipeline else hawkBackend()
    out = backend.convert(SigmaCollection.from_yaml(rule_yaml))
    assert len(out) == 1
    return out[0]


def _leaves(node) -> list:
    if isinstance(node, list):
        return [leaf for child in node for leaf in _leaves(child)]
    if not isinstance(node, dict):
        return []
    if node.get("class") in ("column", "function"):
        return [node]
    return [leaf for child in node.get("children", []) for leaf in _leaves(child)]


def _leaf(record: dict, key: str) -> dict:
    hits = [leaf for leaf in _leaves(record["rules"]) if leaf.get("key") == key]
    assert hits, f"no leaf for {key}: {[l.get('key') for l in _leaves(record['rules'])]}"
    return hits[0]


def _str_arg(leaf: dict) -> dict:
    return leaf["args"]["str"]


def test_regex_modifier_is_not_reescaped() -> None:
    rec = _convert(_rule("""
        selection:
            CommandLine|re: '^a.*b$'
        condition: selection
    """))
    arg = _str_arg(_leaf(rec, "command"))
    assert arg["value"] == "^a.*b$"
    assert arg["regex"] is True


def test_wildcard_forms_anchor_correctly() -> None:
    rec = _convert(_rule("""
        selection:
            CommandLine|contains: 'foo bar'
            Image|endswith: '\\cmd.exe'
            ParentImage|startswith: 'C:\\Windows'
            OriginalFileName: 'a*b'
        condition: selection
    """))
    assert _str_arg(_leaf(rec, "command"))["value"] == ".*foo\\ bar.*"
    assert _str_arg(_leaf(rec, "image"))["value"] == "\\\\cmd\\.exe$"
    assert _str_arg(_leaf(rec, "parent_image"))["value"] == "^C:\\\\Windows"
    # wildcard in the middle: whole-value match, not a floating substring
    assert _str_arg(_leaf(rec, "filename"))["value"] == "^a.*b$"


def test_single_char_wildcard_and_escaped_star() -> None:
    rec = _convert(_rule("""
        selection:
            CommandLine: 'a?b'
            Image: 'x\\*y'
        condition: selection
    """))
    assert _str_arg(_leaf(rec, "command")) == {"value": "^a.b$", "regex": True}
    # escaped star is a literal: exact match, no regex flag
    assert _str_arg(_leaf(rec, "image")) == {"value": "x*y"}


def test_plain_string_stays_exact_match() -> None:
    rec = _convert(_rule("""
        selection:
            Image: 'C:\\Windows\\System32\\cmd.exe'
        condition: selection
    """))
    assert _str_arg(_leaf(rec, "image")) == {"value": "C:\\Windows\\System32\\cmd.exe"}


def test_hash_contains_is_plain_value() -> None:
    rec = _convert(_rule("""
        selection:
            Hashes|contains: 'SHA256=ABCDEF0123456789'
        condition: selection
    """))
    leaf = _leaf(rec, "file_hash_sha256")
    assert _str_arg(leaf) == {"value": "ABCDEF0123456789"}


def test_keywords_use_substring_semantics() -> None:
    rec = _convert(_rule("""
        keywords:
            - 'mimikatz'
            - 'sekurlsa::*'
        condition: keywords
    """, logsource="product: windows\n    service: security"))
    values = {_str_arg(l)["value"] for l in _leaves(rec["rules"]) if l.get("key") == "payload"}
    assert values == {".*mimikatz.*", ".*sekurlsa::.*"}
    assert all(_str_arg(l)["regex"] for l in _leaves(rec["rules"]) if l.get("key") == "payload")


def test_cidr_emits_plain_network_value() -> None:
    rec = _convert(_rule("""
        selection:
            DestinationIp|cidr: '10.0.0.0/8'
        condition: selection
    """, logsource="product: windows\n    category: network_connection"))
    assert _str_arg(_leaf(rec, "ip_dst")) == {"value": "10.0.0.0/8"}


def test_exists_maps_to_empty_function() -> None:
    rec = _convert(_rule("""
        selection:
            CommandLine|exists: true
            ParentImage|exists: false
        condition: selection
    """))
    empties = [l for l in _leaves(rec["rules"]) if l.get("key") == "empty"]
    by_col = {l["args"]["column"]["value"]: l["args"]["comparison"]["value"] for l in empties}
    assert by_col == {"command": "!=", "parent_image": "="}


def test_cased_sets_case_flag() -> None:
    rec = _convert(_rule("""
        selection:
            CommandLine|cased: 'PowerShell'
        condition: selection
    """))
    assert _str_arg(_leaf(rec, "command")) == {"value": "PowerShell", "case": True}


def test_bool_values_are_strings_for_engine() -> None:
    rec = _convert(_rule("""
        selection:
            Blocked: true
        condition: selection
    """))
    leaf = _leaf(rec, "blocked")
    assert leaf["return"] == "bool"
    assert leaf["args"]["bool"]["value"] == "true"


def test_tactics_are_emitted_from_attack_tags() -> None:
    rec = _convert(_rule("""
        selection:
            CommandLine: 'x'
        condition: selection
    """, tags="- attack.execution\n- attack.t1059.001\n- attack.defense-evasion\n- attack.t1027"))
    ids = [t["tactic_id"] for t in rec["tactics"]]
    assert ids == ["TA0002", "TA0005"]
    assert rec["technique"] == "T1059.001"
    assert "T1027" in rec["tags"]


def test_windows_service_is_gated_on_event_channel_not_hawk_source() -> None:
    rec = _convert(_rule("""
        selection:
            EventID: 4624
        condition: selection
    """, logsource="product: windows\n    service: security"), pipeline=True)
    keys = [l.get("key") for l in _leaves(rec["rules"])]
    assert "hawk_source" not in keys
    chan = _leaf(rec, "event_channel")
    assert _str_arg(chan) == {"value": "Security"}
    sysmon = _convert(_rule("""
        selection:
            EventID: 1
        condition: selection
    """, logsource="product: windows\n    service: sysmon"), pipeline=True)
    assert _str_arg(_leaf(sysmon, "event_channel"))["value"] == "Microsoft-Windows-Sysmon/Operational"


def test_not_of_contains_inverts_comparison() -> None:
    rec = _convert(_rule("""
        selection:
            CommandLine|contains: 'foo'
        filter:
            Image|endswith: '\\safe.exe'
        condition: selection and not filter
    """))
    img = _leaf(rec, "image")
    assert img["args"]["comparison"]["value"] == "!="
    assert _str_arg(img)["value"] == "\\\\safe\\.exe$"
