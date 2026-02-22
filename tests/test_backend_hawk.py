from sigma.backends.hawk import hawkBackend
from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule


def _convert_one(rule_yaml: str) -> dict:
    backend = hawkBackend()
    out = backend.convert(SigmaCollection.from_yaml(rule_yaml))
    assert isinstance(out, list)
    assert len(out) == 1
    assert isinstance(out[0], dict)
    return out[0]


def _find_leaf(node, key: str) -> dict | None:
    """Walk a BETree node tree and return the first column leaf with the given key."""
    if isinstance(node, list):
        for child in node:
            result = _find_leaf(child, key)
            if result is not None:
                return result
        return None
    if not isinstance(node, dict):
        return None
    if node.get("class") == "column" and node.get("key") == key:
        return node
    for child in node.get("children", []):
        result = _find_leaf(child, key)
        if result is not None:
            return result
    return None


def _first_detection_leaf(rules: list) -> dict | None:
    """Return the first column leaf from the detection (non-enrichment) subtree.

    The BETree has the form:
      AND -> AND -> [enrichment_node..., AND(detection_children)]
    The detection AND is the last child of the inner AND.
    """
    ENRICHMENT_KEYS = {
        "vendor_name", "vendor_id", "product_name", "product_source",
        "vendor_type", "event_channel", "hawk_source",
    }
    if not rules or not isinstance(rules, list):
        return None
    outer = rules[0]
    inner_children = outer.get("children", [{}])[0].get("children", [])
    # Find the detection AND: the child that is not a plain column enrichment leaf
    for child in inner_children:
        if child.get("class") == "column" and child.get("key") in ENRICHMENT_KEYS:
            continue
        # This is the detection sub-node; return its first column leaf
        stack = [child]
        while stack:
            n = stack.pop()
            if isinstance(n, dict):
                if n.get("class") == "column":
                    return n
                for c in reversed(n.get("children", [])):
                    stack.append(c)
    return None


def test_wildcard_regex_is_boolean() -> None:
    result = _convert_one(
        """
title: Wildcard Rule
id: 11111111-1111-1111-1111-111111111111
status: stable
level: high
logsource:
  product: windows
  category: process_creation
detection:
  sel:
    CommandLine: foo*
  condition: sel
"""
    )
    leaf = _find_leaf(result["rules"], "command")
    assert leaf is not None, "command leaf not found"
    assert leaf["args"]["str"]["regex"] is True
    assert isinstance(leaf["args"]["str"]["regex"], bool)


def test_mitre_technique_and_tag_normalization() -> None:
    result = _convert_one(
        """
title: Mitre Rule
id: 22222222-2222-2222-2222-222222222222
status: stable
level: medium
tags:
  - attack.execution
  - attack.t1055.012
logsource:
  product: windows
  category: process_creation
detection:
  sel:
    Image: rundll32.exe
  condition: sel
"""
    )
    assert "sigma" in result["tags"]
    assert "attack.t1055.012" in result["tags"]
    assert "T1055.012" in result["tags"]
    assert result["technique"] == "T1055.012"


def test_legacy_equivalent_scoring() -> None:
    result = _convert_one(
        """
title: Score Rule
id: 33333333-3333-3333-3333-333333333333
status: stable
level: high
falsepositives:
  - expected admin usage
  - known test machine
logsource:
  product: windows
  category: process_creation
detection:
  sel:
    Image: cmd.exe
  condition: sel
"""
    )
    # Legacy score: base 5 + status 5 + high 10 - (2*2 false positives) = 16
    assert result["correlation_action"] == 16.0
    assert "Scoring:" in result["filter_details"]


def test_parent_commandline_maps_to_authoritative_column() -> None:
    result = _convert_one(
        """
title: Parent Command Mapping
id: 55555555-5555-5555-5555-555555555555
status: stable
level: low
logsource:
  product: windows
  category: process_creation
detection:
  sel:
    ParentCommandLine: '*powershell*'
  condition: sel
"""
    )
    leaf = _find_leaf(result["rules"], "parent_command")
    assert leaf is not None, "parent_command leaf not found"


def test_imagepath_maps_to_image() -> None:
    result = _convert_one(
        """
title: ImagePath Mapping
id: 66666666-6666-6666-6666-666666666666
status: stable
level: medium
logsource:
  product: windows
  category: process_creation
detection:
  sel:
    ImagePath: C:\\Windows\\System32\\cmd.exe
  condition: sel
"""
    )
    leaf = _find_leaf(result["rules"], "image")
    assert leaf is not None, "image leaf not found"


def test_originalfilename_maps_to_filename() -> None:
    result = _convert_one(
        """
title: OriginalFilename Mapping
id: 77777777-7777-7777-7777-777777777777
status: stable
level: medium
logsource:
  product: windows
  category: process_creation
detection:
  sel:
    OriginalFileName: rundll32.exe
  condition: sel
"""
    )
    leaf = _find_leaf(result["rules"], "filename")
    assert leaf is not None, "filename leaf not found"


def test_hashes_sha_alias_maps_to_sha1_column() -> None:
    result = _convert_one(
        """
title: Hash Alias Mapping
id: 88888888-8888-8888-8888-888888888888
status: stable
level: high
logsource:
  product: windows
  category: process_creation
detection:
  sel:
    Hashes: SHA=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  condition: sel
"""
    )
    leaf = _find_leaf(result["rules"], "file_hash_sha1")
    assert leaf is not None, "file_hash_sha1 leaf not found"
    assert leaf["args"]["str"]["value"] == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"


def test_hashes_sha512_maps_to_sha512_column() -> None:
    result = _convert_one(
        """
title: Hash SHA512 Mapping
id: 99999999-9999-9999-9999-999999999999
status: stable
level: high
logsource:
  product: windows
  category: process_creation
detection:
  sel:
    Hashes: SHA512=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
  condition: sel
"""
    )
    leaf = _find_leaf(result["rules"], "file_hash_sha512")
    assert leaf is not None, "file_hash_sha512 leaf not found"


def test_experimental_status_does_not_get_plus_five_and_sets_qa_tag() -> None:
    result = _convert_one(
        """
title: Experimental Score Rule
id: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
status: experimental
level: high
logsource:
  product: windows
  category: process_creation
detection:
  sel:
    Image: cmd.exe
  condition: sel
"""
    )
    # Legacy-equivalent: base 5 + high 10 + experimental bonus 0
    assert result["correlation_action"] == 15.0
    assert "qa" in result["tags"]


# ── Correlation rule tests ───────────────────────────────────────────────────

_BASE_DETECTION_YAML = """
title: Failed Logon Base
id: 11111111-1111-1111-1111-aaaaaaaaaaaa
name: failed_logon_base
status: stable
logsource:
  product: windows
  service: security
detection:
  sel:
    EventID: 4625
  condition: sel
"""

_CORRELATION_EVENT_COUNT_YAML = """
title: Multiple Failed Logons from Same Source IP
id: 22222222-2222-2222-2222-bbbbbbbbbbbb
name: multiple_failed_logons
status: stable
level: high
correlation:
  type: event_count
  rules: failed_logon_base
  group-by:
    - IpAddress
  timespan: 5m
  condition:
    gte: 10
"""

_CORRELATION_VALUE_COUNT_YAML = """
title: Multiple Usernames from Same Source IP
id: 33333333-3333-3333-3333-cccccccccccc
name: multi_user_same_src
status: stable
level: high
correlation:
  type: value_count
  rules: failed_logon_base
  group-by:
    - IpAddress
  timespan: 15m
  condition:
    field: User
    gte: 5
"""


def _convert_correlation(corr_yaml: str, base_yaml: str = _BASE_DETECTION_YAML) -> dict:
    """Convert a detection + correlation YAML pair; return the correlation output record."""
    backend = hawkBackend()
    collection = SigmaCollection.from_yaml(base_yaml + "\n---\n" + corr_yaml)
    out = backend.convert(collection)
    assert isinstance(out, list)
    # Last item is the correlation result (base detection rule is first)
    corr_records = [r for r in out if isinstance(r, dict) and "function" in str(r.get("rules", ""))]
    assert len(corr_records) == 1, f"Expected 1 correlation record, got {len(corr_records)}"
    return corr_records[0]


def _find_function_node(rules: list, key: str) -> dict | None:
    """Walk a BETree and return the first function node with the given key."""
    stack = list(rules) if isinstance(rules, list) else [rules]
    while stack:
        n = stack.pop()
        if isinstance(n, dict):
            if n.get("class") == "function" and n.get("key") == key:
                return n
            for c in n.get("children", []):
                stack.append(c)
        elif isinstance(n, list):
            stack.extend(n)
    return None


def test_event_count_correlation_emits_atomic_counter() -> None:
    result = _convert_correlation(_CORRELATION_EVENT_COUNT_YAML)
    fn = _find_function_node(result["rules"], "atomic_counter")
    assert fn is not None, "atomic_counter function node not found"
    assert fn["class"] == "function"
    args = fn["args"]
    # IpAddress maps to ip_src via field_mapper
    assert args["columns"] == ["ip_src"]
    assert args["comparison"]["value"] == ">="
    assert args["threshold"]["value"] == 10
    assert args["limit"]["value"] == 5  # 5m → 5 minutes


def test_value_count_correlation_emits_atomic_distinct_counter() -> None:
    result = _convert_correlation(_CORRELATION_VALUE_COUNT_YAML)
    fn = _find_function_node(result["rules"], "atomic_distinct_counter")
    assert fn is not None, "atomic_distinct_counter function node not found"
    args = fn["args"]
    # group-by IpAddress → ip_src; field User → correlation_username
    assert args["columns"] == ["ip_src"]
    assert args["distinct_column"]["value"] == "correlation_username"
    assert args["comparison"]["value"] == ">="
    assert args["threshold"]["value"] == 5
    assert args["limit"]["value"] == 15  # 15m → 15 minutes


def test_correlation_record_has_required_fields() -> None:
    result = _convert_correlation(_CORRELATION_EVENT_COUNT_YAML)
    for field in ("hawk_id", "group_name", "filter_name", "rules", "enabled",
                  "public", "actions_category_name", "correlation_action", "tags"):
        assert field in result, f"Missing required field: {field}"
    assert result["hawk_id"] == "22222222-2222-2222-2222-bbbbbbbbbbbb"
    assert result["filter_name"] == "Multiple Failed Logons from Same Source IP"
    assert "sigma" in result["tags"]


def test_null_field_emits_empty_function_node() -> None:
    result = _convert_one(
        """
title: Null Field Test
id: 55555555-5555-5555-5555-aaaaaaaaaaaa
status: stable
level: medium
logsource:
  product: windows
  category: process_creation
detection:
  sel:
    ParentCommandLine: null
  condition: sel
"""
    )
    fn = _find_function_node(result["rules"], "empty")
    assert fn is not None, "empty function node not found"
    assert fn["class"] == "function"
    assert fn["args"]["column"]["value"] == "parent_command"
    assert fn["args"]["comparison"]["value"] == "="  # IS NULL


def test_not_null_field_emits_empty_function_node_neq() -> None:
    result = _convert_one(
        """
title: Not Null Field Test
id: 55555555-5555-5555-5555-bbbbbbbbbbbb
status: stable
level: medium
logsource:
  product: windows
  category: process_creation
detection:
  sel:
    ParentCommandLine: null
  condition: not sel
"""
    )
    fn = _find_function_node(result["rules"], "empty")
    assert fn is not None, "empty function node not found"
    assert fn["args"]["comparison"]["value"] == "!="  # IS NOT NULL (negated via condition)


def test_field_reference_emits_column_comparison() -> None:
    result = _convert_one(
        """
title: Field Reference Test
id: 55555555-5555-5555-5555-cccccccccccc
status: stable
level: medium
logsource:
  product: windows
  category: process_creation
detection:
  sel:
    SourceImage|fieldref: TargetImage
  condition: sel
"""
    )
    fn = _find_function_node(result["rules"], "column_comparison")
    assert fn is not None, "column_comparison function node not found"
    assert fn["args"]["first_column"]["value"] == "parent_image"   # SourceImage → parent_image
    assert fn["args"]["second_column"]["value"] == "target_image"  # TargetImage → target_image
    assert fn["args"]["comparison"]["value"] == "="


def test_correlation_limit_converts_seconds_to_minutes() -> None:
    """Verify timespan units other than minutes are converted correctly."""
    corr = """
title: Hourly Correlation
id: 44444444-4444-4444-4444-dddddddddddd
name: hourly_corr
status: stable
correlation:
  type: event_count
  rules: failed_logon_base
  group-by:
    - IpAddress
  timespan: 2h
  condition:
    gte: 50
"""
    result = _convert_correlation(corr)
    fn = _find_function_node(result["rules"], "atomic_counter")
    assert fn is not None
    assert fn["args"]["limit"]["value"] == 120  # 2h → 120 minutes


def test_value_sum_correlation_emits_statistic_sum() -> None:
    corr = """
title: High Bytes Transferred
id: 66666666-6666-6666-6666-aaaaaaaaaaaa
name: high_bytes
status: stable
level: high
correlation:
  type: value_sum
  rules: failed_logon_base
  group-by:
    - IpAddress
  timespan: 1h
  condition:
    field: DestinationPort
    gte: 1000000
"""
    result = _convert_correlation(corr)
    fn = _find_function_node(result["rules"], "statistic")
    assert fn is not None, "statistic function node not found"
    assert fn["args"]["statistic"]["value"] == "sum"
    assert fn["args"]["function_column"]["value"] == "ip_dport"  # DestinationPort mapped
    assert fn["args"]["hour_range"]["value"] == 1  # 1h
    # companion column comparison node for threshold
    col = _find_leaf(result["rules"], "ip_dport_sum")
    assert col is not None, "companion column comparison node not found"
    assert col["args"]["float"]["value"] == 1000000.0


def test_value_avg_correlation_emits_statistic_avg() -> None:
    corr = """
title: Average Bytes High
id: 66666666-6666-6666-6666-bbbbbbbbbbbb
name: avg_bytes
status: stable
correlation:
  type: value_avg
  rules: failed_logon_base
  group-by:
    - IpAddress
  timespan: 2h
  condition:
    field: DestinationPort
    gt: 500
"""
    result = _convert_correlation(corr)
    fn = _find_function_node(result["rules"], "statistic")
    assert fn is not None
    assert fn["args"]["statistic"]["value"] == "avg"
    assert fn["args"]["hour_range"]["value"] == 2  # 2h


def test_value_percentile_correlation_emits_quantiles() -> None:
    corr = """
title: High 95th Percentile Bytes
id: 66666666-6666-6666-6666-cccccccccccc
name: p95_bytes
status: stable
correlation:
  type: value_percentile
  rules: failed_logon_base
  group-by:
    - IpAddress
  timespan: 8h
  condition:
    field: DestinationPort
    percentile: 95
    gte: 8000
"""
    result = _convert_correlation(corr)
    fn = _find_function_node(result["rules"], "quantiles")
    assert fn is not None, "quantiles function node not found"
    assert abs(fn["args"]["percentile"]["value"] - 0.95) < 0.001
    assert fn["args"]["active_hours"]["value"] == 8
    assert fn["args"]["column"]["value"] == "ip_dport"


def test_value_median_correlation_emits_quantiles_half() -> None:
    corr = """
title: Median Latency High
id: 66666666-6666-6666-6666-dddddddddddd
name: median_latency
status: stable
correlation:
  type: value_median
  rules: failed_logon_base
  group-by:
    - IpAddress
  timespan: 4h
  condition:
    field: DestinationPort
    gte: 200
"""
    result = _convert_correlation(corr)
    fn = _find_function_node(result["rules"], "quantiles")
    assert fn is not None, "quantiles function node not found"
    assert fn["args"]["percentile"]["value"] == 0.5  # median = 50th percentile
    assert fn["args"]["active_hours"]["value"] == 4
