"""Correlation rules against hawk-ece's real evaluation model (2026-09-26).

A stateful function leaf counts every event that reaches it, so the referenced rule's own gate
and detection must precede it under the root And. See converter_validation/patch_converter_v3.py.
"""
import pytest

from sigma.backends.hawk import hawkBackend
from sigma.collection import SigmaCollection
from sigma.pipelines.hawk import hawk_pipeline

BASE_4625 = """
title: Failed Logon
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

BASE_4624 = """
title: Successful Logon
id: 11111111-1111-1111-1111-bbbbbbbbbbbb
name: success_logon_base
status: stable
logsource:
  product: windows
  service: security
detection:
  sel:
    EventID: 4624
    LogonType: 3
  condition: sel
"""


def _convert(*docs: str) -> list:
    backend = hawkBackend(processing_pipeline=hawk_pipeline())
    out = backend.convert(SigmaCollection.from_yaml("\n---\n".join(docs)))
    return [r for r in out if isinstance(r, dict) and "function" in str(r.get("rules"))]


def _val(leaf):
    args = leaf.get("args") or {}
    for t in ("str", "int", "float", "bool"):
        if t in args:
            return str(args[t].get("value"))
    return None


def _inner(rec):
    """Root And -> inner And whose children are [base tree, function leaf, (compare leaf)]."""
    return rec["rules"][0]["children"][0]["children"]


def _leaves(node):
    if isinstance(node, list):
        return [x for c in node for x in _leaves(c)]
    if not isinstance(node, dict):
        return []
    if node.get("class") in ("column", "function"):
        return [node]
    return [x for c in node.get("children", []) or [] for x in _leaves(c)]


def test_event_count_places_base_tree_before_counter() -> None:
    corr = """
title: Many failed logons
id: 22222222-2222-2222-2222-bbbbbbbbbbbb
name: many_failed
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
    (rec,) = _convert(BASE_4625, corr)
    children = _inner(rec)
    # base tree first (its detection carries vendor_id 4625), function leaf last
    assert children[0]["id"] == "and"
    assert any(l["key"] == "vendor_id" and _val(l) == "4625" for l in _leaves(children[0]))
    assert any(l["key"] == "event_channel" for l in _leaves(children[0]))
    fn = children[-1]
    assert fn["class"] == "function" and fn["key"] == "atomic_counter"
    assert fn["args"]["columns"] == ["ip_src"]
    assert fn["args"]["threshold"]["value"] == 10 and fn["args"]["limit"]["value"] == 5
    assert fn["rule_id"]  # stable, keys the engine's memcached state
    (rec2,) = _convert(BASE_4625, corr)
    assert _inner(rec2)[-1]["rule_id"] == fn["rule_id"]


def test_event_count_refuses_fewer_than() -> None:
    corr = """
title: Rare logons
id: 22222222-2222-2222-2222-cccccccccccc
name: rare
status: stable
correlation:
  type: event_count
  rules: failed_logon_base
  group-by:
    - IpAddress
  timespan: 1h
  condition:
    lt: 2
"""
    with pytest.raises(NotImplementedError):
        _convert(BASE_4625, corr)


def test_empty_group_by_uses_group_name_and_limit_rounds_up() -> None:
    corr = """
title: Burst of failed logons
id: 22222222-2222-2222-2222-dddddddddddd
name: burst
status: stable
correlation:
  type: event_count
  rules: failed_logon_base
  timespan: 90s
  condition:
    gte: 100
"""
    (rec,) = _convert(BASE_4625, corr)
    fn = _inner(rec)[-1]
    assert fn["args"]["columns"] == ["group_name"]
    assert fn["args"]["limit"]["value"] == 2


def test_value_sum_uses_statistic_window_and_int_compare() -> None:
    corr = """
title: Bytes out
id: 66666666-6666-6666-6666-aaaaaaaaaaaa
name: bytes_out
status: stable
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
    (rec,) = _convert(BASE_4625, corr)
    children = _inner(rec)
    assert children[0]["id"] == "and"
    fn, cmp = children[-2], children[-1]
    assert fn["key"] == "statistic_window" and fn["args"]["statistic"]["value"] == "sum"
    assert fn["args"]["hour_range"]["value"] == 1 and fn["args"]["window_size"]["value"] == 300
    new_col = fn["args"]["new_column_name"]["value"]
    assert new_col.startswith("ip_dport_sum_")
    assert cmp["key"] == new_col and cmp["return"] == "int" and cmp["args"]["int"]["value"] == 1000000


def test_percentile_and_median_are_refused() -> None:
    for t, extra in (("value_percentile", "    percentile: 95\n"), ("value_median", "")):
        corr = f"""
title: Q
id: 66666666-6666-6666-6666-cccccccccccc
name: q_{t}
status: stable
correlation:
  type: {t}
  rules: failed_logon_base
  group-by:
    - IpAddress
  timespan: 8h
  condition:
    field: DestinationPort
{extra}    gte: 8000
"""
        with pytest.raises(NotImplementedError):
            _convert(BASE_4625, corr)


def test_temporal_uses_or_of_rules_and_distinct_discriminator() -> None:
    corr = """
title: Failed then successful logon
id: 77777777-7777-7777-7777-aaaaaaaaaaaa
name: fail_then_success
status: stable
level: high
correlation:
  type: temporal
  rules:
    - failed_logon_base
    - success_logon_base
  group-by:
    - IpAddress
  timespan: 10m
"""
    (rec,) = _convert(BASE_4625, BASE_4624, corr)
    children = _inner(rec)
    assert children[0]["id"] == "or" and len(children[0]["children"]) == 2
    fn = children[-1]
    assert fn["key"] == "atomic_distinct_counter"
    assert fn["args"]["distinct_column"]["value"] == "vendor_id"
    assert fn["args"]["threshold"]["value"] == 2
    assert fn["args"]["limit"]["value"] == 10
    assert "order-insensitive" in rec["filter_details"]


def test_temporal_without_discriminator_is_refused() -> None:
    same = BASE_4624.replace("11111111-1111-1111-1111-bbbbbbbbbbbb", "11111111-1111-1111-1111-cccccccccccc").replace("success_logon_base", "twin_base").replace("4624", "4625").replace("    LogonType: 3\n", "")
    corr = """
title: Twins
id: 77777777-7777-7777-7777-bbbbbbbbbbbb
name: twins
status: stable
correlation:
  type: temporal
  rules:
    - failed_logon_base
    - twin_base
  timespan: 10m
"""
    with pytest.raises(NotImplementedError):
        _convert(BASE_4625, same, corr)
