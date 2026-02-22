import json
import re
import uuid
from pathlib import Path
from typing import Any, ClassVar, Dict, List, Optional

from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.conversion.base import TextQueryBackend
from sigma.correlations import (
    SigmaCorrelationConditionOperator,
    SigmaCorrelationRule,
    SigmaCorrelationType,
)
from sigma.rule import SigmaRule
from sigma.types import (
    CompareOperators,
    SigmaBool,
    SigmaCompareExpression,
    SigmaExpansion,
    SigmaFieldReference,
    SigmaNull,
    SigmaNumber,
    SigmaRegularExpression,
)

from .field_mapper import FieldMapper
from .logsource_enrichment import LogSourceEnricher

# Maps pySigma correlation condition operators to HAWK comparison strings.
_CORR_OP_STR: Dict[SigmaCorrelationConditionOperator, str] = {
    SigmaCorrelationConditionOperator.LT: "<",
    SigmaCorrelationConditionOperator.LTE: "<=",
    SigmaCorrelationConditionOperator.GT: ">",
    SigmaCorrelationConditionOperator.GTE: ">=",
    SigmaCorrelationConditionOperator.EQ: "=",
    SigmaCorrelationConditionOperator.NEQ: "!=",
}

# inputs schema descriptors (UI metadata, not evaluated by C engine).
_ATOMIC_COUNTER_INPUTS: Dict[str, Any] = {
    "columns":    {"order": 0, "source": "columns",      "type": "array"},
    "comparison": {"order": 1, "source": "comparison",   "type": "comparison"},
    "threshold":  {"order": 2, "source": "",             "type": "int"},
    "limit":      {"order": 3, "source": "time_offset",  "type": "int"},
}
_ATOMIC_DISTINCT_COUNTER_INPUTS: Dict[str, Any] = {
    "columns":        {"order": 0, "source": "columns",      "type": "array"},
    "distinct_column": {"order": 1, "source": "columns",     "type": "str"},
    "comparison":     {"order": 2, "source": "comparison",   "type": "comparison"},
    "threshold":      {"order": 3, "source": "",             "type": "int"},
    "limit":          {"order": 4, "source": "time_offset",  "type": "int"},
}
_EMPTY_INPUTS: Dict[str, Any] = {
    "comparison": {"order": 0, "source": "comparison", "type": "comparison"},
    "column":     {"order": 1, "source": "columns",    "type": "str"},
}
_COLUMN_COMPARISON_INPUTS: Dict[str, Any] = {
    "first_column":  {"order": 0, "source": "columns",    "type": "str"},
    "comparison":    {"order": 1, "source": "comparison", "type": "comparison"},
    "second_column": {"order": 2, "source": "columns",    "type": "str"},
}
_STATISTIC_INPUTS: Dict[str, Any] = {
    "columns":         {"order": 0, "source": "columns",           "type": "array"},
    "statistic":       {"order": 1, "source": "statistic_options", "type": "statistic_options"},
    "function_column": {"order": 2, "source": "columns",           "type": "str"},
    "hour_range":      {"order": 3, "source": "",                  "type": "int"},
    "new_column_name": {"order": 4, "source": "columns",           "type": "str"},
}
_QUANTILES_INPUTS: Dict[str, Any] = {
    "columns":         {"order": 0, "source": "columns", "type": "array"},
    "column":          {"order": 1, "source": "columns", "type": "str"},
    "percentile":      {"order": 2, "source": "",        "type": "double"},
    "active_hours":    {"order": 3, "source": "",        "type": "int"},
    "new_column_name": {"order": 4, "source": "columns", "type": "str"},
}


class hawkBackend(TextQueryBackend):
    name: ClassVar[str] = "HAWK"
    formats: ClassVar[Dict[str, str]] = {"default": "HAWK score JSON records"}
    default_format: ClassVar[str] = "default"
    # Opt in to correlation rule support (event_count → atomic_counter,
    # value_count → atomic_distinct_counter).
    correlation_methods: ClassVar[Dict[str, str]] = {"default": "HAWK atomic counter correlation"}

    def __init__(self, processing_pipeline=None, collect_errors: bool = False, **kwargs):
        super().__init__(processing_pipeline=processing_pipeline, collect_errors=collect_errors, **kwargs)
        self.field_mapper = FieldMapper()
        self.logsource_enricher = LogSourceEnricher()

    def convert_rule(self, rule: SigmaRule, output_format: Optional[str] = None, callback=None) -> list[Any]:
        if not hasattr(self, "last_processing_pipeline") or self.last_processing_pipeline is None:
            self.init_processing_pipeline(output_format)

        self.last_processing_pipeline.apply(rule)
        results = []
        for index, cond in enumerate(rule.detection.parsed_condition):
            tree = self._generate_node(cond.parsed)
            if tree is None:
                continue
            score = self._build_record(rule, [tree])
            if callback is not None:
                score = callback(rule, output_format, index, cond, score)
            if score is not None:
                results.append(score)

        rule.set_conversion_result(results)
        return results if rule._output else []

    def finalize_output_default(self, queries: list[Any]) -> list[Any]:
        return queries

    # ── Correlation rule support ────────────────────────────────────────────────

    def convert_correlation_rule(
        self,
        rule: SigmaCorrelationRule,
        output_format: Optional[str] = None,
        method: Optional[str] = None,
        callback=None,
    ) -> list[Any]:
        """Override to bypass TextQueryBackend.finish_query which stringifies dict output."""
        if not hasattr(self, "last_processing_pipeline") or self.last_processing_pipeline is None:
            self.init_processing_pipeline(output_format)
        self.last_processing_pipeline.apply(rule)

        m = method or self.default_correlation_method
        if rule.type == SigmaCorrelationType.EVENT_COUNT:
            raw = self.convert_correlation_event_count_rule(rule, output_format, m)
        elif rule.type == SigmaCorrelationType.VALUE_COUNT:
            raw = self.convert_correlation_value_count_rule(rule, output_format, m)
        elif rule.type == SigmaCorrelationType.VALUE_SUM:
            raw = self.convert_correlation_value_sum_rule(rule, output_format, m)
        elif rule.type == SigmaCorrelationType.VALUE_AVG:
            raw = self.convert_correlation_value_avg_rule(rule, output_format, m)
        elif rule.type == SigmaCorrelationType.VALUE_PERCENTILE:
            raw = self.convert_correlation_value_percentile_rule(rule, output_format, m)
        elif rule.type == SigmaCorrelationType.VALUE_MEDIAN:
            raw = self.convert_correlation_value_median_rule(rule, output_format, m)
        else:
            raw = []

        results = []
        for index, rec in enumerate(raw):
            result = rec
            if callback is not None:
                result = callback(rule, output_format, index, None, result)
            if result is not None:
                results.append(result)

        rule.set_conversion_result(results)
        return results

    def convert_correlation_event_count_rule(
        self,
        rule: SigmaCorrelationRule,
        output_format: Optional[str] = None,
        method: str = "default",
    ) -> list[Any]:
        """EVENT_COUNT correlation → atomic_counter function node."""
        columns = [self.field_mapper.map(f) for f in (rule.group_by or [])]
        comparison_str = _CORR_OP_STR.get(rule.condition.op, ">=")
        threshold = rule.condition.count
        limit = max(1, rule.timespan.seconds // 60)
        function_node = {
            "key": "atomic_counter",
            "class": "function",
            "inputs": _ATOMIC_COUNTER_INPUTS,
            "args": {
                "columns": columns,
                "comparison": {"value": comparison_str},
                "threshold": {"value": threshold},
                "limit": {"value": limit},
            },
        }
        return [self._build_correlation_record(rule, [function_node])]

    def convert_correlation_value_count_rule(
        self,
        rule: SigmaCorrelationRule,
        output_format: Optional[str] = None,
        method: str = "default",
    ) -> list[Any]:
        """VALUE_COUNT correlation → atomic_distinct_counter function node."""
        columns = [self.field_mapper.map(f) for f in (rule.group_by or [])]
        fieldref = rule.condition.fieldref
        if isinstance(fieldref, list):
            fieldref = fieldref[0] if fieldref else ""
        distinct_column = self.field_mapper.map(fieldref) if fieldref else ""
        comparison_str = _CORR_OP_STR.get(rule.condition.op, ">=")
        threshold = rule.condition.count
        limit = max(1, rule.timespan.seconds // 60)
        function_node = {
            "key": "atomic_distinct_counter",
            "class": "function",
            "inputs": _ATOMIC_DISTINCT_COUNTER_INPUTS,
            "args": {
                "columns": columns,
                "distinct_column": {"value": distinct_column},
                "comparison": {"value": comparison_str},
                "threshold": {"value": threshold},
                "limit": {"value": limit},
            },
        }
        return [self._build_correlation_record(rule, [function_node])]

    def convert_correlation_temporal_rule(self, rule, output_format=None, method="default") -> list[Any]:
        raise NotImplementedError("HAWK backend does not support temporal correlation rules.")

    def convert_correlation_temporal_ordered_rule(self, rule, output_format=None, method="default") -> list[Any]:
        raise NotImplementedError("HAWK backend does not support temporal_ordered correlation rules.")

    def convert_correlation_extended_temporal_rule(self, rule, output_format=None, method="default") -> list[Any]:
        raise NotImplementedError("HAWK backend does not support extended temporal correlation rules.")

    def convert_correlation_extended_temporal_ordered_rule(self, rule, output_format=None, method="default") -> list[Any]:
        raise NotImplementedError("HAWK backend does not support extended temporal_ordered correlation rules.")

    def convert_correlation_value_sum_rule(
        self,
        rule: SigmaCorrelationRule,
        output_format: Optional[str] = None,
        method: str = "default",
    ) -> list[Any]:
        """VALUE_SUM → statistic(sum) + column comparison node."""
        return [self._build_statistic_record(rule, "sum")]

    def convert_correlation_value_avg_rule(
        self,
        rule: SigmaCorrelationRule,
        output_format: Optional[str] = None,
        method: str = "default",
    ) -> list[Any]:
        """VALUE_AVG → statistic(avg) + column comparison node."""
        return [self._build_statistic_record(rule, "avg")]

    def convert_correlation_value_percentile_rule(
        self,
        rule: SigmaCorrelationRule,
        output_format: Optional[str] = None,
        method: str = "default",
    ) -> list[Any]:
        """VALUE_PERCENTILE → quantiles + column comparison node."""
        return [self._build_quantiles_record(rule)]

    def convert_correlation_value_median_rule(
        self,
        rule: SigmaCorrelationRule,
        output_format: Optional[str] = None,
        method: str = "default",
    ) -> list[Any]:
        """VALUE_MEDIAN → quantiles(0.5) + column comparison node."""
        return [self._build_quantiles_record(rule, percentile=0.5)]

    def _build_correlation_record(self, rule: SigmaCorrelationRule, children: list[dict]) -> dict:
        """Build a HAWK score record for a correlation rule with a list of BETree child nodes."""
        tags, techniques = self._normalize_tags_and_techniques(rule.tags or [])
        if self._is_experimental(rule) and "qa" not in tags:
            tags.append("qa")
        score, score_reason = self._calculate_score(rule)
        filter_name = self._format_filter_name(rule)
        return {
            "hawk_id": str(rule.id) if rule.id is not None else str(uuid.uuid4()),
            "group_name": ".",
            "filter_name": filter_name,
            "rules": [{
                "id": "and",
                "key": "And",
                "children": [{
                    "id": "and",
                    "key": "And",
                    "children": children,
                }],
            }],
            "enabled": False,
            "public": True,
            "actions_category_name": "Add (+)",
            "filter_details": self._generate_details(rule, score_reason),
            "references": "\n".join(rule.references or []),
            "comments": "",
            "correlation_action": score,
            "technique": techniques[0] if techniques else "",
            "tags": tags,
            "tactics": [],
        }

    def _corr_fieldref(self, rule: SigmaCorrelationRule) -> str:
        """Return the mapped field name from a correlation rule's condition fieldref."""
        fieldref = rule.condition.fieldref
        if isinstance(fieldref, list):
            fieldref = fieldref[0] if fieldref else ""
        return self.field_mapper.map(fieldref) if fieldref else ""

    def _build_statistic_record(self, rule: SigmaCorrelationRule, stat_type: str) -> dict:
        """Build a record using statistic() + column comparison for sum/avg correlation types."""
        columns = [self.field_mapper.map(f) for f in (rule.group_by or [])]
        function_col = self._corr_fieldref(rule)
        new_col = f"{function_col}_{stat_type}" if function_col else f"stat_{stat_type}"
        hour_range = max(1, rule.timespan.seconds // 3600)
        comparison_str = _CORR_OP_STR.get(rule.condition.op, ">=")
        threshold = rule.condition.count
        stat_node = {
            "key": "statistic",
            "class": "function",
            "inputs": _STATISTIC_INPUTS,
            "args": {
                "columns": columns,
                "statistic": {"value": stat_type},
                "function_column": {"value": function_col},
                "new_column_name": {"value": new_col},
                "hour_range": {"value": hour_range},
            },
        }
        compare_node = {
            "key": new_col,
            "description": f"{stat_type}({function_col})",
            "class": "column",
            "return": "float",
            "args": {
                "comparison": {"value": comparison_str},
                "float": {"value": float(threshold)},
            },
            "rule_id": str(uuid.uuid4()),
        }
        return self._build_correlation_record(rule, [stat_node, compare_node])

    def _build_quantiles_record(
        self, rule: SigmaCorrelationRule, percentile: Optional[float] = None
    ) -> dict:
        """Build a record using quantiles() + column comparison for percentile/median types."""
        columns = [self.field_mapper.map(f) for f in (rule.group_by or [])]
        function_col = self._corr_fieldref(rule)
        if percentile is None:
            pct_int = getattr(rule.condition, "percentile", None) or 50
            percentile = pct_int / 100.0
            pct_label = str(pct_int)
        else:
            pct_label = "50"
        new_col = f"{function_col}_p{pct_label}" if function_col else f"stat_p{pct_label}"
        active_hours = max(1, rule.timespan.seconds // 3600)
        comparison_str = _CORR_OP_STR.get(rule.condition.op, ">=")
        threshold = rule.condition.count
        quant_node = {
            "key": "quantiles",
            "class": "function",
            "inputs": _QUANTILES_INPUTS,
            "args": {
                "columns": columns,
                "column": {"value": function_col},
                "percentile": {"value": percentile},
                "active_hours": {"value": active_hours},
                "new_column_name": {"value": new_col},
            },
        }
        compare_node = {
            "key": new_col,
            "description": f"p{pct_label}({function_col})",
            "class": "column",
            "return": "float",
            "args": {
                "comparison": {"value": comparison_str},
                "float": {"value": float(threshold)},
            },
            "rule_id": str(uuid.uuid4()),
        }
        return self._build_correlation_record(rule, [quant_node, compare_node])

    def _build_record(self, rule: SigmaRule, children: list[dict]) -> dict:
        tags, techniques = self._normalize_tags_and_techniques(rule.tags or [])
        if self._is_experimental(rule) and "qa" not in tags:
            tags.append("qa")
        score, score_reason = self._calculate_score(rule)
        filter_name = self._format_filter_name(rule)
        return {
            "hawk_id": str(rule.id) if rule.id is not None else str(uuid.uuid4()),
            "group_name": ".",
            "filter_name": filter_name,
            "rules": [{
                "id": "and",
                "key": "And",
                "children": [{
                    "id": "and",
                    "key": "And",
                    "children": self._wrap_with_enrichment(children, rule),
                }],
            }],
            "enabled": False,
            "public": True,
            "actions_category_name": "Add (+)",
            "filter_details": self._generate_details(rule, score_reason),
            "references": "\n".join(rule.references or []),
            "comments": "",
            "correlation_action": score,
            # hawk-ece currently consumes a single technique string.
            "technique": techniques[0] if techniques else "",
            "tags": tags,
            "tactics": [],
        }

    def _normalize_tags_and_techniques(self, tags: list[Any]) -> tuple[list[str], list[str]]:
        out_tags: list[str] = ["sigma"]
        seen: set[str] = set()
        techniques: list[str] = []
        seen.add("sigma")

        for raw in tags:
            tag = str(raw).strip()
            if not tag:
                continue
            if tag not in seen:
                out_tags.append(tag)
                seen.add(tag)

            m = re.match(r"^attack\.(t\d{4}(?:\.\d{3})?)$", tag, flags=re.IGNORECASE)
            if not m:
                continue
            mitre = m.group(1).upper()
            if mitre not in seen:
                out_tags.append(mitre)
                seen.add(mitre)
            if mitre not in techniques:
                techniques.append(mitre)

        return out_tags, techniques

    def _generate_node(self, node: Any, not_node: bool = False) -> Optional[dict]:
        if isinstance(node, ConditionAND):
            children = [self._generate_node(n, not_node) for n in node.args]
            children = [c for c in children if c is not None]
            if not children:
                return None
            # De Morgan: NOT(A AND B) == (NOT A) OR (NOT B)
            op = "or" if not_node else "and"
            return {"id": op, "key": op.capitalize(), "children": self._dedupe_children(children)}
        if isinstance(node, ConditionOR):
            children = [self._generate_node(n, not_node) for n in node.args]
            children = [c for c in children if c is not None]
            if not children:
                return None
            # De Morgan: NOT(A OR B) == (NOT A) AND (NOT B)
            op = "and" if not_node else "or"
            return {"id": op, "key": op.capitalize(), "children": self._dedupe_children(children)}
        if isinstance(node, ConditionNOT):
            if not node.args:
                raise NotImplementedError("NOT condition without arguments is not supported.")
            return self._generate_node(node.args[0], not_node=True)
        if isinstance(node, ConditionFieldEqualsValueExpression):
            if isinstance(node.value, SigmaFieldReference):
                first_col = self.field_mapper.map(node.field)
                second_col = self.field_mapper.map(node.value.field)
                comparison_str = "!=" if not_node else "="
                return {
                    "key": "column_comparison",
                    "class": "function",
                    "inputs": _COLUMN_COMPARISON_INPUTS,
                    "args": {
                        "first_column": {"value": first_col},
                        "comparison": {"value": comparison_str},
                        "second_column": {"value": second_col},
                    },
                    "rule_id": str(uuid.uuid4()),
                }
            if isinstance(node.value, SigmaExpansion):
                return self._expand_sigma_expansion(node.field, node.value, not_node)
            return self._leaf_node(node.field, node.value, not_node)
        if isinstance(node, ConditionValueExpression):
            if isinstance(node.value, SigmaExpansion):
                return self._expand_sigma_expansion("payload", node.value, not_node)
            return self._leaf_node("payload", node.value, not_node)
        raise NotImplementedError(f"Unsupported node type: {type(node)}")

    def _expand_sigma_expansion(
        self, field: str, expansion: SigmaExpansion, not_node: bool
    ) -> Optional[dict]:
        children: list[dict] = []
        for val in expansion.values:
            child = self._leaf_node(field, val, not_node)
            if child is not None:
                children.append(child)
        if not children:
            return None
        return {"id": "or", "key": "Or", "children": self._dedupe_children(children)}

    def _leaf_node(self, key: str, raw_value: Any, not_node: bool) -> dict:
        # Null values map to the empty() IS-NULL function node.
        if isinstance(raw_value, SigmaNull):
            norm_key = self.field_mapper.map(key)
            comparison_str = "!=" if not_node else "="
            return {
                "key": "empty",
                "class": "function",
                "inputs": _EMPTY_INPUTS,
                "args": {
                    "comparison": {"value": comparison_str},
                    "column": {"value": norm_key},
                },
                "rule_id": str(uuid.uuid4()),
            }

        comparison_op = "="
        value = raw_value
        is_regex = False

        if isinstance(value, SigmaCompareExpression):
            op_map = {
                CompareOperators.LT: "<",
                CompareOperators.LTE: "<=",
                CompareOperators.GT: ">",
                CompareOperators.GTE: ">=",
            }
            comparison_op = op_map.get(value.op, "=")
            value = value.number.number
        elif isinstance(value, SigmaRegularExpression):
            value = str(value.regexp)
            is_regex = True
        elif isinstance(value, SigmaBool):
            value = bool(value)
        elif isinstance(value, SigmaNumber):
            value = value.number
        else:
            value = str(value)

        if isinstance(value, str) and ("*" in value or value.startswith("\\\\")):
            value = value.replace("*", "EEEESTAREEE")
            value = re.escape(value).replace("EEEESTAREEE", ".*")
            if value.endswith("\\\\"):
                value = value[:-2]
            if value.startswith(".*") and not value.endswith(".*"):
                value = value[2:] + "$"
            elif value.endswith(".*") and not value.startswith(".*"):
                value = "^" + value[:-2]
            is_regex = True

        norm_key = self.field_mapper.map(key)
        norm_key, value = self._normalize_hash_field(norm_key, value)
        norm_key, value = self._normalize_integrity_level(norm_key, value)
        if key == "Provider_Name" and isinstance(value, str) and value.startswith("Microsoft-Windows-"):
            norm_key = "product_name"
            value = value[len("Microsoft-Windows-"):]

        if not_node:
            _invert_op = {"=": "!=", "!=": "=", "<": ">=", "<=": ">", ">": "<=", ">=": "<"}
            comparison_op = _invert_op.get(comparison_op, comparison_op)

        return_type = "str"
        arg_key = "str"
        if isinstance(value, bool):
            return_type = "bool"
            arg_key = "bool"
        elif isinstance(value, int):
            return_type = "int"
            arg_key = "int"
        elif isinstance(value, float):
            return_type = "float"
            arg_key = "float"

        return {
            "key": norm_key,
            "description": key,
            "class": "column",
            "return": return_type,
            "args": {
                "comparison": {"value": comparison_op},
                arg_key: {
                    "value": value,
                    **({"regex": True} if is_regex and arg_key == "str" else {}),
                },
            },
            "rule_id": str(uuid.uuid4()),
        }

    def _normalize_hash_field(self, norm_key: str, value: Any) -> tuple[str, Any]:
        # Enforce aliasing and split-friendly hash selection based on authoritative Hawk columns.
        if norm_key == "file_hash_sha":
            norm_key = "file_hash_sha1"

        if not isinstance(value, str):
            return norm_key, value

        if norm_key not in {"hashes", "hash", "file_hash_sha", "file_hash_sha1"}:
            return norm_key, value

        markers: list[tuple[str, str]] = [
            ("imphash", "file_hash_imphash"),
            ("pehash", "file_hash_pehash"),
            ("sha256", "file_hash_sha256"),
            ("sha2", "file_hash_sha2"),
            ("sha512", "file_hash_sha512"),
            ("sha1", "file_hash_sha1"),
            ("sha", "file_hash_sha1"),
            ("md5", "file_hash_md5"),
        ]
        for marker, mapped_key in markers:
            rx = re.compile(rf"(?i)\b{re.escape(marker)}\b\s*[:=]\s*([A-Fa-f0-9]{{6,}})")
            m = rx.search(value)
            if m:
                return mapped_key, m.group(1)

        return norm_key, value

    def _normalize_integrity_level(self, norm_key: str, value: Any) -> tuple[str, Any]:
        if norm_key != "integrity_level" or not isinstance(value, str):
            return norm_key, value
        sid_to_level = {
            "S-1-16-4096": "low",
            "S-1-16-8192": "medium",
            "S-1-16-12288": "high",
            "S-1-16-16384": "system",
        }
        normalized = sid_to_level.get(value.upper())
        if normalized is not None:
            return norm_key, normalized
        return norm_key, value.lower()

    def _dedupe_children(self, children: list[dict]) -> list[dict]:
        out: list[dict] = []
        seen: set[str] = set()
        for child in children:
            sig = self._node_signature(child)
            if sig in seen:
                continue
            seen.add(sig)
            out.append(child)
        return out

    def _node_signature(self, node: Any) -> str:
        def strip_volatile(x: Any) -> Any:
            if isinstance(x, list):
                return [strip_volatile(v) for v in x]
            if isinstance(x, dict):
                return {k: strip_volatile(v) for k, v in x.items() if k != "rule_id"}
            return x

        return json.dumps(strip_volatile(node), sort_keys=True, separators=(",", ":"))

    def _wrap_with_enrichment(self, children: list[dict], rule: SigmaRule) -> list[dict]:
        detection_children = [c for c in children if c is not None]
        detection_children = self._dedupe_children(detection_children)
        enrichment_nodes = self._build_logsource_enrichment_nodes(rule)
        wrapped: list[dict] = []
        wrapped.extend(enrichment_nodes)
        if detection_children:
            wrapped.append({"id": "and", "key": "And", "children": detection_children})
        if not wrapped and children:
            wrapped = children
        return wrapped

    def _build_logsource_enrichment_nodes(self, rule: SigmaRule) -> list[dict]:
        nodes: list[dict] = []
        seen: set[str] = set()
        for conditions in self.logsource_enricher.match(rule.logsource):
            for node in self._nodes_from_conditions(conditions):
                sig = self._node_signature(node)
                if sig in seen:
                    continue
                seen.add(sig)
                nodes.append(node)
        return nodes

    def _nodes_from_conditions(self, conditions: dict[str, Any]) -> list[dict]:
        nodes: list[dict] = []
        for key, value in conditions.items():
            if value is None:
                continue
            if isinstance(value, (list, tuple)):
                children = [
                    child for child in (self._leaf_node(key, item, False) for item in value) if child is not None
                ]
                if children:
                    nodes.append({"id": "or", "key": "Or", "children": self._dedupe_children(children)})
                continue
            node = self._leaf_node(key, value, False)
            if node is not None:
                nodes.append(node)
        return nodes

    def _generate_details(self, rule: SigmaRule, score_reason: str) -> str:
        details = f"Sigma Rule: {rule.id}\nAuthor: {rule.author or 'Unknown'}\nLevel: {rule.level}\n"
        if rule.falsepositives:
            details += "False Positives: " + ", ".join(rule.falsepositives) + "\n"
        return details + "\n\n" + score_reason

    def _calculate_score(self, rule: SigmaRule) -> tuple[float, str]:
        # Keep scoring behavior aligned with legacy sigmac converter.
        score = 5.0
        reasons = ["Scoring:"]
        if not self._is_experimental(rule):
            score += 5.0
            reasons.append("Status is not experimental (+5)")
        else:
            reasons.append("Status is experimental (+0)")
        false_positives = rule.falsepositives or []
        if len(false_positives) > 1:
            penalty = 2.0 * len(false_positives)
            score -= penalty
            reasons.append(f"False positives  (-2 * {len(false_positives)})")
        if rule.level:
            lvl = str(rule.level).lower()
            if lvl == "critical":
                score += 15.0
                reasons.append("Critical (+15)")
            elif lvl == "high":
                score += 10.0
                reasons.append("High (+10)")
            elif lvl in ("medium", "moderate"):
                reasons.append("Medium (+0)")
            elif lvl == "low":
                score -= 10.0
                reasons.append("Low (-10)")
            elif lvl == "informational":
                score -= 15.0
                reasons.append("Informational (-15)")
        return max(score, 0.0), "\n".join(reasons)

    def _is_experimental(self, rule: SigmaRule) -> bool:
        status = str(rule.status or "").lower()
        # pySigma may stringify enum values like "SigmaStatus.EXPERIMENTAL".
        return "experimental" in status

    def _format_filter_name(self, rule: SigmaRule) -> str:
        title = rule.title or "Unnamed Sigma Rule"
        if self._is_deprecated(rule):
            return f"{title} (Deprecated)"
        return title

    def _is_deprecated(self, rule: SigmaRule) -> bool:
        source = getattr(rule, "source", None)
        if source is None:
            return False
        path = getattr(source, "path", None)
        if path is None:
            return False
        parts = [str(part).lower() for part in Path(path).parts]
        if "deprecated" in parts:
            return True
        return any("deprecated" in part for part in parts)

