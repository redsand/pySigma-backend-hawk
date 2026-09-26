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
    SigmaCasedString,
    SigmaCIDRExpression,
    SigmaCompareExpression,
    SigmaExists,
    SigmaExpansion,
    SigmaFieldReference,
    SigmaNull,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaString,
    SpecialChars,
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

# MITRE ATT&CK tactic slugs (as used in Sigma `attack.<tactic>` tags) -> tactic ids.
_ATTACK_TACTICS: Dict[str, tuple] = {
    "reconnaissance": ("TA0043", "Reconnaissance"),
    "resource-development": ("TA0042", "Resource Development"),
    "resource_development": ("TA0042", "Resource Development"),
    "initial-access": ("TA0001", "Initial Access"),
    "initial_access": ("TA0001", "Initial Access"),
    "execution": ("TA0002", "Execution"),
    "persistence": ("TA0003", "Persistence"),
    "privilege-escalation": ("TA0004", "Privilege Escalation"),
    "privilege_escalation": ("TA0004", "Privilege Escalation"),
    "defense-evasion": ("TA0005", "Defense Evasion"),
    "defense_evasion": ("TA0005", "Defense Evasion"),
    "credential-access": ("TA0006", "Credential Access"),
    "credential_access": ("TA0006", "Credential Access"),
    "discovery": ("TA0007", "Discovery"),
    "lateral-movement": ("TA0008", "Lateral Movement"),
    "lateral_movement": ("TA0008", "Lateral Movement"),
    "collection": ("TA0009", "Collection"),
    "exfiltration": ("TA0010", "Exfiltration"),
    "command-and-control": ("TA0011", "Command and Control"),
    "command_and_control": ("TA0011", "Command and Control"),
    "impact": ("TA0040", "Impact"),
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
_STATISTIC_WINDOW_INPUTS: Dict[str, Any] = {
    "columns":         {"order": 0, "source": "columns",                  "type": "array"},
    "statistic":       {"order": 1, "source": "statistic_window_options", "type": "statistic_window_options"},
    "function_column": {"order": 2, "source": "columns",                  "type": "str"},
    "hour_range":      {"order": 3, "source": "",                         "type": "int"},
    "window_size":     {"order": 4, "source": "",                         "type": "int"},
    "new_column_name": {"order": 5, "source": "columns",                  "type": "str"},
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

        self._apply_pipeline_once(rule)
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

    def _apply_pipeline_once(self, rule: SigmaRule) -> None:
        """Referenced rules are converted again inside a correlation; never re-map their fields."""
        if rule.custom_attributes.get("_hawk_pipeline_applied"):
            return
        self.last_processing_pipeline.apply(rule)
        rule.custom_attributes["_hawk_pipeline_applied"] = True

    def _base_children(self, rule: SigmaRule) -> list[dict]:
        """Enrichment gate + detection subtree for a rule, exactly as _build_record nests them."""
        self._apply_pipeline_once(rule)
        trees = [t for t in (self._generate_node(c.parsed) for c in rule.detection.parsed_condition) if t is not None]
        if not trees:
            return []
        det = trees[0] if len(trees) == 1 else {"id": "or", "key": "Or", "children": trees}
        return self._wrap_with_enrichment([det], rule)

    def _referenced_rules(self, rule: SigmaCorrelationRule) -> list[SigmaRule]:
        refs = []
        for ref in rule.rules or []:
            r = getattr(ref, "rule", None)
            if r is None:
                raise NotImplementedError(f"Correlation {rule.id}: rule reference {ref!r} is unresolved.")
            if isinstance(r, SigmaCorrelationRule):
                raise NotImplementedError(f"Correlation {rule.id}: nested correlations are not supported by hawk-ece.")
            refs.append(r)
        if not refs:
            raise NotImplementedError(f"Correlation {rule.id} references no rules.")
        return refs

    def _correlation_base(self, rule: SigmaCorrelationRule) -> dict:
        """The referenced rule(s) as one And node (or an Or of Ands) that precedes the function leaf."""
        groups = []
        for r in self._referenced_rules(rule):
            children = self._base_children(r)
            if not children:
                raise NotImplementedError(f"Correlation {rule.id}: referenced rule {r.id} converts to an empty tree.")
            groups.append({"id": "and", "key": "And", "children": children})
        return groups[0] if len(groups) == 1 else {"id": "or", "key": "Or", "children": groups}

    def _stable_rule_id(self, rule: SigmaCorrelationRule, key: str, index: int = 0) -> str:
        """Function-leaf ids key the engine's memcached state; keep them stable across re-syncs."""
        return str(uuid.uuid5(uuid.NAMESPACE_URL, f"hawk-correlation:{rule.id}:{key}:{index}"))

    def _corr_columns(self, rule: SigmaCorrelationRule) -> list[str]:
        # an empty `columns` array is dropped by the loader and the leaf then always fails;
        # group_name is stamped on every event at ingest
        cols = [self.field_mapper.map(f) for f in (rule.group_by or [])]
        return cols or ["group_name"]

    @staticmethod
    def _corr_minutes(rule: SigmaCorrelationRule, cap: Optional[int] = None) -> int:
        minutes = max(1, -(-int(rule.timespan.seconds) // 60))
        return min(minutes, cap) if cap else minutes

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
        elif rule.type == SigmaCorrelationType.TEMPORAL:
            raw = self.convert_correlation_temporal_rule(rule, output_format, m)
        elif rule.type == SigmaCorrelationType.TEMPORAL_ORDERED:
            raw = self.convert_correlation_temporal_ordered_rule(rule, output_format, m)
        else:
            raise NotImplementedError(f"hawk backend: unsupported correlation type {rule.type}")

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
        """EVENT_COUNT → base detection tree, then atomic_counter (counts only events that reach it).

        `limit` is minutes on 5-minute blocks with a 24h TTL. `<`/`<=` are evaluated before the
        history walk in the engine and are always true, so they are refused.
        """
        if rule.condition.op in (SigmaCorrelationConditionOperator.LT, SigmaCorrelationConditionOperator.LTE):
            raise NotImplementedError("hawk-ece atomic_counter cannot express a 'fewer than' event count.")
        function_node = {
            "key": "atomic_counter",
            "class": "function",
            "return": "int",
            "inputs": _ATOMIC_COUNTER_INPUTS,
            "args": {
                "columns": self._corr_columns(rule),
                "comparison": {"value": _CORR_OP_STR.get(rule.condition.op, ">=")},
                "threshold": {"value": int(rule.condition.count)},
                "limit": {"value": self._corr_minutes(rule, cap=1440)},
            },
            "rule_id": self._stable_rule_id(rule, "atomic_counter"),
        }
        return [self._build_correlation_record(rule, [function_node])]

    def convert_correlation_value_count_rule(
        self,
        rule: SigmaCorrelationRule,
        output_format: Optional[str] = None,
        method: str = "default",
    ) -> list[Any]:
        """VALUE_COUNT → base detection tree, then atomic_distinct_counter.

        The engine keeps a HyperLogLog per group with an inactivity TTL of `limit` minutes, so
        "distinct values within timespan" is approximate (~5%) and window-by-inactivity.
        """
        distinct_column = self._corr_fieldref(rule)
        if not distinct_column:
            raise NotImplementedError("value_count needs a `field` to count distinct values of.")
        function_node = {
            "key": "atomic_distinct_counter",
            "class": "function",
            "return": "int",
            "inputs": _ATOMIC_DISTINCT_COUNTER_INPUTS,
            "args": {
                "columns": self._corr_columns(rule),
                "distinct_column": {"value": distinct_column},
                "comparison": {"value": _CORR_OP_STR.get(rule.condition.op, ">=")},
                "threshold": {"value": int(rule.condition.count)},
                "limit": {"value": self._corr_minutes(rule)},
            },
            "rule_id": self._stable_rule_id(rule, "atomic_distinct_counter"),
        }
        return [self._build_correlation_record(rule, [function_node])]

    def convert_correlation_temporal_rule(self, rule, output_format=None, method="default") -> list[Any]:
        """TEMPORAL (all referenced rules seen for the same group within timespan).

        hawk-ece has no join primitive. When every referenced rule pins a distinct constant value
        of one common column (EventID 4624 vs 4625, alert_name, ...), the event class can be
        recognised by that column: Or[rule trees] followed by atomic_distinct_counter on it with
        threshold = number of rules. Fires on the k-th distinct rule for the group within the
        inactivity window; order-insensitive and HLL-approximate. Without such a discriminator the
        rule is refused rather than converted into something that fires on any single rule.
        """
        return [self._build_temporal_record(rule, ordered=False)]

    def convert_correlation_temporal_ordered_rule(self, rule, output_format=None, method="default") -> list[Any]:
        """TEMPORAL_ORDERED: nothing in hawk-ece records sequence; converted as temporal and
        labelled so reviewers know the order is not enforced."""
        return [self._build_temporal_record(rule, ordered=True)]

    def _constant_leaves(self, node: Any) -> dict:
        """Column -> constant value for plain equality leaves in a tree (regex/negation excluded)."""
        out: dict = {}
        stack = [node]
        while stack:
            n = stack.pop()
            if isinstance(n, list):
                stack.extend(n)
                continue
            if not isinstance(n, dict):
                continue
            if n.get("class") == "column":
                args = n.get("args") or {}
                if (args.get("comparison") or {}).get("value") != "=":
                    continue
                for t in ("str", "int"):
                    a = args.get(t)
                    if isinstance(a, dict) and not a.get("regex") and a.get("value") not in (None, ""):
                        out.setdefault(n["key"], str(a["value"]).lower())
            else:
                stack.extend(n.get("children", []) or [])
        return out

    def _build_temporal_record(self, rule: SigmaCorrelationRule, ordered: bool) -> dict:
        refs = self._referenced_rules(rule)
        if len(refs) < 2:
            raise NotImplementedError("temporal correlation needs at least two referenced rules.")
        groups = []
        constants = []
        for r in refs:
            children = self._base_children(r)
            if not children:
                raise NotImplementedError(f"Correlation {rule.id}: referenced rule {r.id} converts to an empty tree.")
            groups.append({"id": "and", "key": "And", "children": children})
            constants.append(self._constant_leaves(children))
        common = set(constants[0])
        for c in constants[1:]:
            common &= set(c)
        discriminator = None
        for col in sorted(common, key=lambda k: (k not in ("vendor_id", "alert_name", "event_name", "product_name"), k)):
            values = [c[col] for c in constants]
            if len(set(values)) == len(values):
                discriminator = col
                break
        if discriminator is None:
            raise NotImplementedError(
                f"Correlation {rule.id}: no single column takes a distinct constant value in every referenced rule; "
                "hawk-ece cannot join them."
            )
        function_node = {
            "key": "atomic_distinct_counter",
            "class": "function",
            "return": "int",
            "inputs": _ATOMIC_DISTINCT_COUNTER_INPUTS,
            "args": {
                "columns": self._corr_columns(rule),
                "distinct_column": {"value": discriminator},
                "comparison": {"value": ">="},
                "threshold": {"value": len(refs)},
                "limit": {"value": self._corr_minutes(rule)},
            },
            "rule_id": self._stable_rule_id(rule, "temporal"),
        }
        rec = self._build_correlation_record(rule, [function_node], base={"id": "or", "key": "Or", "children": groups})
        note = (f"Temporal correlation of {len(refs)} rules, recognised by distinct values of `{discriminator}`; "
                "order-insensitive, approximate (HyperLogLog), inactivity window of the timespan.")
        if ordered:
            note += " ORDER IS NOT ENFORCED (temporal_ordered downgraded)."
        rec["filter_details"] = rec["filter_details"] + "\n\n" + note
        return rec

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
        """VALUE_PERCENTILE: refused. hawk-ece `quantiles` reads `percentile` from a field the
        score loader never populates and keeps per-process state with no timespan."""
        raise NotImplementedError("hawk-ece quantiles is not usable for value_percentile (engine reads an unset field).")

    def convert_correlation_value_median_rule(
        self,
        rule: SigmaCorrelationRule,
        output_format: Optional[str] = None,
        method: str = "default",
    ) -> list[Any]:
        """VALUE_MEDIAN: refused for the same reason as value_percentile."""
        raise NotImplementedError("hawk-ece quantiles is not usable for value_median (engine reads an unset field).")

    def _build_correlation_record(self, rule: SigmaCorrelationRule, function_leaves: list[dict], base: Optional[dict] = None) -> dict:
        """Score record for a correlation: [base tree, function leaf, (compare leaf)] under the root And.

        The base tree is the referenced rule's own gate + detection, so the stateful leaf that
        follows it only ever sees events that matched the rule.
        """
        children = [base if base is not None else self._correlation_base(rule)] + list(function_leaves)
        tags, techniques = self._normalize_tags_and_techniques(rule.tags or [])
        tactics = self._normalize_tactics(rule.tags or [])
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
            # scores.technique is VARCHAR(16): a single technique id. The rest ride in tags.
            "technique": techniques[0] if techniques else "",
            "tags": tags,
            "tactics": tactics,
        }

    def _normalize_tactics(self, tags: list) -> list:
        out: list = []
        seen: set = set()
        for raw in tags:
            m = re.match(r"^attack\.([a-z_\-]+)$", str(raw).strip(), flags=re.IGNORECASE)
            if not m:
                continue
            hit = _ATTACK_TACTICS.get(m.group(1).lower())
            if hit is None or hit[0] in seen:
                continue
            seen.add(hit[0])
            out.append({
                "tactic_id": hit[0],
                "tactic_name": hit[1],
                "tactic_url": f"https://attack.mitre.org/tactics/{hit[0]}/",
            })
        return out

    def _corr_fieldref(self, rule: SigmaCorrelationRule) -> str:
        """Return the mapped field name from a correlation rule's condition fieldref."""
        fieldref = rule.condition.fieldref
        if isinstance(fieldref, list):
            fieldref = fieldref[0] if fieldref else ""
        return self.field_mapper.map(fieldref) if fieldref else ""

    def _build_statistic_record(self, rule: SigmaCorrelationRule, stat_type: str) -> dict:
        """value_sum / value_avg → statistic_window + an `int` compare leaf on the written column.

        statistic_window buckets by event reception_time (`window_size` seconds) over
        `hour_range` hours and writes a DOUBLE attribute; only an `int` compare leaf can read
        it (float/double leaves compare a field the engine never sets). `avg` is the mean of
        per-bucket means, so a single bucket spanning the range keeps it exact.
        """
        function_col = self._corr_fieldref(rule)
        if not function_col:
            raise NotImplementedError(f"value_{stat_type} needs a `field`.")
        seconds = int(rule.timespan.seconds)
        hour_range = max(1, -(-seconds // 3600))
        window_size = min(seconds, 300) if stat_type == "sum" else hour_range * 3600
        short = self._stable_rule_id(rule, f"statistic_window_{stat_type}")[:8]
        new_col = f"{function_col}_{stat_type}_{short}"
        stat_node = {
            "key": "statistic_window",
            "class": "function",
            "return": "float",
            "inputs": _STATISTIC_WINDOW_INPUTS,
            "args": {
                "columns": self._corr_columns(rule),
                "statistic": {"value": stat_type},
                "function_column": {"value": function_col},
                "hour_range": {"value": hour_range},
                "window_size": {"value": max(1, window_size)},
                "new_column_name": {"value": new_col},
            },
            "rule_id": self._stable_rule_id(rule, f"statistic_window_{stat_type}"),
        }
        compare_node = {
            "key": new_col,
            "description": f"{stat_type}({function_col}) over {seconds}s",
            "class": "column",
            "return": "int",
            "args": {
                "comparison": {"value": _CORR_OP_STR.get(rule.condition.op, ">=")},
                "int": {"value": int(rule.condition.count)},
            },
            "rule_id": self._stable_rule_id(rule, f"statistic_window_{stat_type}_compare"),
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
        tactics = self._normalize_tactics(rule.tags or [])
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
            # scores.technique is VARCHAR(16): a single technique id. The rest ride in tags.
            "technique": techniques[0] if techniques else "",
            "tags": tags,
            "tactics": tactics,
        }

    def _normalize_tactics(self, tags: list) -> list:
        out: list = []
        seen: set = set()
        for raw in tags:
            m = re.match(r"^attack\.([a-z_\-]+)$", str(raw).strip(), flags=re.IGNORECASE)
            if not m:
                continue
            hit = _ATTACK_TACTICS.get(m.group(1).lower())
            if hit is None or hit[0] in seen:
                continue
            seen.add(hit[0])
            out.append({
                "tactic_id": hit[0],
                "tactic_name": hit[1],
                "tactic_url": f"https://attack.mitre.org/tactics/{hit[0]}/",
            })
        return out

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
            # Sigma keywords match anywhere in the event: substring semantics on payload.
            if isinstance(node.value, SigmaExpansion):
                return self._expand_sigma_expansion("payload", node.value, not_node, contains=True)
            return self._leaf_node("payload", node.value, not_node, contains=True)
        raise NotImplementedError(f"Unsupported node type: {type(node)}")

    def _expand_sigma_expansion(
        self, field: str, expansion: SigmaExpansion, not_node: bool, contains: bool = False
    ) -> Optional[dict]:
        children: list[dict] = []
        for val in expansion.values:
            child = self._leaf_node(field, val, not_node, contains=contains)
            if child is not None:
                children.append(child)
        if not children:
            return None
        return {"id": "or", "key": "Or", "children": self._dedupe_children(children)}

    def _leaf_node(self, key: str, raw_value: Any, not_node: bool, contains: bool = False) -> dict:
        # Null values map to the empty() IS-NULL function node; `|exists` is its inverse.
        if isinstance(raw_value, (SigmaNull, SigmaExists)):
            norm_key = self.field_mapper.map(key)
            is_null = isinstance(raw_value, SigmaNull) or not raw_value.exists
            comparison_str = "=" if is_null else "!="
            if not_node:
                comparison_str = "!=" if comparison_str == "=" else "="
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
        case_sensitive = False

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
            # Already a regex: never re-escape. hawk-ece PCRE matching is case-insensitive
            # by default, which is the production convention for Sigma-derived scores.
            value = str(value.regexp)
            if contains and not value.startswith(".*") and not value.startswith("^"):
                value = ".*" + value
            if contains and not value.endswith(".*") and not value.endswith("$"):
                value = value + ".*"
            is_regex = True
        elif isinstance(value, SigmaCIDRExpression):
            # hawk-ece detects a/b notation in a plain string value and does a CIDR match.
            value = str(value.cidr)
        elif isinstance(value, SigmaBool):
            # hawk-ece parses the bool arg from a string ("true"/"success" => true); a JSON
            # boolean is read as NULL and silently becomes false.
            value = bool(value)
        elif isinstance(value, SigmaNumber):
            value = value.number
        elif isinstance(value, SigmaString):
            case_sensitive = isinstance(value, SigmaCasedString)
            value, is_regex = self._sigma_string_to_hawk(value, contains)
        else:
            value = str(value)
            if contains:
                value, is_regex = ".*" + re.escape(value) + ".*", True

        norm_key = self.field_mapper.map(key)
        value, is_regex = self._tolerate_xml_entities(value, is_regex)
        norm_key, value, is_regex = self._normalize_connector_value(norm_key, value, is_regex)
        norm_key, value = self._normalize_hash_field(norm_key, value)
        if norm_key.startswith("file_hash_") and isinstance(value, str) and re.fullmatch(r"[A-Fa-f0-9]{6,}", value):
            is_regex = False  # a bare hash pulled out of a `Hashes|contains` wildcard is an exact value
        norm_key, value = self._normalize_integrity_level(norm_key, value)
        if key in ("Provider_Name", "ProviderName") and isinstance(value, str) and not is_regex:
            # hawkagentd strips "Microsoft-Windows-" and replaces spaces with "_" in the provider
            # name before it becomes product_name (hawkagentd/hawk-events.c).
            norm_key = "product_name"
            if value.startswith("Microsoft-Windows-"):
                value = value[len("Microsoft-Windows-"):]
            value = value.replace(" ", "_")

        if not_node:
            _invert_op = {"=": "!=", "!=": "=", "<": ">=", "<=": ">", ">": "<=", ">=": "<"}
            comparison_op = _invert_op.get(comparison_op, comparison_op)

        return_type = "str"
        arg_key = "str"
        if isinstance(value, bool):
            return_type = "bool"
            arg_key = "bool"
            value = "true" if value else "false"
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
                    **({"case": True} if case_sensitive and arg_key == "str" else {}),
                },
            },
            "rule_id": str(uuid.uuid4()),
        }

    def _sigma_string_to_hawk(self, value: SigmaString, contains: bool = False) -> tuple:
        """Translate a SigmaString (with its wildcard parts) into a hawk-ece value.

        Returns (value, is_regex). Plain strings (no wildcards) stay exact-match values so the
        engine can use its fast case-insensitive compare. Wildcards become an anchored PCRE:
        `*` -> `.*`, `?` -> `.`; escaped wildcards stay literal. A wildcard only at the edges
        yields the familiar startswith/endswith/contains anchoring; a wildcard in the middle is
        fully anchored because Sigma strings match the whole field value.
        """
        parts = list(value.s)
        if not value.contains_special():
            plain = "".join(str(p) for p in parts)
            if contains:
                return ".*" + re.escape(plain) + ".*", True
            return plain, False
        out: list = []
        for p in parts:
            if p == SpecialChars.WILDCARD_MULTI:
                out.append(".*")
            elif p == SpecialChars.WILDCARD_SINGLE:
                out.append(".")
            else:
                out.append(re.escape(str(p)))
        rx = "".join(out)
        if contains:
            if not rx.startswith(".*"):
                rx = ".*" + rx
            if not rx.endswith(".*"):
                rx = rx + ".*"
        starts_open = rx.startswith(".*")
        ends_open = rx.endswith(".*")
        if starts_open and ends_open:
            return rx, True             # contains
        if starts_open:
            return rx[2:] + "$", True   # endswith
        if ends_open:
            return "^" + rx[:-2], True  # startswith
        return "^" + rx + "$", True     # wildcard in the middle: whole-value match

    _XML_ENTITY_ALTS = (("&", "(?:&|&amp;)"), ("<", "(?:<|&lt;)"), (">", "(?:>|&gt;)"), ('"', '(?:"|&quot;)'))

    def _tolerate_xml_entities(self, value: Any, is_regex: bool):
        """Match XML-bearing values whether the feed delivers them raw or entity-encoded.

        hawkagentd renders EventData such as TaskContent / TemplateContent with the XML
        entities still escaped (a live 4698 event carries literally `&lt;Arguments&gt;`), so a
        Sigma value like `<Arguments>/c ` would never match. Accept both spellings.
        """
        if not isinstance(value, str) or not any(ch in value for ch in "<>"):
            return value, is_regex
        if not is_regex:
            value = "^" + re.escape(value) + "$"
        out = []
        i = 0
        while i < len(value):
            ch = value[i]
            if ch == "\\" and i + 1 < len(value):
                out.append(value[i:i + 2])
                i += 2
                continue
            out.append(dict(self._XML_ENTITY_ALTS).get(ch, ch))
            i += 1
        return "".join(out), True

    def _normalize_connector_value(self, norm_key: str, value: Any, is_regex: bool):
        """Live value vocabularies that differ from Sigma's (verified 2026-09-25)."""
        if norm_key == "ResultStatus" and isinstance(value, str) and not is_regex:
            v = value.lower()
            if v in ("success", "succeeded"):
                return norm_key, "^Succe", True   # Management API: "Success" / "Succeeded"
            if v in ("failure", "failed"):
                return norm_key, "^Fail", True
        if norm_key == "audit_login" and not is_regex:
            # Sigma ResultType 0 == successful sign-in; anything else is a failure code
            try:
                return norm_key, (int(value) == 0), False
            except (TypeError, ValueError):
                return norm_key, value, is_regex
        return norm_key, value, is_regex

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
        # Category rules: one gate that ORs every live source of that event class, so the
        # vendor-neutral detection logic applies across Sysmon, Security auditing, EDR, ...
        alternatives = self.logsource_enricher.category_sources(rule.logsource)
        if alternatives:
            groups: list[dict] = []
            for conditions in alternatives:
                leaves = self._nodes_from_conditions(conditions)
                if not leaves:
                    continue
                groups.append(leaves[0] if len(leaves) == 1 else {"id": "and", "key": "And", "children": leaves})
            if len(groups) == 1:
                return [groups[0]] if groups[0].get("class") else groups[0]["children"]
            if groups:
                return [{"id": "or", "key": "Or", "children": self._dedupe_children(groups)}]
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

