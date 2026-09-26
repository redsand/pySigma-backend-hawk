"""Third patch round (2026-09-26): correlation rules against the real engine semantics.

Engine facts driving this (hawk-ece/src/hawkcorr, verified 2026-09-26):
  * children evaluate in JSON order with And short-circuit; a stateful function leaf increments
    for every event that REACHES it, so it must be the last child after the base detection tree;
  * atomic_counter `limit` is minutes (5-minute blocks, 24h TTL); `<`/`<=` are meaningless;
  * atomic_distinct_counter `limit` is an inactivity window in minutes (HLL, ~5% error);
  * `statistic avg` never persists its sum and `quantiles` reads a field the loader never fills,
    so value_sum/value_avg go through statistic_window and percentile/median are refused;
  * float/double compare leaves cannot read values a function writes; an `int` leaf can;
  * an empty `columns` array is dropped by the loader and the leaf then always fails.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
b = ROOT / "sigma/backends/hawk/hawk.py"
u = b.read_bytes().decode("utf-8").replace("\r\n", "\n")

# ---- descriptors --------------------------------------------------------------------------
old = '''_QUANTILES_INPUTS: Dict[str, Any] = {'''
new = '''_STATISTIC_WINDOW_INPUTS: Dict[str, Any] = {
    "columns":         {"order": 0, "source": "columns",                  "type": "array"},
    "statistic":       {"order": 1, "source": "statistic_window_options", "type": "statistic_window_options"},
    "function_column": {"order": 2, "source": "columns",                  "type": "str"},
    "hour_range":      {"order": 3, "source": "",                         "type": "int"},
    "window_size":     {"order": 4, "source": "",                         "type": "int"},
    "new_column_name": {"order": 5, "source": "columns",                  "type": "str"},
}
_QUANTILES_INPUTS: Dict[str, Any] = {'''
assert old in u
u = u.replace(old, new, 1)

# ---- convert_rule: factor the base tree builder, apply the pipeline once per rule --------------
old = '''        self.last_processing_pipeline.apply(rule)
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
'''
new = '''        self._apply_pipeline_once(rule)
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
'''
assert old in u
u = u.replace(old, new, 1)

# ---- event_count ----------------------------------------------------------------------------
old = '''        """EVENT_COUNT correlation → atomic_counter function node."""
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
'''
new = '''        """EVENT_COUNT → base detection tree, then atomic_counter (counts only events that reach it).

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
'''
assert old in u
u = u.replace(old, new, 1)

# ---- value_count ----------------------------------------------------------------------------
old = '''        """VALUE_COUNT correlation → atomic_distinct_counter function node."""
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
'''
new = '''        """VALUE_COUNT → base detection tree, then atomic_distinct_counter.

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
'''
assert old in u
u = u.replace(old, new, 1)

# ---- temporal --------------------------------------------------------------------------------
old = '''    def convert_correlation_temporal_rule(self, rule, output_format=None, method="default") -> list[Any]:
        raise NotImplementedError("HAWK backend does not support temporal correlation rules.")

    def convert_correlation_temporal_ordered_rule(self, rule, output_format=None, method="default") -> list[Any]:
        raise NotImplementedError("HAWK backend does not support temporal_ordered correlation rules.")
'''
new = '''    def convert_correlation_temporal_rule(self, rule, output_format=None, method="default") -> list[Any]:
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
        rec["filter_details"] = rec["filter_details"] + "\\n\\n" + note
        return rec
'''
assert old in u
u = u.replace(old, new, 1)

# ---- percentile / median refused --------------------------------------------------------------
old = '''        """VALUE_PERCENTILE → quantiles + column comparison node."""
        return [self._build_quantiles_record(rule)]
'''
new = '''        """VALUE_PERCENTILE: refused. hawk-ece `quantiles` reads `percentile` from a field the
        score loader never populates and keeps per-process state with no timespan."""
        raise NotImplementedError("hawk-ece quantiles is not usable for value_percentile (engine reads an unset field).")
'''
assert old in u
u = u.replace(old, new, 1)
old = '''        """VALUE_MEDIAN → quantiles(0.5) + column comparison node."""
        return [self._build_quantiles_record(rule, percentile=0.5)]
'''
new = '''        """VALUE_MEDIAN: refused for the same reason as value_percentile."""
        raise NotImplementedError("hawk-ece quantiles is not usable for value_median (engine reads an unset field).")
'''
assert old in u
u = u.replace(old, new, 1)

# ---- record: base tree first, function leaves after ------------------------------------------
old = '''    def _build_correlation_record(self, rule: SigmaCorrelationRule, children: list[dict]) -> dict:
        """Build a HAWK score record for a correlation rule with a list of BETree child nodes."""
        tags, techniques = self._normalize_tags_and_techniques(rule.tags or [])'''
new = '''    def _build_correlation_record(self, rule: SigmaCorrelationRule, function_leaves: list[dict], base: Optional[dict] = None) -> dict:
        """Score record for a correlation: [base tree, function leaf, (compare leaf)] under the root And.

        The base tree is the referenced rule's own gate + detection, so the stateful leaf that
        follows it only ever sees events that matched the rule.
        """
        children = [base if base is not None else self._correlation_base(rule)] + list(function_leaves)
        tags, techniques = self._normalize_tags_and_techniques(rule.tags or [])'''
assert old in u
u = u.replace(old, new, 1)

# ---- statistic-based types via statistic_window --------------------------------------------------
old_start = u.index("    def _build_statistic_record(self, rule: SigmaCorrelationRule, stat_type: str) -> dict:")
old_end = u.index("    def _build_quantiles_record(")
new = '''    def _build_statistic_record(self, rule: SigmaCorrelationRule, stat_type: str) -> dict:
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

'''
u = u[:old_start] + new + u[old_end:]

b.write_bytes(u.replace("\n", "\r\n").encode("utf-8"))
print("hawk.py patched")
