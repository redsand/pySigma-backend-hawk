
import uuid
import json
import re
from sigma.backends.base import SigmaBackend
from sigma.conditions import (
    ConditionAND, ConditionOR, ConditionNOT
)
from .field_mapper import FieldMapper

class hawkBackend(SigmaBackend):
    def __init__(self, config=None):
        super().__init__(config)
        self.field_mapper = FieldMapper()

    def convert(self, rule):
        tree = self._generate_node(rule.detection.condition)
        children = [tree]

        if hasattr(rule, 'parsed_agg') and rule.parsed_agg:
            agg_node = self._generate_aggregation(rule.parsed_agg, getattr(rule.detection, 'timeframe', None))
            if agg_node:
                children.append(agg_node)

        metadata = {
            "score_id": "180304",
            "hawk_id": rule.id or str(uuid.uuid4()),
            "group_name": ".",
            "filter_name": rule.title,
            "rules": [{
                "id": "and",
                "key": "And",
                "children": [{
                    "id": "and",
                    "key": "And",
                    "children": children
                }]
            }],
            "enabled": True,
            "public": True,
            "actions_category_name": "Add (+)",
            "filter_details": self._generate_details(rule),
            "references": "\\n".join(rule.references or []),
            "comments": "",
            "correlation_action": self._calculate_score(rule),
            "technique": "",
            "tags": str(rule.tags or []),
            "date_added": str(rule.date or "2023-01-01"),
            "last_updated": "2023-05-04 19:47:07",
            "tactics": "[ ]"
        }

        return json.dumps(metadata, indent=2)

    def _generate_node(self, node, not_node=False):
        if isinstance(node, ConditionAND):
            return {
                "id": "and",
                "key": "And",
                "children": [self._generate_node(n, not_node) for n in node.items]
            }
        elif isinstance(node, ConditionOR):
            return {
                "id": "or",
                "key": "Or",
                "children": [self._generate_node(n, not_node) for n in node.items]
            }
        elif isinstance(node, ConditionNOT):
            return self._generate_node(node.item, not_node=True)
        elif isinstance(node, tuple):
            return self._leaf_node(node, not_node)
        else:
            raise NotImplementedError(f"Unsupported node type: {type(node)}")

    def _leaf_node(self, item, not_node):
        key, value = item
        norm_key = self.field_mapper.map(key)

        if key == "Provider_Name":
            norm_key = "product_name"
            if isinstance(value, str) and value.startswith("Microsoft-Windows-"):
                value = value[len("Microsoft-Windows-"):]

        if isinstance(value, list):
            return {
                "id": "or",
                "key": "Or",
                "children": [self._leaf_node((key, v), not_node) for v in value]
            }

        comparison_op = "="
        return_type = "str"
        arg_key = "str"
        is_regex = False

        if "|" in key:
            field, modifier = key.split("|", 1)
            norm_key = self.field_mapper.map(field)

            if modifier == "startswith":
                value = "^" + re.escape(value)
                is_regex = True
            elif modifier == "endswith":
                value = re.escape(value) + "$"
                is_regex = True
            elif modifier == "contains":
                value = ".*" + re.escape(value) + ".*"
                is_regex = True
            elif modifier == "wildcard":
                value = re.escape(value).replace("\\*", ".*")
                is_regex = True
            elif modifier in ("lt", "le", "gt", "ge", "ne"):
                op_map = {"lt": "<", "le": "<=", "gt": ">", "ge": ">=", "ne": "!="}
                comparison_op = op_map[modifier]
                return_type = "int" if isinstance(value, int) else "float"
                arg_key = return_type
            elif modifier in ("eq", "=="):
                comparison_op = "="
            else:
                raise NotImplementedError(f"Unsupported modifier: {modifier}")
        else:
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
                "comparison": {"value": comparison_op if not_node is False else "!="},
                arg_key: {
                    "value": value,
                    **({"regex": "true"} if is_regex and arg_key == "str" else {})
                }
            },
            "rule_id": str(uuid.uuid4())
        }

    def _generate_details(self, rule):
        details = f"Sigma Rule: {rule.id}\\nAuthor: {rule.author or 'Unknown'}\\nLevel: {rule.level}\\n"
        if rule.falsepositives:
            details += "False Positives: " + ", ".join(rule.falsepositives) + "\\n"
        return details

    def _calculate_score(self, rule):
        score = 0.0
        if rule.status != "experimental":
            score += 5.0
        if rule.level:
            lvl = rule.level.lower()
            if lvl == "critical":
                score += 15.0
            elif lvl == "high":
                score += 10.0
            elif lvl == "low":
                score -= 10.0
            elif lvl == "informational":
                score -= 15.0
        return max(score, 0.0)

    def _generate_aggregation(self, agg, timeframe):
        if agg.aggfunc.lower() != "count":
            raise NotImplementedError(f"Aggregation function '{agg.aggfunc}' not supported.")

        columns = [self.field_mapper.map(agg.aggfield)]
        if agg.groupfield:
            columns.append(self.field_mapper.map(agg.groupfield))

        return {
            "key": "atomic_counter",
            "description": f"{agg.groupfield} count aggregation stream counter",
            "class": "function",
            "return": "int",
            "inputs": {
                "columns": {"order": 0, "source": "columns", "type": "array", "objectKey": "columns"},
                "comparison": {"order": 1, "source": "comparison", "type": "comparison", "objectKey": "comparison"},
                "threshold": {"order": 2, "source": "", "type": "int", "objectKey": "threshold"},
                "limit": {"order": 3, "source": "time_offset", "type": "int", "objectKey": "limit"}
            },
            "args": {
                "columns": columns,
                "comparison": {"value": agg.cond_op},
                "threshold": {"value": int(agg.condition)},
                "limit": {"value": self._parse_timeframe(timeframe or "60s")}
            },
            "rule_id": str(uuid.uuid4())
        }

    def _parse_timeframe(self, tf_str):
        units = {"s": 1, "m": 60, "h": 3600, "d": 86400}
        if not tf_str:
            return 60
        value = int(tf_str[:-1])
        unit = tf_str[-1]
        return value * units.get(unit, 1)

