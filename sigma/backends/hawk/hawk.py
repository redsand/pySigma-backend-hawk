import re
import uuid
from typing import Any, ClassVar, Dict, Optional

from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
)
from sigma.conversion.base import TextQueryBackend
from sigma.rule import SigmaRule
from sigma.types import CompareOperators, SigmaBool, SigmaCompareExpression, SigmaNumber, SigmaRegularExpression

from .field_mapper import FieldMapper


class hawkBackend(TextQueryBackend):
    name: ClassVar[str] = "HAWK"
    formats: ClassVar[Dict[str, str]] = {"default": "HAWK score JSON records"}
    default_format: ClassVar[str] = "default"

    def __init__(self, processing_pipeline=None, collect_errors: bool = False, **kwargs):
        super().__init__(processing_pipeline=processing_pipeline, collect_errors=collect_errors, **kwargs)
        self.field_mapper = FieldMapper()

    def convert_rule(self, rule: SigmaRule, output_format: Optional[str] = None, callback=None) -> list[Any]:
        if not hasattr(self, "last_processing_pipeline") or self.last_processing_pipeline is None:
            self.init_processing_pipeline(output_format)

        self.last_processing_pipeline.apply(rule)
        results = []
        for index, cond in enumerate(rule.detection.parsed_condition):
            tree = self._generate_node(cond.parsed)
            score = self._build_record(rule, [tree])
            if callback is not None:
                score = callback(rule, output_format, index, cond, score)
            if score is not None:
                results.append(score)

        rule.set_conversion_result(results)
        return results if rule._output else []

    def finalize_output_default(self, queries: list[Any]) -> list[Any]:
        return queries

    def _build_record(self, rule: SigmaRule, children: list[dict]) -> dict:
        tags, techniques = self._normalize_tags_and_techniques(rule.tags or [])
        if self._is_experimental(rule) and "qa" not in tags:
            tags.append("qa")
        score, score_reason = self._calculate_score(rule)
        return {
            "hawk_id": str(rule.id) if rule.id is not None else str(uuid.uuid4()),
            "group_name": ".",
            "filter_name": rule.title or "Unnamed Sigma Rule",
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

    def _generate_node(self, node: Any, not_node: bool = False) -> dict:
        if isinstance(node, ConditionAND):
            return {"id": "and", "key": "And", "children": [self._generate_node(n, not_node) for n in node.args]}
        if isinstance(node, ConditionOR):
            return {"id": "or", "key": "Or", "children": [self._generate_node(n, not_node) for n in node.args]}
        if isinstance(node, ConditionNOT):
            if not node.args:
                raise NotImplementedError("NOT condition without arguments is not supported.")
            return self._generate_node(node.args[0], not_node=True)
        if isinstance(node, ConditionFieldEqualsValueExpression):
            return self._leaf_node(node.field, node.value, not_node)
        raise NotImplementedError(f"Unsupported node type: {type(node)}")

    def _leaf_node(self, key: str, raw_value: Any, not_node: bool) -> dict:
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
        if key == "Provider_Name" and isinstance(value, str) and value.startswith("Microsoft-Windows-"):
            norm_key = "product_name"
            value = value[len("Microsoft-Windows-"):]

        if not_node:
            comparison_op = "!=" if comparison_op == "=" else "="

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

