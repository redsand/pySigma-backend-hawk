"""One-shot patch applying the first round of converter fixes (2026-09-25).

Kept in the repo so the change is reviewable as a script; the resulting diff is the source of truth.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
p = ROOT / "sigma/backends/hawk/hawk.py"
s = p.read_text(encoding="utf-8")

# 1. imports
s = s.replace(
    """from sigma.types import (
    CompareOperators,
    SigmaBool,
    SigmaCompareExpression,
    SigmaExpansion,
    SigmaFieldReference,
    SigmaNull,
    SigmaNumber,
    SigmaRegularExpression,
)""",
    """from sigma.types import (
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
)""",
)

# 2. tactics table
s = s.replace(
    "# inputs schema descriptors (UI metadata, not evaluated by C engine).",
    """# MITRE ATT&CK tactic slugs (as used in Sigma `attack.<tactic>` tags) -> tactic ids.
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

# inputs schema descriptors (UI metadata, not evaluated by C engine).""",
)

# 3. tactics in record
s = s.replace(
    """        tags, techniques = self._normalize_tags_and_techniques(rule.tags or [])
        if self._is_experimental(rule) and "qa" not in tags:""",
    """        tags, techniques = self._normalize_tags_and_techniques(rule.tags or [])
        tactics = self._normalize_tactics(rule.tags or [])
        if self._is_experimental(rule) and "qa" not in tags:""",
)
s = s.replace(
    """            "technique": techniques[0] if techniques else "",
            "tags": tags,
            "tactics": [],
        }""",
    """            # scores.technique is VARCHAR(16): a single technique id. The rest ride in tags.
            "technique": techniques[0] if techniques else "",
            "tags": tags,
            "tactics": tactics,
        }

    def _normalize_tactics(self, tags: list) -> list:
        out: list = []
        seen: set = set()
        for raw in tags:
            m = re.match(r"^attack\\.([a-z_\\-]+)$", str(raw).strip(), flags=re.IGNORECASE)
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
        return out""",
)

# 4. keyword nodes: substring semantics
s = s.replace(
    """        if isinstance(node, ConditionValueExpression):
            if isinstance(node.value, SigmaExpansion):
                return self._expand_sigma_expansion("payload", node.value, not_node)
            return self._leaf_node("payload", node.value, not_node)""",
    """        if isinstance(node, ConditionValueExpression):
            # Sigma keywords match anywhere in the event: substring semantics on payload.
            if isinstance(node.value, SigmaExpansion):
                return self._expand_sigma_expansion("payload", node.value, not_node, contains=True)
            return self._leaf_node("payload", node.value, not_node, contains=True)""",
)
s = s.replace(
    """    def _expand_sigma_expansion(
        self, field: str, expansion: SigmaExpansion, not_node: bool
    ) -> Optional[dict]:
        children: list[dict] = []
        for val in expansion.values:
            child = self._leaf_node(field, val, not_node)""",
    """    def _expand_sigma_expansion(
        self, field: str, expansion: SigmaExpansion, not_node: bool, contains: bool = False
    ) -> Optional[dict]:
        children: list[dict] = []
        for val in expansion.values:
            child = self._leaf_node(field, val, not_node, contains=contains)""",
)

# 5. leaf value handling rewrite
old_start = s.index("    def _leaf_node(self, key: str, raw_value: Any, not_node: bool) -> dict:")
old_end = s.index("        norm_key = self.field_mapper.map(key)\n        norm_key, value = self._normalize_hash_field(norm_key, value)")
new_leaf = '''    def _leaf_node(self, key: str, raw_value: Any, not_node: bool, contains: bool = False) -> dict:
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

'''
s = s[:old_start] + new_leaf + s[old_end:]

# 6. case flag on emitted str arg
s = s.replace(
    """                arg_key: {
                    "value": value,
                    **({"regex": True} if is_regex and arg_key == "str" else {}),
                },""",
    """                arg_key: {
                    "value": value,
                    **({"regex": True} if is_regex and arg_key == "str" else {}),
                    **({"case": True} if case_sensitive and arg_key == "str" else {}),
                },""",
)

# 7. helper for SigmaString parts
s = s.replace(
    "    def _normalize_hash_field(self, norm_key: str, value: Any) -> tuple[str, Any]:",
    '''    def _sigma_string_to_hawk(self, value: SigmaString, contains: bool = False) -> tuple:
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

    def _normalize_hash_field(self, norm_key: str, value: Any) -> tuple[str, Any]:''',
)
p.write_text(s, encoding="utf-8")
print("hawk.py patched")

# pipeline: gate Windows rules on event_channel, not hawk_source
pp = ROOT / "sigma/pipelines/hawk/hawk.py"
t = pp.read_text(encoding="utf-8")
t = t.replace(
    '''            ProcessingItem(
                identifier=f"hawk_windows_{service}",
                transformation=AddConditionTransformation({"hawk_source": source}),
                rule_conditions=[logsource_windows(service)],
            )''',
    '''            # Windows service -> channel gate. hawkagentd's unified Windows format stamps the
            # raw channel into `event_channel` (e.g. "Security", "Microsoft-Windows-Sysmon/Operational").
            # `hawk_source` is only set by file-tailed JSON sources (Zeek, Suricata) and is never
            # present on Windows events, so gating on it made every Windows score dead.
            ProcessingItem(
                identifier=f"hawk_windows_{service}",
                transformation=AddConditionTransformation({"event_channel": source}),
                rule_conditions=[logsource_windows(service)],
            )''',
)
pp.write_text(t, encoding="utf-8")
print("pipeline patched")

# dependency pins
py = ROOT / "pyproject.toml"
u = py.read_text(encoding="utf-8")
u = u.replace('pysigma = "0.11.16"', 'pysigma = "^1.5.1"').replace('sigma-cli = "1.0.4"', 'sigma-cli = "^3.1.0"').replace('python = "^3.8"', 'python = "^3.10"')
py.write_text(u, encoding="utf-8")
print("pyproject patched")
