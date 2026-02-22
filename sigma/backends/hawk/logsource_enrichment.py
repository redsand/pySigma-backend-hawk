from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable, List

import yaml


_CONFIG_PATH = Path(__file__).resolve().parent / "config" / "logsource_enrichments.yml"


class LogSourceEnrichmentEntry:
    __slots__ = ("match", "conditions")

    def __init__(self, match: dict[str, Any], conditions: dict[str, Any]) -> None:
        self.match = {k: v for k, v in match.items() if v is not None}
        self.conditions = conditions


class LogSourceEnricher:
    def __init__(self, config_path: Path | None = None) -> None:
        path = config_path or _CONFIG_PATH
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except FileNotFoundError:
            self._entries: List[LogSourceEnrichmentEntry] = []
            return
        logsources = raw.get("logsources", {})
        self._entries = [
            LogSourceEnrichmentEntry(entry.get("match", {}), entry.get("conditions", {}))
            for entry in logsources.values()
            if entry.get("conditions")
        ]

    def match(self, logsource: Any) -> Iterable[dict[str, Any]]:
        for entry in self._entries:
            if self._matches(entry.match, logsource):
                yield entry.conditions

    def _matches(self, match: dict[str, Any], logsource: Any) -> bool:
        if not match:
            return False
        for key, expected in match.items():
            actual = getattr(logsource, key, None)
            if actual is None:
                return False
            if isinstance(expected, (list, tuple)):
                allowed = {str(item).lower() for item in expected}
                if str(actual).lower() not in allowed:
                    return False
            else:
                if str(actual).lower() != str(expected).lower():
                    return False
        return True
