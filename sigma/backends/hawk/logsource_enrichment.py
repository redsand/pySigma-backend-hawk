from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable, List

import yaml


_CONFIG_PATH = Path(__file__).resolve().parent / "config" / "logsource_enrichments.yml"
_CATEGORY_PATH = Path(__file__).resolve().parent / "config" / "category_sources.yml"


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
        try:
            cats = yaml.safe_load(_CATEGORY_PATH.read_text(encoding="utf-8")) or {}
        except FileNotFoundError:
            cats = {}
        self._categories: dict = {
            str(name).lower(): [src.get("gate", {}) for src in (entry.get("sources") or []) if src.get("gate")]
            for name, entry in (cats.get("categories") or {}).items()
        }

    def category_sources(self, logsource: Any) -> List[dict]:
        """Cross-vendor gate alternatives for a category rule (OR of per-source conditions).

        Applies to Windows (or product-less) category rules; the registry is the single place
        where "which live sources carry this event class" is recorded.
        """
        category = getattr(logsource, "category", None)
        product = str(getattr(logsource, "product", "") or "").lower()
        if not category or product not in ("windows", ""):
            return []
        return list(self._categories.get(str(category).lower(), []))

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
