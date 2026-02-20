import os
import re

import yaml


class FieldMapper:
    def __init__(self):
        path = os.path.join(os.path.dirname(__file__), "config", "hawk_field_config.yml")
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
                self.mappings = data.get("fieldmappings", {})
        else:
            self.mappings = {}
        self._ci_mappings = {str(k).lower(): v for k, v in self.mappings.items()}
        self._snake_mappings = {self._normalize_fallback(str(k)): v for k, v in self.mappings.items()}
        self._compact_mappings = {self._compact(str(k)): v for k, v in self.mappings.items()}

    def _compact(self, value: str) -> str:
        return re.sub(r"[^a-z0-9]+", "", str(value).lower())

    def _normalize_fallback(self, field: str) -> str:
        # Legacy backend normalized fields to snake_case and lower-cased symbols.
        value = str(field).strip()
        if not value:
            return ""
        value = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value)
        value = re.sub(r"[^A-Za-z0-9]+", "_", value)
        value = re.sub(r"_+", "_", value).strip("_")
        return value.lower()

    def map(self, field: str) -> str:
        mapped = self.mappings.get(field)
        if mapped is None:
            mapped = self._ci_mappings.get(str(field).lower())
        if mapped is None:
            mapped = self._snake_mappings.get(self._normalize_fallback(str(field)))
        if mapped is None:
            mapped = self._compact_mappings.get(self._compact(str(field)))
        if isinstance(mapped, list) and mapped:
            mapped = mapped[0]
        if isinstance(mapped, str):
            return mapped.lower()
        return self._normalize_fallback(field)
