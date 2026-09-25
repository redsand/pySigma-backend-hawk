import json
import os
import re

import yaml

from sigma.pipelines.hawk import windows_unified


class FieldMapper:
    def __init__(self):
        path = os.path.join(os.path.dirname(__file__), "config", "hawk_field_config.yml")
        self._ansi_re = re.compile(r"\x1b\[[0-9;]*m")
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
                self.mappings = data.get("fieldmappings", {})
        else:
            self.mappings = {}
        self._ci_mappings = {self._strip_ansi(str(k)).lower(): v for k, v in self.mappings.items()}
        self._snake_mappings = {self._normalize_fallback(self._strip_ansi(str(k))): v for k, v in self.mappings.items()}
        self._compact_mappings = {self._compact(self._strip_ansi(str(k))): v for k, v in self.mappings.items()}
        # Names that are already final HAWK columns must never be re-mapped: the pipeline's
        # Windows item emits them, and the compact-key fallback would otherwise fold e.g.
        # original_file_name back into the legacy OriginalFileName -> filename entry.
        cols_path = os.path.join(os.path.dirname(__file__), "config", "hawk_columns.json")
        self.known_columns = set()
        if os.path.exists(cols_path):
            with open(cols_path, "r", encoding="utf-8") as f:
                self.known_columns = set(json.load(f))
        self.known_columns.update(v.lower() for v in windows_unified._TRANSLATIONS.values())
        self.known_columns.update(windows_unified._OVERRIDES.values())

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

    def _strip_ansi(self, value: str) -> str:
        return self._ansi_re.sub("", value)

    def map(self, field: str) -> str:
        field_key = self._strip_ansi(str(field))
        plain = str(field)
        if field_key in self.known_columns or field_key in windows_unified.EMITTED:
            return field_key
        mapped = self.mappings.get(field)
        if mapped is None:
            mapped = self.mappings.get(field_key)
        if mapped is None:
            mapped = self._ci_mappings.get(field_key.lower())
        if mapped is None:
            mapped = self._snake_mappings.get(self._normalize_fallback(field_key))
        if mapped is None:
            mapped = self._compact_mappings.get(self._compact(field_key))
        if isinstance(mapped, list) and mapped:
            mapped = mapped[0]
        if isinstance(mapped, str):
            return mapped.lower()
        return self._normalize_fallback(plain)
