"""Field naming for events produced by the HAWK cloud collectors (hawk-ece/scripts/hawk_*.py).

Those collectors bypass the .hwk rules (force_matching = -1). They emit the flattened vendor record
verbatim plus the canonical columns listed in hawk-ece-rules/py3/json_key_to_column.py. So a Sigma
field name maps to the table's column when the table names one, and otherwise stays as the vendor
key it already is. The tables are bundled as config/connector_field_maps.json (regenerate from
json_key_to_column.py with converter_validation tooling when the rules package changes).
"""
import json
from pathlib import Path

from . import windows_unified

_MAPS_PATH = Path(__file__).resolve().parents[2] / "backends" / "hawk" / "config" / "connector_field_maps.json"
_MAPS: dict = json.loads(_MAPS_PATH.read_text(encoding="utf-8"))

# Sigma logsource product -> json_key_to_column table
_PRODUCT_TABLE = {"aws": "aws", "okta": "okta"}
CONNECTOR_PRODUCTS = tuple(_PRODUCT_TABLE)


def connector_field(product: str):
    table = _MAPS.get(_PRODUCT_TABLE[product], {})
    lower = {k.lower(): v for k, v in table.items()}

    def _map(name):
        if name is None:
            return name
        out = table.get(name) or lower.get(name.lower()) or name
        windows_unified.EMITTED.add(out)
        return out

    return _map
