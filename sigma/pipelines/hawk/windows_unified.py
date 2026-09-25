"""Windows field naming exactly as hawk-ece normalizes hawkagentd's unified event format.

hawk-ece-rules/sl_winnt_unified.hwk captures every `| Key=Value` pair of a Windows event and
inserts it as an alert attribute named by `HWKTranslateAndAdd` (hawk-ece/src/hawkcorr/hawk-match.c):

    1. exact lookup in the module's BeginTranslation table (From -> To);
    2. otherwise `uncamel(key)` (CamelCase -> snake_case, see below);
    3. otherwise the key unchanged.

This module reproduces that so a Sigma field name lands on the same column the engine populates.
The translation table is a verbatim extract (config/winnt_unified_translations.json); regenerate
it with converter_validation/patch_converter_v1.py's sibling when the .hwk changes.

A few names are handled before the table because the unified rule sets them from the event header
rather than from a Key=Value pair (EventID -> vendor_id, Channel -> event_channel, Provider_Name ->
product_name), or because pySigma synthesizes them (md5/sha1/sha256/Imphash from Hashes).
"""
import json
from pathlib import Path

_TABLE_PATH = Path(__file__).resolve().parents[2] / "backends" / "hawk" / "config" / "winnt_unified_translations.json"
_TRANSLATIONS: dict = json.loads(_TABLE_PATH.read_text(encoding="utf-8"))

# Header-derived and pySigma-synthesized names (not Key=Value captures).
_OVERRIDES = {
    "EventID": "vendor_id",
    "Channel": "event_channel",
    "Provider_Name": "product_name",
    "ProviderName": "product_name",
    "Computer": "resource_name",
    "ComputerName": "resource_name",
    "Hashes": "hashes",
    "md5": "file_hash_md5",
    "sha1": "file_hash_sha1",
    "sha256": "file_hash_sha256",
    "Imphash": "file_hash_imphash",
    "imphash": "file_hash_imphash",
}


def uncamel(value: str):
    """Port of uncamel() in hawk-ece/src/hawkcorr/hawk-match.c. Returns None when no uppercase."""
    if not value or not any(c.isupper() for c in value):
        return None
    ret = list(value)
    i = 0
    while i < len(ret):
        if i + 1 == len(ret):  # C loop breaks before touching the final character
            break
        if ret[i] in "/- ":
            ret[i] = "_"
        if ret[i].isupper() and i > 0 and ret[i - 1] != "_" and ret[i - 1].islower():
            ret.insert(i, "_")  # tmp[i] = '_', tmp[i+1] = tolower(ret[i]) ...
            ret[i + 1] = ret[i + 1].lower()
            i = 2  # C sets i = 1 and the for-loop increment makes it 2
            continue
        ret[i] = ret[i].lower()
        i += 1
    return "".join(ret)


# Column names this process has emitted; the backend FieldMapper leaves them untouched.
EMITTED: set = set()


def windows_unified_field(name):
    """Map a Sigma (raw Windows) field name to the column hawk-ece populates for it."""
    if name is None:
        return name
    if name in _OVERRIDES:
        out = _OVERRIDES[name]
    elif name in _TRANSLATIONS:
        # The table maps ProcessName -> "Image"; the Security-specific rules also populate
        # lowercase `image` on those events, so prefer the canonical lowercase column.
        out = _TRANSLATIONS[name].lower()
    else:
        out = uncamel(name) or name
    EMITTED.add(out)
    return out
