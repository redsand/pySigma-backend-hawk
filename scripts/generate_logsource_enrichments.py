"""Dump logsource enrichment mapping derived from sigma.old/tools/config/hawk.yml."""
from pathlib import Path
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE = REPO_ROOT / "sigma.old" / "tools" / "config" / "hawk.yml"
TARGET = REPO_ROOT / "pySigma-backend-hawk" / "sigma" / "backends" / "hawk" / "config" / "logsource_enrichments.yml"

if not SOURCE.exists():
    raise SystemExit(f"source config not found: {SOURCE}")

with SOURCE.open("r", encoding="utf-8") as fh:
    data = yaml.safe_load(fh) or {}

logsources = data.get("logsources", {})
new_data = {"logsources": {}}
for name, entry in logsources.items():
    match = {}
    for field in ("product", "service", "category"):
        value = entry.get(field)
        if value is not None:
            match[field] = value
    conditions = entry.get("conditions")
    if not conditions:
        continue
    new_data["logsources"][name] = {
        "match": match,
        "conditions": conditions,
    }

target_parent = TARGET.parent
target_parent.mkdir(parents=True, exist_ok=True)
with TARGET.open("w", encoding="utf-8") as fh:
    yaml.dump(new_data, fh, sort_keys=False)

print(f"wrote {len(new_data['logsources'])} logsource entries to {TARGET}")
