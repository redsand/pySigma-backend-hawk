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
_PRODUCT_TABLE = {"aws": "aws", "okta": "okta", "azure": "m365", "m365": "m365"}
CONNECTOR_PRODUCTS = tuple(_PRODUCT_TABLE)

# Sigma's Azure/M365 field names (Log Analytics / legacy o365 schema) -> the keys the HAWK M365
# collectors emit (Graph camelCase for signInAudits/directoryAudits, Management-API PascalCase for
# Exchange/AzureActiveDirectory/General/SharePoint, canonical event_source/event_name/title).
# Verified from live product_source profiles on 2026-09-25 (converter_validation/live).
_CROSSWALK = {
    "azure": {
        # directoryAudits (Graph)
        "ActivityDisplayName": "activityDisplayName",
        "OperationName": "activityDisplayName",
        "operationName": "activityDisplayName",
        "Category": "category",
        "LoggedByService": "loggedByService",
        "Result": "result",
        "ResultReason": "resultReason",
        "TargetResources.userPrincipalName": "target_username",
        "targetResources.userPrincipalName": "target_username",
        "InitiatedBy.user.userPrincipalName": "correlation_username",
        "initiatedBy.user.userPrincipalName": "correlation_username",
        # signInAudits (Graph)
        "ConditionalAccessStatus": "conditionalAccessStatus",
        "RiskState": "riskState",
        "RiskLevelDuringSignIn": "riskLevelDuringSignIn",
        "RiskLevelAggregated": "riskLevelAggregated",
        "RiskDetail": "riskDetail",
        "ClientAppUsed": "clientAppUsed",
        "UserAgent": "userAgent",
        "userAgent": "userAgent",
        "IPAddress": "ipAddress",
        "IpAddress": "ipAddress",
        "UserPrincipalName": "userPrincipalName",
        "ResourceDisplayName": "resourceDisplayName",
        "IsInteractive": "isInteractive",
        "HomeTenantId": "homeTenantId",
        "ResourceTenantId": "resourceTenantId",
        # ResultType 0 == success; the collector only keeps the success flag
        "ResultType": "audit_login",
    },
    "m365": {
        # Management Activity API records carry canonical event_source/event_name
        "eventSource": "event_source",
        "eventName": "event_name",
        "Operation": "event_name",
        "Workload": "event_source",
        "status": "ResultStatus",
        "ResultStatus": "ResultStatus",
        "UserId": "correlation_username",
        "ClientIP": "ip_src",
        "ClientIPAddress": "ip_src",
    },
}


def connector_field(product: str):
    table = _MAPS.get(_PRODUCT_TABLE[product], {})
    lower = {k.lower(): v for k, v in table.items()}
    cross = _CROSSWALK.get(product, {})

    def _map(name):
        if name is None:
            return name
        out = cross.get(name) or table.get(name) or lower.get(name.lower()) or name
        windows_unified.EMITTED.add(out)
        return out

    return _map
