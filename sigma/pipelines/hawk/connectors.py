"""Field naming for events produced by the HAWK cloud collectors (hawk-ece/scripts/hawk_*.py).

Those collectors bypass the .hwk rules (force_matching = -1). They emit the flattened vendor record
verbatim plus the canonical columns listed in hawk-ece-rules/py3/json_key_to_column.py. So a Sigma
field name maps to the table's column when the table names one, and otherwise stays as the vendor
key it already is. The tables are bundled as config/connector_field_maps.json (regenerate from
json_key_to_column.py with converter_validation tooling when the rules package changes).
"""
import json
import re
from pathlib import Path

from sigma.processing.transformations.values import ValueTransformation
from sigma.types import SigmaRegularExpression, SigmaString

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
        "Parameters": "Parameters",
        "OperationProperties": "OperationProperties",
        "ModifiedProperties": "ModifiedProperties",
        "ClientIP": "ip_src",
        "ClientIPAddress": "ip_src",
    },
}


# (product, service) -> {sigma field: HAWK column}. Checked from live product_source samples on
# 2026-09-29 (converter_validation/live/m365_samples.json) plus the collector contract in
# reports/prompt_m365_collector.md for columns being added.
SERVICE_CROSSWALK = {
    ("azure", "signinlogs"): {
        "ResultType": "errorCode",
        "Status": "audit_login",
        "ResultDescription": "failureReason", "Resultdescription": "failureReason",
        "resultDescription": "failureReason", "failure_status_reason": "failureReason",
        "AuthenticationRequirement": "authenticationRequirement",
        "ClientApp": "clientAppUsed", "ClientAppUsed": "clientAppUsed",
        "ConditionalAccessStatus": "conditionalAccessStatus", "conditionalAccessStatus": "conditionalAccessStatus",
        "RiskState": "riskState", "riskState": "riskState",
        "RiskLevelDuringSignIn": "riskLevelDuringSignIn", "RiskLevelAggregated": "riskLevelAggregated",
        "RiskDetail": "riskDetail", "riskEventType": "riskEventTypes",
        "ResourceDisplayName": "resourceDisplayName", "resourceDisplayName": "resourceDisplayName",
        "AppDisplayName": "appDisplayName", "AppId": "appId",
        "UserPrincipalName": "userPrincipalName", "Username": "userPrincipalName",
        "userAgent": "userAgent", "UserAgent": "userAgent",
        "IPAddress": "ipAddress", "IpAddress": "ipAddress",
        "IsInteractive": "isInteractive",
        "DeviceDetail.deviceId": "deviceId", "DeviceDetail.trusttype": "deviceTrustType",
        "DeviceDetail.trustType": "deviceTrustType", "DeviceDetail.isCompliant": "deviceIsCompliant",
        "DeviceDetail.isManaged": "deviceIsManaged", "DeviceDetail.operatingSystem": "deviceOperatingSystem",
        "DeviceDetail.browser": "deviceBrowser",
        "NetworkLocationDetails": "networkLocationDetails", "Location": "locationCountry",
        "properties.message": "failureReason",
    },
    ("azure", "auditlogs"): {
        "properties.message": "activityDisplayName",
        "ActivityDisplayName": "activityDisplayName", "activityDisplayName": "activityDisplayName",
        "OperationName": "activityDisplayName", "operationName": "activityDisplayName",
        "ActivityType": "activityDisplayName", "activityType": "activityDisplayName",
        "Category": "category", "category": "category",
        "LoggedByService": "loggedByService", "loggedByService": "loggedByService",
        "Status": "result", "Result": "result", "properties.result": "result", "result": "result",
        "ResultReason": "resultReason", "failure_status_reason": "resultReason",
        "OperationType": "operationType",
        "InitiatedBy": "correlation_username", "Initiatedby": "correlation_username",
        "initiatedBy.user.userPrincipalName": "correlation_username",
        "Target": "target_username", "TargetResources.userPrincipalName": "target_username",
        "targetResources.userPrincipalName": "target_username",
        "TargetResources.type": "targetResourceType", "targetResources.type": "targetResourceType",
        "TargetResources.displayName": "targetResourceName",
        "TargetResources": "targetResourceName", "properties.targetResources": "targetResourceName",
        "TargetResources.modifiedProperties": "modifiedPropertyName",
        "TargetResources.ModifiedProperties.DisplayName": "modifiedPropertyName",
        "TargetResources.modifiedProperties.displayName": "modifiedPropertyName",
        "TargetResources.modifiedProperties.newValue": "modifiedPropertyNewValue",
        "TargetResources.ModifiedProperties.NewValue": "modifiedPropertyNewValue",
        "TargetResources.modifiedProperties.oldValue": "modifiedPropertyOldValue",
        "ConsentContext.IsAdminConsent": "modifiedPropertyPairs",
        "additionalDetails.additionalInfo": "additionalDetails", "AdditionalDetails": "additionalDetails",
    },
    ("m365", "threat_management"): {
        "eventName": "title", "EventName": "title",
        "Payload": "description",
    },
}
DROP_FIELDS = {("m365", "threat_management"): ["eventSource", "status"]}

# Sigma auditlogs fields that are really directoryAudits modified-property names. The collector
# writes modifiedPropertyPairs as "Name=NewValue;..." with Graph's JSON-quoted values
# (ConsentContext.IsAdminConsent="False"), so the value must be matched beside its name.
MODIFIED_PROPERTY_FIELDS = ["ConsentContext.IsAdminConsent"]


class ModifiedPropertyPairTransformation(ValueTransformation):
    """Rewrite `<property>: value` into a regex over the named pair in modifiedPropertyPairs."""

    def apply_value(self, field: str, val: SigmaString):
        if val.contains_special():
            return None
        return SigmaRegularExpression('(^|;)%s="?%s"?(;|$)' % (re.escape(field), re.escape(str(val))))


def service_field(product: str, service: str):
    cross = SERVICE_CROSSWALK[(product, service)]
    lower = {k.lower(): v for k, v in cross.items()}

    def _map(name):
        if name is None:
            return name
        out = cross.get(name) or lower.get(name.lower())
        if out is None:
            out = connector_field(product)(name)
        windows_unified.EMITTED.add(out)
        return out

    return _map


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
