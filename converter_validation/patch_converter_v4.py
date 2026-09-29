"""Patch round 4 (2026-09-29): Azure / M365 field translation from live data + collector contract.

Service-specific crosswalks (applied before the product-level connector item):
  * azure/signinlogs  -> Graph signIns as the M365 collector emits them (product_source signInAudits)
  * azure/auditlogs   -> Graph directoryAudits (product_source directoryAudits)
  * m365/threat_management -> Graph security alerts (product_source Alerts): the Sigma rule's
    eventSource/status leaves have no equivalent and are dropped; eventName is the alert title
  * azure/activitylogs (Azure Resource Manager activity log) is not collected: rules fail loudly
Column names for fields the collector does not emit yet (errorCode, failureReason,
authenticationRequirement, device*, modifiedProperty*, Parameters...) follow the contract in
converter_validation/reports/prompt_m365_collector.md, section 3.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# ---- connectors.py: service crosswalks ------------------------------------------------------
c = ROOT / "sigma/pipelines/hawk/connectors.py"
s = c.read_text(encoding="utf-8")
s = s.replace('''def connector_field(product: str):''', '''# (product, service) -> {sigma field: HAWK column}. Checked from live product_source samples on
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
        "NetworkLocationDetails": "locationCountry", "Location": "locationCountry",
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
        "ConsentContext.IsAdminConsent": "additionalDetails",
        "additionalDetails.additionalInfo": "additionalDetails", "AdditionalDetails": "additionalDetails",
    },
    ("m365", "threat_management"): {
        "eventName": "title", "EventName": "title",
        "Payload": "description",
    },
}
DROP_FIELDS = {("m365", "threat_management"): ["eventSource", "status"]}


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


def connector_field(product: str):''', 1)
# m365 product-level: Management API array fields go to their flattened canonical columns
s = s.replace('''        "UserId": "correlation_username",''', '''        "UserId": "correlation_username",
        "Parameters": "Parameters",
        "OperationProperties": "OperationProperties",
        "ModifiedProperties": "ModifiedProperties",''', 1)
c.write_text(s, encoding="utf-8")
print("connectors.py patched")

# ---- pipeline: service items, drops, activitylogs refusal ----------------------------------
p = ROOT / "sigma/pipelines/hawk/hawk.py"
u = p.read_bytes().decode("utf-8").replace("\r\n", "\n")
u = u.replace("from sigma.processing.transformations import AddConditionTransformation, FieldFunctionTransformation,",
              "from sigma.processing.transformations import AddConditionTransformation, DropDetectionItemTransformation, FieldFunctionTransformation,", 1)
u = u.replace("from .connectors import connector_field, CONNECTOR_PRODUCTS",
              "from .connectors import connector_field, service_field, CONNECTOR_PRODUCTS, SERVICE_CROSSWALK, DROP_FIELDS", 1)
old = '''        [
            # Cloud connectors: the Python collectors pass the flattened vendor record through'''
new = '''        [
            # Azure Resource Manager activity logs are not collected by any HAWK connector; a rule
            # for them would only ever match unrelated Azure (M365) events through its gate.
            ProcessingItem(
                identifier="hawk_refuse_azure_activitylogs",
                transformation=RuleFailureTransformation("Azure activity logs (ARM) are not collected by HAWK; no source to match."),
                rule_conditions=[LogsourceCondition(product="azure", service="activitylogs")],
            ),
        ] +
        [
            ProcessingItem(
                identifier=f"hawk_drop_{product}_{service}",
                transformation=DropDetectionItemTransformation(),
                rule_conditions=[LogsourceCondition(product=product, service=service)],
                field_name_conditions=[IncludeFieldCondition(fields)],
            )
            for (product, service), fields in DROP_FIELDS.items()
        ] +
        [
            # Service-specific crosswalks (Graph signIns / directoryAudits / security alerts) run
            # before the product-level connector item and win for the fields they name.
            ProcessingItem(
                identifier=f"hawk_service_fields_{product}_{service}",
                transformation=FieldFunctionTransformation({}, service_field(product, service)),
                rule_conditions=[LogsourceCondition(product=product, service=service)],
            )
            for (product, service) in SERVICE_CROSSWALK
        ] +
        [
            # Cloud connectors: the Python collectors pass the flattened vendor record through'''
assert old in u
u = u.replace(old, new, 1)
old = '''                identifier=f"hawk_connector_fields_{product}",
                transformation=FieldFunctionTransformation({}, connector_field(product)),
                rule_conditions=[LogsourceCondition(product=product)],
            )'''
new = '''                identifier=f"hawk_connector_fields_{product}",
                transformation=FieldFunctionTransformation({}, connector_field(product)),
                rule_conditions=[LogsourceCondition(product=product)],
                field_name_conditions=[FieldNameProcessingItemAppliedCondition(f"hawk_service_fields_{p}_{s}") for (p, s) in SERVICE_CROSSWALK],
                field_name_condition_linking=any,
                field_name_condition_negation=True,
            )'''
assert old in u
u = u.replace(old, new, 1)
old = '''                + [FieldNameProcessingItemAppliedCondition(f"hawk_connector_fields_{product}") for product in CONNECTOR_PRODUCTS],'''
new = '''                + [FieldNameProcessingItemAppliedCondition(f"hawk_connector_fields_{product}") for product in CONNECTOR_PRODUCTS]
                + [FieldNameProcessingItemAppliedCondition(f"hawk_service_fields_{p}_{s}") for (p, s) in SERVICE_CROSSWALK],'''
assert old in u
u = u.replace(old, new, 1)
p.write_bytes(u.replace("\n", "\r\n").encode("utf-8"))
print("pipeline patched")

# ---- backend value vocabularies: errorCode / audit_login / result ----------------------------
b = ROOT / "sigma/backends/hawk/hawk.py"
v = b.read_bytes().decode("utf-8").replace("\r\n", "\n")
old = '''        if norm_key == "audit_login" and not is_regex:
            # Sigma ResultType 0 == successful sign-in; anything else is a failure code
            try:
                return norm_key, (int(value) == 0), False
            except (TypeError, ValueError):
                return norm_key, value, is_regex
        return norm_key, value, is_regex'''
new = '''        if norm_key == "audit_login" and not is_regex:
            # sign-in Status: Success / Failure (and legacy ResultType 0 == success)
            sv = str(value).strip().lower()
            if sv in ("success", "succeeded", "0", "true"):
                return norm_key, True, False
            if sv in ("failure", "failed", "false"):
                return norm_key, False, False
            return norm_key, value, is_regex
        if norm_key == "errorCode" and isinstance(value, str) and value.strip().lstrip("-").isdigit() and not is_regex:
            return norm_key, int(value), False
        if norm_key == "result" and isinstance(value, str) and not is_regex:
            # directoryAudits result values are lower-case success / failure / clientError
            return norm_key, {"success": "success", "failure": "failure"}.get(value.lower(), value), False
        return norm_key, value, is_regex'''
assert old in v
v = v.replace(old, new, 1)
b.write_bytes(v.replace("\n", "\r\n").encode("utf-8"))
print("backend patched")
