"""Second patch round (2026-09-25): Azure/M365 crosswalk, value vocabularies, M365 gates."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# connectors: azure / m365 crosswalk on top of the m365 table
p = ROOT / "sigma/pipelines/hawk/connectors.py"
s = p.read_text(encoding="utf-8")
old = '''# Sigma logsource product -> json_key_to_column table
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
'''
new = '''# Sigma logsource product -> json_key_to_column table
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
'''
assert old in s
p.write_text(s.replace(old, new), encoding="utf-8")
print("connectors patched")

# backend: value normalizers for connector columns whose live values differ from Sigma's
b = ROOT / "sigma/backends/hawk/hawk.py"
u = b.read_bytes().decode("utf-8").replace("\r\n", "\n")
old = '''        norm_key = self.field_mapper.map(key)
        norm_key, value = self._normalize_hash_field(norm_key, value)
'''
new = '''        norm_key = self.field_mapper.map(key)
        norm_key, value, is_regex = self._normalize_connector_value(norm_key, value, is_regex)
        norm_key, value = self._normalize_hash_field(norm_key, value)
'''
assert old in u
u = u.replace(old, new)
old2 = "    def _normalize_hash_field(self, norm_key: str, value: Any) -> tuple[str, Any]:"
new2 = '''    def _normalize_connector_value(self, norm_key: str, value: Any, is_regex: bool):
        """Live value vocabularies that differ from Sigma's (verified 2026-09-25)."""
        if norm_key == "ResultStatus" and isinstance(value, str) and not is_regex:
            v = value.lower()
            if v in ("success", "succeeded"):
                return norm_key, "^Succe", True   # Management API: "Success" / "Succeeded"
            if v in ("failure", "failed"):
                return norm_key, "^Fail", True
        if norm_key == "audit_login" and not is_regex:
            # Sigma ResultType 0 == successful sign-in; anything else is a failure code
            try:
                return norm_key, (int(value) == 0), False
            except (TypeError, ValueError):
                return norm_key, value, is_regex
        return norm_key, value, is_regex

    def _normalize_hash_field(self, norm_key: str, value: Any) -> tuple[str, Any]:'''
assert old2 in u
u = u.replace(old2, new2, 1)
b.write_bytes(u.replace("\n", "\r\n").encode("utf-8"))
print("backend patched")

# yml: m365 gates -> product Azure + product_source
y = ROOT / "sigma/backends/hawk/config/logsource_enrichments.yml"
raw = y.read_bytes()
crlf = b"\r\n" in raw
t = raw.decode("utf-8").replace("\r\n", "\n")
old = """  microsoft365:
    match:
      product: m365
      service: threat_management
    conditions:
      vendor_name: Microsoft
      product_name: '365'
  m365:
    match:
      product: m365
      service: threat_management
    conditions:
      vendor_name: Microsoft
      product_name: '365'
"""
new = """  m365-threat-management:
    match:
      product: m365
      service: threat_management
    conditions:
      vendor_name: Microsoft
      product_name: Azure
      product_source:
      - Alerts
      - Incidents
      - DefenderAlerts
  m365-audit:
    match:
      product: m365
      service:
      - exchange
      - sharepoint
      - audit
      - azuread
      - azureactivedirectory
      - general
      - teams
      - onedrive
    conditions:
      vendor_name: Microsoft
      product_name: Azure
"""
assert old in t
t = t.replace(old, new)
y.write_bytes((t.replace("\n", "\r\n") if crlf else t).encode("utf-8"))
print("yml patched")

# tests
tp = ROOT / "tests/test_connectors.py"
tests = '''

def test_azure_signin_and_audit_fields_use_graph_keys() -> None:
    rule = """
title: T
id: 77777777-2222-3333-4444-555555555555
status: test
level: high
logsource:
    product: azure
    service: signinlogs
detection:
    selection:
        ResultType: 0
        ConditionalAccessStatus: 'failure'
        RiskState: 'atRisk'
    condition: selection
"""
    out = hawkBackend(processing_pipeline=hawk_pipeline()).convert(SigmaCollection.from_yaml(rule))
    leaves = {l["key"]: l for l in _leaves(out[0]["rules"])}
    assert leaves["audit_login"]["args"]["bool"]["value"] == "true"
    assert "conditionalAccessStatus" in leaves and "riskState" in leaves
    assert "product_source" in leaves


def test_m365_status_success_matches_management_api_vocabulary() -> None:
    rule = """
title: T
id: 88888888-2222-3333-4444-555555555555
status: test
level: high
logsource:
    product: m365
    service: exchange
detection:
    selection:
        eventSource: 'Exchange'
        eventName: 'Set-Mailbox'
        status: 'success'
    condition: selection
"""
    out = hawkBackend(processing_pipeline=hawk_pipeline()).convert(SigmaCollection.from_yaml(rule))
    leaves = {l["key"]: l for l in _leaves(out[0]["rules"])}
    assert leaves["event_source"]["args"]["str"]["value"] == "Exchange"
    assert leaves["event_name"]["args"]["str"]["value"] == "Set-Mailbox"
    assert leaves["ResultStatus"]["args"]["str"] == {"value": "^Succe", "regex": True}
'''
if "test_azure_signin_and_audit_fields_use_graph_keys" not in tp.read_text(encoding="utf-8"):
    tp.write_text(tp.read_text(encoding="utf-8") + tests, encoding="utf-8")
print("tests added")
