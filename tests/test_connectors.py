import re

from sigma.backends.hawk import hawkBackend
from sigma.collection import SigmaCollection
from sigma.pipelines.hawk import hawk_pipeline


def _leaves(node):
    if isinstance(node, list):
        return [x for c in node for x in _leaves(c)]
    if not isinstance(node, dict):
        return []
    if node.get("class") in ("column", "function"):
        return [node]
    return [x for c in node.get("children", []) or [] for x in _leaves(c)]


def test_aws_fields_follow_json_key_to_column() -> None:
    rule = """
title: T
id: 44444444-2222-3333-4444-555555555555
status: test
level: high
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: 'iam.amazonaws.com'
        eventName: 'CreateAccessKey'
        userIdentity.type: 'Root'
        errorCode: 'AccessDenied'
    condition: selection
"""
    out = hawkBackend(processing_pipeline=hawk_pipeline()).convert(SigmaCollection.from_yaml(rule))
    keys = {l["key"] for l in _leaves(out[0]["rules"])}
    # table-mapped per json_key_to_column.cloudtrail
    assert {"product_name", "alert_name", "aws_auth_type", "error_code"} <= keys
    assert "user_identity.type" not in keys and "userIdentity.type" not in keys


def test_okta_fields_follow_json_key_to_column() -> None:
    rule = """
title: T
id: 55555555-2222-3333-4444-555555555555
status: test
level: high
logsource:
    product: okta
    service: okta
detection:
    selection:
        eventType: 'user.session.start'
        actor.alternateId|contains: '@corp'
        debugContext.debugData.requestUri|contains: '/api/'
    condition: selection
"""
    out = hawkBackend(processing_pipeline=hawk_pipeline()).convert(SigmaCollection.from_yaml(rule))
    keys = {l["key"] for l in _leaves(out[0]["rules"])}
    # table-mapped per json_key_to_column.okta
    assert {"correlation_username", "vendor_category"} <= keys
    # unmapped vendor keys pass through verbatim (the collector keeps the raw record)
    assert "debugContext.debugData.requestUri" in keys


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
    # ResultType is the Graph status.errorCode, emitted by the collector as errorCode
    assert leaves["errorCode"]["args"]["int"]["value"] == 0
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


def test_proxy_rule_gated_on_zscaler_with_uri_mapping() -> None:
    rule = """
title: T
id: 99999999-2222-3333-4444-555555555555
status: test
level: high
logsource:
    category: proxy
detection:
    selection:
        c-uri|contains: '/wp-content/plugins/'
        c-useragent|contains: 'python-requests'
    condition: selection
"""
    out = hawkBackend(processing_pipeline=hawk_pipeline()).convert(SigmaCollection.from_yaml(rule))
    leaves = {l["key"]: l for l in _leaves(out[0]["rules"])}
    assert leaves["product_name"]["args"]["str"]["value"] == "NSSWeblog"
    assert "http_path" in leaves and "http_user_agent" in leaves


def test_azure_auditlogs_message_maps_to_activity_display_name() -> None:
    rule = """
title: T
id: aaaaaaaa-2222-3333-4444-555555555555
status: test
level: high
logsource:
    product: azure
    service: auditlogs
detection:
    selection:
        properties.message: 'Add member to role'
        Status: 'Success'
        TargetResources.modifiedProperties.newValue|contains: 'Global Administrator'
    condition: selection
"""
    out = hawkBackend(processing_pipeline=hawk_pipeline()).convert(SigmaCollection.from_yaml(rule))
    leaves = {l["key"]: l for l in _leaves(out[0]["rules"])}
    assert leaves["activityDisplayName"]["args"]["str"]["value"] == "Add member to role"
    assert leaves["result"]["args"]["str"]["value"] == "success"
    assert "modifiedPropertyNewValue" in leaves
    assert leaves["product_source"]["args"]["str"]["value"] == "directoryAudits"


def _convert_azure(service: str, detection: str) -> dict:
    rule = """
title: T
id: bbbbbbbb-2222-3333-4444-555555555555
status: test
level: high
logsource:
    product: azure
    service: %s
detection:
%s
    condition: selection
""" % (service, detection)
    out = hawkBackend(processing_pipeline=hawk_pipeline()).convert(SigmaCollection.from_yaml(rule))
    return {l["key"]: l for l in _leaves(out[0]["rules"])}


def _hawk_match(leaf: dict, emitted: str) -> bool:
    # hawk-ece PCRE matching is case-insensitive by default
    return re.search(leaf["args"]["str"]["value"], emitted, re.IGNORECASE) is not None


def test_azure_empty_network_location_uses_collector_column() -> None:
    # Sign-ins by Unknown Devices: the collector emits networkLocationDetails as JSON ('[]').
    leaves = _convert_azure("signinlogs", """    selection:
        NetworkLocationDetails: '[]'
        DeviceDetail.deviceId: ''""")
    assert "locationCountry" not in leaves
    assert leaves["networkLocationDetails"]["args"]["str"]["value"] == "[]"
    assert leaves["deviceId"]["args"]["str"]["value"] == ""


def test_azure_admin_consent_matches_named_modified_property() -> None:
    # End User Consent: IsAdminConsent is a modified property whose Graph newValue is '"False"'.
    leaf = _convert_azure("auditlogs", """    selection:
        ConsentContext.IsAdminConsent: 'false'""")["modifiedPropertyPairs"]
    assert _hawk_match(leaf, 'ConsentContext.IsAdminConsent="False";ConsentContext.IsAppOnly="True"')
    # a different property holding False must not satisfy the rule
    assert not _hawk_match(leaf, 'ConsentContext.IsAdminConsent="True";ConsentContext.IsAppOnly="False"')


def test_azure_target_type_matches_graph_spelling_in_joined_list() -> None:
    # Sigma writes 'Service Principal'; Graph sends ServicePrincipal and the collector
    # comma-joins the distinct target types.
    leaf = _convert_azure("auditlogs", """    selection:
        TargetResources.type: 'Service Principal'""")["targetResourceType"]
    assert _hawk_match(leaf, "ServicePrincipal")
    assert _hawk_match(leaf, "User,ServicePrincipal")
    assert not _hawk_match(leaf, "User")
    assert not _hawk_match(leaf, "ServicePrincipalGroup")


def test_m365_threat_management_uses_alert_title_and_drops_eventsource() -> None:
    rule = """
title: T
id: bbbbbbbb-2222-3333-4444-555555555555
status: test
level: high
logsource:
    product: m365
    service: threat_management
detection:
    selection:
        eventSource: SecurityComplianceCenter
        eventName: 'Suspicious email sending patterns detected'
        status: success
    condition: selection
"""
    out = hawkBackend(processing_pipeline=hawk_pipeline()).convert(SigmaCollection.from_yaml(rule))
    keys = {l["key"] for l in _leaves(out[0]["rules"])}
    assert "title" in keys
    assert "event_source" not in keys and "ResultStatus" not in keys and "eventSource" not in keys


def test_azure_activitylogs_are_refused() -> None:
    import pytest
    rule = """
title: T
id: cccccccc-2222-3333-4444-555555555555
status: test
level: high
logsource:
    product: azure
    service: activitylogs
detection:
    selection:
        operationName: 'MICROSOFT.KEYVAULT/VAULTS/DELETE'
    condition: selection
"""
    with pytest.raises(Exception):
        hawkBackend(processing_pipeline=hawk_pipeline()).convert(SigmaCollection.from_yaml(rule))
