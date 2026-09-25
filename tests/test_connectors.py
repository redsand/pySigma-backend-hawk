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
