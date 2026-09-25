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
