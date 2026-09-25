from sigma.backends.hawk import hawkBackend
from sigma.collection import SigmaCollection
from sigma.pipelines.hawk import hawk_pipeline
from sigma.pipelines.hawk.windows_unified import uncamel, windows_unified_field


def test_uncamel_matches_engine_behaviour() -> None:
    # observed live: SourceProcessGUID -> source_process_g_u_iD, CallerPID -> caller_p_iD
    assert uncamel("SourceProcessGUID") == "source_process_g_u_iD"
    assert uncamel("OriginalFileName") == "original_file_name"
    assert uncamel("IntegrityLevel") == "integrity_level"
    assert uncamel("User") == "user"
    assert uncamel("GrantedAccess") == "granted_access"
    assert uncamel("NewProcessName") == "new_process_name"
    assert uncamel("account type") is None  # no uppercase -> untouched by uncamel
    assert uncamel("Windows Firewall") == "windows_firewall"


def test_translation_table_wins_over_uncamel() -> None:
    assert windows_unified_field("TargetObject") == "object"
    assert windows_unified_field("TargetFilename") == "filename"
    assert windows_unified_field("ParentCommandLine") == "parent_command"
    assert windows_unified_field("SourceImage") == "parent_image"
    assert windows_unified_field("QueryName") == "hostname_dst"
    assert windows_unified_field("ProcessName") == "image"
    assert windows_unified_field("SubjectUserName") == "correlation_username"
    assert windows_unified_field("ScriptBlockText") == "value"
    assert windows_unified_field("EventID") == "vendor_id"
    assert windows_unified_field("Details") == "details"


def _leaves(node):
    if isinstance(node, list):
        return [x for c in node for x in _leaves(c)]
    if not isinstance(node, dict):
        return []
    if node.get("class") in ("column", "function"):
        return [node]
    return [x for c in node.get("children", []) or [] for x in _leaves(c)]


def test_pipeline_uses_unified_names_for_windows_rules() -> None:
    rule = """
title: T
id: 22222222-2222-3333-4444-555555555555
status: test
level: high
logsource:
    product: windows
    category: registry_set
detection:
    selection:
        TargetObject|contains: '\\CurrentVersion\\Run\\'
        Details|startswith: 'C:\\Users\\'
        Image|endswith: '\\reg.exe'
        OriginalFileName: 'reg.exe'
        User|contains: 'AUTHORI'
    condition: selection
"""
    out = hawkBackend(processing_pipeline=hawk_pipeline()).convert(SigmaCollection.from_yaml(rule))
    keys = {l["key"] for l in _leaves(out[0]["rules"])}
    assert {"object", "details", "image", "original_file_name", "user"} <= keys
    assert "object_target" not in keys and "filename" not in keys and "correlation_username" not in keys


def test_non_windows_rules_keep_generic_mapping() -> None:
    rule = """
title: T
id: 33333333-2222-3333-4444-555555555555
status: test
level: high
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        Image|endswith: '/nc'
        CommandLine|contains: '-e /bin/sh'
    condition: selection
"""
    out = hawkBackend(processing_pipeline=hawk_pipeline()).convert(SigmaCollection.from_yaml(rule))
    keys = {l["key"] for l in _leaves(out[0]["rules"])}
    assert {"image", "command"} <= keys


def test_process_creation_gate_is_cross_vendor_or() -> None:
    rule = r"""
title: T
id: 66666666-2222-3333-4444-555555555555
status: test
level: high
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\certutil.exe'
        CommandLine|contains: 'urlcache'
    condition: selection
"""
    out = hawkBackend(processing_pipeline=hawk_pipeline()).convert(SigmaCollection.from_yaml(rule))
    inner = out[0]["rules"][0]["children"][0]["children"]
    gate = inner[0]
    assert gate["id"] == "or", gate
    vids = set()
    for alt in gate["children"]:
        leaves = _leaves(alt)
        vids.add(next(l["args"]["str"]["value"] for l in leaves if l["key"] == "vendor_id"))
        assert any(l["key"] == "product_name" for l in leaves)
    assert vids == {"1", "4688"}
    # detection logic stays vendor-neutral canonical columns
    det = _leaves(inner[-1])
    assert {l["key"] for l in det} == {"image", "command"}
