from sigma.backends.hawk import hawkBackend
from sigma.collection import SigmaCollection


def _convert_one(rule_yaml: str) -> dict:
    backend = hawkBackend()
    out = backend.convert(SigmaCollection.from_yaml(rule_yaml))
    assert isinstance(out, list)
    assert len(out) == 1
    assert isinstance(out[0], dict)
    return out[0]


def test_wildcard_regex_is_boolean() -> None:
    result = _convert_one(
        """
title: Wildcard Rule
id: 11111111-1111-1111-1111-111111111111
status: stable
level: high
logsource:
  product: windows
  category: process_creation
detection:
  sel:
    CommandLine: foo*
  condition: sel
"""
    )
    leaf = result["rules"][0]["children"][0]["children"][0]
    assert leaf["key"] == "command"
    assert leaf["args"]["str"]["regex"] is True
    assert isinstance(leaf["args"]["str"]["regex"], bool)


def test_mitre_technique_and_tag_normalization() -> None:
    result = _convert_one(
        """
title: Mitre Rule
id: 22222222-2222-2222-2222-222222222222
status: stable
level: medium
tags:
  - attack.execution
  - attack.t1055.012
logsource:
  product: windows
  category: process_creation
detection:
  sel:
    Image: rundll32.exe
  condition: sel
"""
    )
    assert "sigma" in result["tags"]
    assert "attack.t1055.012" in result["tags"]
    assert "T1055.012" in result["tags"]
    assert result["technique"] == "T1055.012"


def test_legacy_equivalent_scoring() -> None:
    result = _convert_one(
        """
title: Score Rule
id: 33333333-3333-3333-3333-333333333333
status: stable
level: high
falsepositives:
  - expected admin usage
  - known test machine
logsource:
  product: windows
  category: process_creation
detection:
  sel:
    Image: cmd.exe
  condition: sel
"""
    )
    # Legacy score: base 5 + status 5 + high 10 - (2*2 false positives) = 16
    assert result["correlation_action"] == 16.0
    assert "Scoring:" in result["filter_details"]


def test_parent_commandline_maps_to_authoritative_column() -> None:
    result = _convert_one(
        """
title: Parent Command Mapping
id: 55555555-5555-5555-5555-555555555555
status: stable
level: low
logsource:
  product: windows
  category: process_creation
detection:
  sel:
    ParentCommandLine: '*powershell*'
  condition: sel
"""
    )
    leaf = result["rules"][0]["children"][0]["children"][0]
    assert leaf["key"] == "parent_command"


def test_imagepath_maps_to_image() -> None:
    result = _convert_one(
        """
title: ImagePath Mapping
id: 66666666-6666-6666-6666-666666666666
status: stable
level: medium
logsource:
  product: windows
  category: process_creation
detection:
  sel:
    ImagePath: C:\\Windows\\System32\\cmd.exe
  condition: sel
"""
    )
    leaf = result["rules"][0]["children"][0]["children"][0]
    assert leaf["key"] == "image"


def test_originalfilename_maps_to_filename() -> None:
    result = _convert_one(
        """
title: OriginalFilename Mapping
id: 77777777-7777-7777-7777-777777777777
status: stable
level: medium
logsource:
  product: windows
  category: process_creation
detection:
  sel:
    OriginalFileName: rundll32.exe
  condition: sel
"""
    )
    leaf = result["rules"][0]["children"][0]["children"][0]
    assert leaf["key"] == "filename"


def test_hashes_sha_alias_maps_to_sha1_column() -> None:
    result = _convert_one(
        """
title: Hash Alias Mapping
id: 88888888-8888-8888-8888-888888888888
status: stable
level: high
logsource:
  product: windows
  category: process_creation
detection:
  sel:
    Hashes: SHA=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  condition: sel
"""
    )
    leaf = result["rules"][0]["children"][0]["children"][0]
    assert leaf["key"] == "file_hash_sha1"
    assert leaf["args"]["str"]["value"] == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"


def test_hashes_sha512_maps_to_sha512_column() -> None:
    result = _convert_one(
        """
title: Hash SHA512 Mapping
id: 99999999-9999-9999-9999-999999999999
status: stable
level: high
logsource:
  product: windows
  category: process_creation
detection:
  sel:
    Hashes: SHA512=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
  condition: sel
"""
    )
    leaf = result["rules"][0]["children"][0]["children"][0]
    assert leaf["key"] == "file_hash_sha512"


def test_experimental_status_does_not_get_plus_five_and_sets_qa_tag() -> None:
    result = _convert_one(
        """
title: Experimental Score Rule
id: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
status: experimental
level: high
logsource:
  product: windows
  category: process_creation
detection:
  sel:
    Image: cmd.exe
  condition: sel
"""
    )
    # Legacy-equivalent: base 5 + high 10 + experimental bonus 0
    assert result["correlation_action"] == 15.0
    assert "qa" in result["tags"]
