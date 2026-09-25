#!/usr/bin/env python3
"""Build connector_inventory.json: taxonomy constants + emitted column names per HAWK cloud connector.

Sources:
  * hawk-ece/scripts/*.py            (AST walk of record[...] = ..., .setdefault(), record-like dict literals)
  * hawk-ece-rules/py3/json_key_to_column.py (table-driven vendor-key -> HAWK column maps)
  * hawk-ece-rules/*.hwk             (Source="col: val; ..." directives for syslog/CEF-fed connectors)
  * hawk-data/app/tpls/pulse_templates.json (template name/id -> LOCALSCRIPT)
"""
import ast
import json
import os
import re
import gzip
import sys
from collections import defaultdict

REPOS = r'C:\Users\tshel\source\repos'
SCRIPTS = os.path.join(REPOS, 'hawk-ece', 'scripts')
RULES = os.path.join(REPOS, 'hawk-ece-rules')
J2C = os.path.join(RULES, 'py3', 'json_key_to_column.py')
TPLS = os.path.join(REPOS, 'hawk-data', 'app', 'tpls', 'pulse_templates.json')
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'connector_inventory.json')

TAXONOMY_KEYS = ['product_name', 'vendor_name', 'vendor_type', 'class_type', 'class_name',
                 'hawk_source', 'product_source', 'event_channel', 'alerts_type_name',
                 'alerts_type_category', 'os_type_name', 'resource_name', 'event_type', 'hid']
SEED_KEYS = {'alert_name', 'vendor_name', 'product_name', 'alerts_type_name', 'hid', 'priority',
             'force_matching', 'ip_src', 'correlation_username', 'payload', 'line', 'status',
             'product_source', 'vendor_type'}

# connector -> spec
CONNECTORS = {
    'aws_cloudtrail':        {'py': ['hawk_amazon_cloudtrail.py'], 'hwk': []},
    'aws_guardduty':         {'py': ['hawk_amazon_guardduty.py'], 'hwk': ['sl_ids_amazon_guardduty.hwk']},
    'aws_waf':               {'py': ['hawk_amazon_waf.py'], 'hwk': []},
    'azure_repos':           {'py': ['hawk_azure_repos.py'], 'hwk': []},
    'bloodhound_enterprise': {'py': ['hawk_bloodhound.py'], 'hwk': []},
    'canary_tools':          {'py': ['hawk_canary.py'], 'hwk': []},
    'cisco_cloud_web_security': {'py': ['hawk_cisco_cloud_web_security.py'], 'hwk': ['sl_cisco_cloud_web_security.hwk']},
    'claude_compliance':     {'py': ['hawk_claude.py'], 'hwk': []},
    'code42':                {'py': ['hawk_code42.py'], 'hwk': []},
    'crowdstrike_falcon':    {'py': ['hawk_crowdstrike.py'], 'hwk': []},
    'duo_mfa':               {'py': ['hawk_duo_mfa.py'], 'hwk': ['sl_auth_duo.hwk']},
    'grammarly':             {'py': ['hawk_grammarly.py'], 'hwk': []},
    'ivanti_neurons':        {'py': ['hawk_ivanti.py'], 'hwk': ['sl_ivanti_neurons.hwk']},
    'lastpass':              {'py': ['hawk_lastpass.py'], 'hwk': []},
    'm365_wrapper':          {'py': ['hawk_microsoft_m365.py'], 'hwk': []},
    'm365_signin':           {'py': ['hawk_m365_signin.py'], 'hwk': []},
    'm365_directory':        {'py': ['hawk_m365_directory.py'], 'hwk': []},
    'm365_identity_protection': {'py': ['hawk_m365_identity_protection.py'], 'hwk': []},
    'm365_security_alerts':  {'py': ['hawk_m365_security_alerts.py'], 'hwk': []},
    'm365_defender_xdr':     {'py': ['hawk_m365_defender_xdr.py'], 'hwk': []},
    'm365_entra':            {'py': ['hawk_m365_entra.py'], 'hwk': []},
    'm365_threat_intel':     {'py': ['hawk_m365_threat_intel.py'], 'hwk': []},
    'm365_activity':         {'py': ['hawk_m365_activity.py'], 'hwk': []},
    'm365_audit_logs':       {'py': ['hawk_m365_audit_logs.py'], 'hwk': []},
    'm365_app_risk':         {'py': ['hawk_m365_app_risk.py', 'hawk_m365_snapshot_mixin.py'], 'hwk': []},
    'm365_directory_inventory': {'py': ['hawk_m365_directory_inventory.py', 'hawk_m365_snapshot_mixin.py'], 'hwk': []},
    'm365_identity_posture': {'py': ['hawk_m365_identity_posture.py', 'hawk_m365_snapshot_mixin.py'], 'hwk': []},
    'm365_legacy_monolith':  {'py': ['hawk_microsoft_m365-logins.py'], 'hwk': [], 'legacy': True},
    'm365_legacy_new':       {'py': ['hawk_microsoft_m365_new.py'], 'hwk': [], 'legacy': True},
    'm365_legacy_azure_audit': {'py': ['hawk_microsoft_m365_azure_audit.py'], 'hwk': [], 'legacy': True},
    'm365_legacy_azure_directory_audit': {'py': ['hawk_microsoft_m365_azure_directory_audit.py'], 'hwk': [], 'legacy': True},
    'm365_legacy_teams_calls': {'py': ['hawk_microsoft_m365_teams_calls.py'], 'hwk': [], 'legacy': True},
    'microsoft_cloud_app_security': {'py': ['hawk_cas/hawk_microsoft_cas.py'], 'hwk': ['sl_microsoft_cloud.hwk']},
    'netskope':              {'py': ['hawk_netskope_v1.py'], 'hwk': []},
    'okta':                  {'py': ['hawk_okta.py'], 'hwk': []},
    'ping_identity_cloud':   {'py': ['hawk_ping_identity_cloud.py'], 'hwk': []},
    'proofpoint_tap':        {'py': ['hawk_proofpoint.py'], 'hwk': ['sl_mail_proofpoint_pulse.hwk']},
    'proofpoint_dashboard':  {'py': ['hawk_proofpoint_dashboard.py'], 'hwk': []},
    'proofpoint_trap':       {'py': ['hawk_proofpoint_threat_response.py'], 'hwk': []},
    'sentinelone':           {'py': ['hawk_sentinel_one.py'], 'hwk': []},
    'slack':                 {'py': ['hawk_slack_sdk/hawk_slack_sdk.py'], 'hwk': []},
    'snowflake':             {'py': ['hawk_snowflake.py'], 'hwk': []},
    'spycloud':              {'py': ['hawk_spycloud.py'], 'hwk': ['sl_darkweb_spycloud.hwk']},
    'sucuri_waf':            {'py': ['hawk_sucuri_waf.py'], 'hwk': []},
    'threatlocker':          {'py': ['hawk_threatlocker.py'], 'hwk': []},
    'varonis_datalert':      {'py': ['hawk_varonis.py'], 'hwk': ['sl_ids_varonis.hwk', 'sl_ids_varonis_cef.hwk']},
    'workday':               {'py': ['hawk_workday2.py', 'hawk_workday.py'], 'hwk': []},
    'zscaler_nss':           {'py': [], 'hwk': ['sl_zscaler_nss.hwk'], 'syslog_only': True},
    'tenable_io':            {'py': ['hawk_tenableio.py', 'hawk_pytenable_new_assets.py', 'hawk_pytenable_expire_assets.py'], 'hwk': [], 'vuln': True},
}

MANUAL_NOTES = {
    'aws_cloudtrail': ['hawk_record = flat_record (hawk_amazon_cloudtrail.py:565): ALL flattened CloudTrail keys (userIdentity.arn, requestParameters.*, responseElements.*, eventName, ...) are emitted verbatim as dotted/camelCase attributes alongside the json_key_to_column.cloudtrail targets; eventName->alert_name is camel_case_split()',
                       'product_name is NOT a constant: cloudtrail map sets product_name = eventSource (e.g. "iam.amazonaws.com", "s3.amazonaws.com")'],
    'aws_guardduty': ['python sends the raw boto3 finding dict as JSON with NO force_matching; JSONToAlert loads every finding key (Service_Action_..., Resource_InstanceDetails_...) and sl_ids_amazon_guardduty.hwk PreRules regex the raw JSON text for ip_src/ip_dst/alert_name/aws_region etc.'],
    'sucuri_waf': ['emits CEF "CEF:0|Sucuri|WAF|<host>|" + raw vendor key="value" pairs (hawk_sucuri_waf.py:146-163); NO sl_*sucuri*.hwk exists in hawk-ece-rules, so events fall through .hwk matching to orphans unless a rule exists elsewhere', 'python2-era script (iteritems, urllib.unquote)'],
    'cisco_cloud_web_security': ['python2-era script (urllib.unquote); emits W3C-style line + key="value" for every W3C field (cs-method, cs-uri-path, cs(User-Agent), x-ss-category ...); sl_cisco_cloud_web_security.hwk PreRules map the ones it knows'],
    'duo_mfa': ['emits CEF line with every raw Duo admin/auth log key="value" (hawk_duo_mfa.py:198-235); only fields named in sl_auth_duo.hwk PreRules become columns; exception records are returned to hawk-pulsed with payload= CEF string'],
    'proofpoint_tap': ['emits kv syslog "<pri>1 <ts> - ProofpointTAP - MSGDLV|MSGBLK|CLKPER|CLKBLK key=value, ..."; sl_mail_proofpoint_pulse.hwk InfoMatchAll="\\s([^=]+)=([^,]+)" turns EVERY kv pair into a column, so untranslated vendor keys (completelyRewritten, messageParts.*, threatsInfoMap.*, proofpoint.<orig>) also land as columns',
                       'inline getKeyByVendorKey map (hawk_proofpoint.py:338) renames senderIP->ip_src, clickIP->ip_dst, recipient->mail_to_address, threatId->threat_name, filename->file_name, url->http_uri (+http_protocol/http_host/http_path/http_query split)'],
    'proofpoint_dashboard': ['emits JSON {vendor_name, product_name, event_type, collected_at, query, data:{...row}, page_metadata:{...}} with NO force_matching and no alert_name/hid; JSONToAlert flattens nested objects with "_" so row fields arrive as data_<field>, query_<field>, page_metadata_<field>'],
    'm365_audit_logs': ['product_source = content_type.split(".")[1] -> AzureActiveDirectory | Exchange | General | SharePoint | All (DLP.All) (hawk_m365_audit_logs.py:553-554); Teams DLP override sets product_source="Teams DLP"',
                        'raw Office Management Activity API keys (Operation, Workload, ResultStatus, UserId, ClientIP, ObjectId, Parameters.*, ...) pass through as PascalCase columns; json_key_to_column.m365 aliases a few to correlation_username/ip_src/etc.'],
    'm365_signin': ['raw Graph signIn keys pass through (userPrincipalName, appDisplayName, conditionalAccessStatus, status.errorCode -> status.errorCode flattened, deviceDetail.*, location.*)'],
    'm365_directory': ['raw Graph directoryAudit/provisioning/intune keys pass through (activityDisplayName, initiatedBy.user.userPrincipalName, targetResources.0.*, ...)'],
    'microsoft_cloud_app_security': ['hawk_cas/hawk_microsoft_cas.py only launches the MCAS SIEM agent jar; MCAS emits CEF syslog itself and sl_microsoft_cloud.hwk parses it'],
    'zscaler_nss': ['no python collector; Zscaler NSS/Tunnel syslog (CEF and kv) parsed by sl_zscaler_nss.hwk; note hwk emits a dotted column net.tunnel.type'],
    'netskope': ['json_key_to_column.netskope_map contains vendor_socre (typo) and *_local pseudo-columns (alert_local, priority_local) that the script consumes locally'],
    'okta': ['hawk_record starts empty; only json_key_to_column.okta targets are emitted, raw event stored in payload (hawk_okta.py:220)'],
    'crowdstrike_falcon': ['raw detection stored in payload; only json_key_to_column.crowdstrike targets emitted'],
    'sentinelone': ['raw threat stored in payload; only json_key_to_column.sentinelone targets emitted'],
    'slack': ['unmapped raw audit keys are copied through as-is (hawk_slack_sdk.py:228) -> dotted keys like entity.channel.name'],
    'tenable_io': ['vulnerability/asset inventory feed, not security events'],
    'claude_compliance': ['BUG: writes uppercase key hawk_record["HID"] (hawk_claude.py:390,446,454) in addition to/instead of "hid"'],
    'lastpass': ['BUG: writes uppercase key hawk_record["HID"] (hawk_lastpass.py:312)'],
    'm365_activity': ['product_source also takes loop values "TeamsPSTN" and "TeamsDirectRouting" (hawk_m365_activity.py:294-299)'],
    'm365_legacy_azure_audit': ['writes short column name a_name (alert_name alias) directly'],
    'm365_legacy_azure_directory_audit': ['writes short column name a_name (alert_name alias) directly'],
}

EMISSION_OVERRIDE = {
    'proofpoint_tap': ['kv_syslog_line_to_127.0.0.1:514'],
    'proofpoint_dashboard': ['json_line_to_127.0.0.1:514 (no force_matching, no hid/alert_name -> .hwk rules run, none match -> orphan/FastText fallback)'],
    'm365_wrapper': ['none (dispatches the m365_* subsystems; only returns pulse status)'],
    'microsoft_cloud_app_security': ['launches MCAS SIEM agent jar; MCAS agent sends CEF syslog to eventd'],
}

# ---------------------------------------------------------------- helpers

def const_val(node):
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return '<fstring>'
    if isinstance(node, ast.Name):
        return '<var:%s>' % node.id
    if isinstance(node, ast.Call):
        f = node.func
        if isinstance(f, ast.Attribute):
            return '<call:.%s>' % f.attr
        if isinstance(f, ast.Name):
            return '<call:%s>' % f.id
    if isinstance(node, ast.Subscript):
        return '<subscript>'
    if isinstance(node, ast.BinOp):
        return '<expr>'
    return '<dynamic>'


def base_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return base_name(node.value) + '.' + node.attr
    if isinstance(node, ast.Subscript):
        return base_name(node.value) + '[]'
    return '?'


def analyze_py(path):
    """Return dict(assign={key: {bases:set, values:set, lines:set}}, imports=[...], name_vars={...}, flags)"""
    src = open(path, encoding='utf-8', errors='replace').read()
    # comment-stripped copy for flag regexes
    nsrc = '\n'.join(l for l in src.splitlines() if not l.lstrip().startswith('#'))
    res = {'assign': defaultdict(lambda: {'bases': set(), 'values': set(), 'lines': set()}),
           'j2c_tables': [], 'name_vars': defaultdict(set), 'flags': set(), 'errors': [],
           'call_taxonomy': defaultdict(set)}
    # regex-level flags
    if re.search(r'from json_key_to_column import (.+)', src):
        res['j2c_tables'] = [t.strip() for t in re.search(r'from json_key_to_column import (.+)', src).group(1).split(',')]
    if re.search(r'def send_log', nsrc) and re.search(r'json\.dumps\(\s*message', nsrc):
        res['flags'].add('emit:json_line_to_127.0.0.1:514')
    if 'CEF:0|' in nsrc and re.search(r"send_log\(\s*'127\.0\.0\.1'|sys_line", nsrc):
        res['flags'].add('emit:cef_syslog_line_to_127.0.0.1:514')
    if 'ProofpointTAP' in nsrc or 'CiscoCloudWebSecurity:' in nsrc:
        res['flags'].add('emit:kv_syslog_line_to_127.0.0.1:514')
    if re.search(r'hawk_record\s*=\s*flat_record|hawk_record\s*=\s*record\b|flat_record\.copy\(\)', src):
        res['flags'].add('passthrough:flattened_raw_vendor_keys_emitted_as_columns')
    if re.search(r"\['payload'\]\s*=\s*(record|json\.dumps\(record\)|event|json\.dumps\(event\))", src):
        res['flags'].add('raw_record_in_payload')
    if re.search(r"\['force_matching'\]\s*=\s*-1|'force_matching'\s*:\s*-1|\"force_matching\"\s*:\s*-1", src):
        res['flags'].add('force_matching:-1 (bypasses .hwk rule matching in hawk-packet-process.c)')
    if 'flatten_dict' in src:
        res['flags'].add('flattens_nested_json_with_dot_keys')
    try:
        tree = ast.parse(src)
    except SyntaxError as e:
        res['errors'].append('SyntaxError %s' % e)
        return res
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Subscript) and isinstance(t.slice, ast.Constant) and isinstance(t.slice.value, str):
                    k = t.slice.value
                    e = res['assign'][k]
                    e['bases'].add(base_name(t.value))
                    e['values'].add(repr(const_val(node.value)))
                    e['lines'].add(node.lineno)
                elif isinstance(t, ast.Name) and t.id in ('product_name', 'product_source', 'vendor_name', 'vendor_type',
                                                          'PRODUCT', 'VENDOR', 'alerts_type_name', 'class_type'):
                    v = const_val(node.value)
                    if isinstance(v, str) and not v.startswith('<'):
                        res['name_vars'][t.id].add(v)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == 'setdefault' \
                and node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
            k = node.args[0].value
            e = res['assign'][k]
            e['bases'].add(base_name(node.func.value))
            e['values'].add(repr(const_val(node.args[1]) if len(node.args) > 1 else None))
            e['lines'].add(node.lineno)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == '_yield_collection':
            # M365 subsystems: _yield_collection(api, data, product_name, product_source)
            if len(node.args) >= 4:
                for idx, key in ((2, 'product_name'), (3, 'product_source')):
                    v = const_val(node.args[idx])
                    res['call_taxonomy'][key].add(repr(v) + ' (_yield_collection arg, line %d)' % node.lineno)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'dict' and node.keywords:
            keys = [kw.arg for kw in node.keywords if kw.arg]
            ks = set(keys)
            if 'line' in ks and 'status' in ks and not ({'vendor_name', 'hid', 'product_name'} & ks):
                continue
            if SEED_KEYS & ks:
                for kw in node.keywords:
                    if kw.arg:
                        e = res['assign'][kw.arg]
                        e['bases'].add('<dict-call>')
                        e['values'].add(repr(const_val(kw.value)))
                        e['lines'].add(node.lineno)
        elif isinstance(node, ast.FunctionDef) and node.name == 'getKeyByVendorKey':
            for sub in ast.walk(node):
                if isinstance(sub, ast.Dict):
                    for k, v in zip(sub.keys, sub.values):
                        if isinstance(v, ast.Constant) and isinstance(v.value, str):
                            e = res['assign'][v.value]
                            e['bases'].add('<inline-vendor-key-map>')
                            e['values'].add('<from vendor key %s>' % (k.value if isinstance(k, ast.Constant) else '?'))
                            e['lines'].add(sub.lineno)
                            res['assign'][v.value]['bases'].add('hawk_record')  # force inclusion
        elif isinstance(node, ast.Dict):
            keys = [k.value for k in node.keys if isinstance(k, ast.Constant) and isinstance(k.value, str)]
            ks = set(keys)
            if SEED_KEYS & ks:
                # skip hawk-pulsed status-return dicts (alert_name/status/line without taxonomy)
                if 'line' in ks and 'status' in ks and not ({'vendor_name', 'hid', 'product_name'} & ks):
                    continue
                for k, v in zip(node.keys, node.values):
                    if isinstance(k, ast.Constant) and isinstance(k.value, str):
                        e = res['assign'][k.value]
                        e['bases'].add('<dict-literal>')
                        e['values'].add(repr(const_val(v)))
                        e['lines'].add(node.lineno)
    return res


def load_j2c():
    src = open(J2C, encoding='utf-8').read()
    tree = ast.parse(src)
    tables = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Dict) and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            m = {}
            for k, v in zip(node.value.keys, node.value.values):
                if isinstance(k, ast.Constant):
                    m[k.value] = v.value if isinstance(v, ast.Constant) else '<non-const>'
            tables[name] = {'line': node.lineno, 'map': m}
    return tables


HWK_SRC_RE = re.compile(r'Source\s*=\s*"([^"]*)"')


def analyze_hwk(path):
    cols = defaultdict(lambda: {'values': set(), 'lines': set()})
    src = open(path, encoding='utf-8', errors='replace').read().splitlines()
    for i, line in enumerate(src, 1):
        m = HWK_SRC_RE.search(line)
        if not m:
            continue
        for part in m.group(1).split(';'):
            part = part.strip()
            if not part or ':' not in part:
                continue
            col, val = part.split(':', 1)
            col = col.strip(); val = val.strip()
            if col.startswith('$'):
                col = '<$captured-key>'
            cols[col]['lines'].add(i)
            if '$' not in val:
                cols[col]['values'].add(val)
    return cols


def load_templates():
    d = json.load(open(TPLS, encoding='utf-8'))
    by_script = {}
    for it in d:
        for r in it.get('rules', []):
            if r.get('key') == 'LOCALSCRIPT':
                by_script.setdefault(r['value'].replace('.py', ''), []).append({'id': it['id'], 'name': it['name']})
    return by_script


def load_canonical():
    cols = set()
    p = os.path.join(RULES, 'columns')
    for l in open(p, encoding='utf-8'):
        l = l.strip()
        if l:
            cols.add(l)
    sql = os.path.join(REPOS, 'hawk-data', 'bin', 'database', 'updates', '51024_dynamic_columns.sql.gz')
    dyn = set()
    if os.path.exists(sql):
        txt = gzip.open(sql, 'rt', encoding='utf-8', errors='replace').read()
        for m in re.finditer(r'VALUES\s*\(\s*NULL\s*,\s*\d+\s*,\s*["\']([a-zA-Z0-9_.]+)["\']', txt):
            dyn.add(m.group(1))
    return cols, dyn


def classify(col):
    if col.startswith('<'):
        return 'meta'
    if '.' in col:
        return 'dotted'
    if re.search(r'[A-Z]', col):
        return 'camelCase/PascalCase'
    if re.search(r'[^a-z0-9_]', col):
        return 'other-nonword'
    return 'snake'


def main():
    j2c = load_j2c()
    tpl = load_templates()
    canon_rules, canon_dyn = load_canonical()
    canonical = canon_rules | canon_dyn
    inv = {}
    for name, spec in CONNECTORS.items():
        entry = {'files': [], 'pulse_templates': [], 'emission': [], 'flags': [],
                 'taxonomy': defaultdict(set), 'columns': set(), 'column_sources': defaultdict(set),
                 'json_key_to_column_tables': {}, 'hwk_rules': {}, 'non_canonical': defaultdict(set),
                 'notes': []}
        if spec.get('legacy'):
            entry['notes'].append('legacy/superseded script (not referenced by hawk_microsoft_m365.py wrapper or hawk-m365-plugins.yaml)')
        if spec.get('vuln'):
            entry['notes'].append('vulnerability/asset collector, not an event-log connector')
        if spec.get('syslog_only'):
            entry['notes'].append('no python collector; vendor ships syslog/CEF directly, parsed by .hwk rule only')
        record_bases = set()
        for rel in spec['py']:
            p = os.path.join(SCRIPTS, rel)
            if not os.path.exists(p):
                entry['notes'].append('missing file %s' % p)
                continue
            entry['files'].append(p.replace('\\', '/'))
            stem = os.path.splitext(os.path.basename(rel))[0]
            for t in tpl.get(stem, []):
                entry['pulse_templates'].append(t)
            a = analyze_py(p)
            entry['flags'].extend(sorted(a['flags']))
            for f in sorted(a['flags']):
                if f.startswith('emit:'):
                    entry['emission'].append(f[5:])
            # determine record-like bases
            for k, e in a['assign'].items():
                if k in SEED_KEYS:
                    record_bases |= e['bases']
            for k, e in a['assign'].items():
                if not (e['bases'] & record_bases):
                    continue
                if re.fullmatch(r'[A-Z0-9_]+', k) and k not in ('HID',):
                    continue  # config-style keys
                entry['columns'].add(k)
                entry['column_sources'][k].add('%s:%s' % (os.path.basename(rel), ','.join(str(x) for x in sorted(e['lines'])[:6])))
                if k in TAXONOMY_KEYS:
                    for v in e['values']:
                        entry['taxonomy'][k].add(v)
            for var, vals in a['name_vars'].items():
                key = {'PRODUCT': 'vendor_name(PRODUCT var)', 'VENDOR': 'vendor_name'}.get(var, var)
                for v in vals:
                    entry['taxonomy'][key].add(repr(v) + ' (via variable)')
            for key, vals in a['call_taxonomy'].items():
                entry['taxonomy'][key] |= vals
            # resolve "'<var:X>'" placeholders against module-level constants
            for key in list(entry['taxonomy'].keys()):
                resolved = set()
                for v in entry['taxonomy'][key]:
                    m = re.fullmatch(r"'<var:(\w+)>'", v)
                    if m and m.group(1) in a['name_vars']:
                        for rv in a['name_vars'][m.group(1)]:
                            resolved.add(repr(rv) + ' (via variable %s)' % m.group(1))
                    elif m and m.group(1) in ('product_name', 'product_source') and a['call_taxonomy'].get(m.group(1)):
                        continue  # covered by call_taxonomy entries
                    else:
                        resolved.add(v)
                entry['taxonomy'][key] = resolved
            for t in a['j2c_tables']:
                if t in j2c:
                    tgt = sorted({v for v in j2c[t]['map'].values() if v and v != '<non-const>'})
                    entry['json_key_to_column_tables'][t] = {
                        'file': J2C.replace('\\', '/'), 'line': j2c[t]['line'],
                        'vendor_keys': len(j2c[t]['map']),
                        'mapped_keys': sum(1 for v in j2c[t]['map'].values() if v),
                        'target_columns': tgt}
                    for c in tgt:
                        entry['columns'].add(c)
                        entry['column_sources'][c].add('json_key_to_column.%s' % t)
                        if c == 'product_name':
                            entry['taxonomy']['product_name'].add('<from vendor field via json_key_to_column.%s>' % t)
                else:
                    entry['notes'].append('imports json_key_to_column.%s which is not defined' % t)
        for rel in spec['hwk']:
            p = os.path.join(RULES, rel)
            if not os.path.exists(p):
                entry['notes'].append('missing hwk %s' % p)
                continue
            entry['files'].append(p.replace('\\', '/'))
            h = analyze_hwk(p)
            entry['hwk_rules'][rel] = {'columns': sorted(h.keys())}
            for c, e in h.items():
                entry['columns'].add(c)
                entry['column_sources'][c].add('%s:%s' % (rel, ','.join(str(x) for x in sorted(e['lines'])[:6])))
                if c in TAXONOMY_KEYS:
                    for v in e['values']:
                        entry['taxonomy'][c].add(repr(v) + ' (hwk)')
        for c in entry['columns']:
            cl = classify(c)
            if cl != 'snake':
                entry['non_canonical'][cl].add(c)
            elif c not in canonical:
                entry['non_canonical']['snake_but_not_in_canonical_list'].add(c)
        for n in MANUAL_NOTES.get(name, []):
            entry['notes'].append(n)
        # finalize
        entry['taxonomy'] = {k: sorted(v) for k, v in sorted(entry['taxonomy'].items())}
        entry['columns'] = sorted(entry['columns'])
        entry['column_sources'] = {k: sorted(v) for k, v in sorted(entry['column_sources'].items())}
        entry['non_canonical'] = {k: sorted(v) for k, v in sorted(entry['non_canonical'].items())}
        entry['emission'] = sorted(set(entry['emission'])) or (['pulse_return_only_or_unknown'] if spec['py'] else ['vendor_syslog_direct'])
        if name in EMISSION_OVERRIDE:
            entry['emission'] = EMISSION_OVERRIDE[name]
        hwk_json_trigger = any(re.search(r'Trigger\s*=\s*"\^\\?\{', open(os.path.join(RULES, r), encoding='utf-8', errors='replace').read()) for r in spec['hwk'] if os.path.exists(os.path.join(RULES, r)))
        if hwk_json_trigger and any(f.startswith('force_matching:-1') for f in entry['flags']):
            entry['notes'].append('DEAD RULE: python sets force_matching=-1 (skips HAWKEventMatchArray) but %s has a JSON Trigger; its Source= columns/taxonomy only apply if force_matching is absent' % ','.join(spec['hwk']))
            entry['dead_hwk_rule'] = True
        entry['flags'] = sorted(set(entry['flags']))
        inv[name] = entry

    column_index = defaultdict(list)
    for n, e in inv.items():
        for c in e['columns']:
            column_index[c].append(n)
    findings = {
        'raw_passthrough_connectors': sorted(n for n, e in inv.items() if any(f.startswith('passthrough') for f in e['flags'])),
        'raw_record_in_payload_only': sorted(n for n, e in inv.items() if 'raw_record_in_payload' in e['flags'] and not any(f.startswith('passthrough') for f in e['flags'])),
        'syslog_text_fed_via_hwk': sorted(n for n, e in inv.items() if any('syslog_line' in x for x in e['emission'])),
        'json_no_hwk_bypass': sorted(n for n, e in inv.items() if 'json_line_to_127.0.0.1:514' in e['emission'] and any(f.startswith('force_matching:-1') for f in e['flags'])),
        'camelCase_columns': sorted({c for e in inv.values() for c in e['non_canonical'].get('camelCase/PascalCase', [])}),
        'dotted_columns': sorted({c for e in inv.values() for c in e['non_canonical'].get('dotted', [])}),
        'snake_not_in_canonical': sorted({c for e in inv.values() for c in e['non_canonical'].get('snake_but_not_in_canonical_list', [])}),
    }
    meta = {
        'generated_by': os.path.abspath(__file__),
        'findings': findings,
        'column_index': {k: sorted(v) for k, v in sorted(column_index.items())},
        'canonical_column_sources': {
            'hawk-ece-rules/columns': len(canon_rules),
            'hawk-data/bin/database/updates/51024_dynamic_columns.sql.gz': len(canon_dyn),
        },
        'canonical_columns': sorted(canonical),
        'json_key_to_column_tables': {k: {'line': v['line'], 'vendor_keys': len(v['map']),
                                          'mapped': sum(1 for x in v['map'].values() if x)} for k, v in j2c.items()},
        'pipeline': {
            'runner': 'hawk-ece/scripts/hawk-pulsed loads hawk-data/app/tpls/pulse_templates.json (key PYTHON3, LOCALSCRIPT/LOCALFUNCTION) and calls <script>.hawk_dispatch(config); return list is only used for collector health (collection_result/publish_result).',
            'event_path_json': 'collector builds dict, sets force_matching=-1 and taxonomy, sends json.dumps(record)+"\\n" over TCP/UDP to 127.0.0.1:514; hawk-eventd packet path (hawk-ece/src/hawk-packet-process.c:359) detects leading "{" and calls JSONToAlert (hawk-ece/src/hawk-json-alert.c:30/66) which inserts every JSON key verbatim as an alert attribute (nested objects prefixed parent_child, key "payload" renamed payload2, arrays of strings kept). force_matching=-1 skips HAWKEventMatchArray (.hwk rules), so Python is the only normalization layer.',
            'event_path_syslog': 'collector formats a CEF/kv syslog line to 127.0.0.1:514; no force_matching so .hwk rules run (hawk-ece-rules/sl_*.hwk PreRule Source= directives map regex captures to HAWK columns).',
        },
    }
    json.dump({'_meta': meta, 'connectors': inv}, open(OUT, 'w', encoding='utf-8'), indent=1, sort_keys=False)
    print('wrote', OUT, 'connectors:', len(inv))
    # summary to stdout
    for n, e in inv.items():
        print('%-36s cols=%3d emit=%s tax=%s' % (n, len(e['columns']), ','.join(e['emission']),
              {k: v[:4] for k, v in e['taxonomy'].items() if k in ('vendor_name', 'product_name', 'vendor_type', 'class_type', 'product_source')}))


if __name__ == '__main__':
    main()
