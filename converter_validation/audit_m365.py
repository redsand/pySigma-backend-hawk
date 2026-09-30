"""Audit every production score that targets Microsoft 365 / Entra / Azure data.

1. Sample real documents per M365 product_source from the explore index. This is NOT the JSON the
   engine matched: hawk-sink-elastic indexes only keys matching ^[a-zA-Z_]+$ (<= 64 chars), so
   dotted keys and any column with a digit (file_hash_sha256, param1) are absent here even when
   the collector sent them. Treat those as unknown, not missing; verify from collector output.
   See hawk-ece docs/m365-sigma-field-findings.md.
2. For each score whose tree gates on M365 data (product_name Azure/Entra/Defender*/Purview/SecureScore,
   product_source, event_source/Workload values, or vendor Microsoft + cloud columns), list every column
   leaf and whether that column exists in the sampled documents of the sources the score can see.
3. Count how often each score name appears in result_name on the sampled documents (= it matched).
Writes reports/m365_audit.csv and prints a summary.
"""
import collections, csv, json, re, sys
import requests, urllib3
urllib3.disable_warnings()
key = [l.split('=', 1)[1].strip() for l in open('hawk.env') if l.startswith('HAWK_API_KEY=')][0]
B = 'https://portal.hawk.io:8080/API/1.1/'; H = {'Authorization': 'Bearer ' + key}
IDX = 'hawkio-da9d0285-4cda-11e9-835b-0cc47a0f9a88'
WINDOW = sys.argv[1] if len(sys.argv) > 1 else 'now-3d'
SOURCES = ['signInAudits', 'directoryAudits', 'provisioning', 'intune', 'Identity Protection', 'Alerts', 'Incidents',
           'DefenderAlerts', 'Exchange', 'SharePoint', 'General', 'AzureActiveDirectory', 'Teams', 'TeamsPSTN', 'OneDrive',
           'Outlook', 'All', 'AuthMethodsUserRegistration', 'ConditionalAccessPolicy', 'SecureScoreControlProfiles', 'SecureScore']


def search(q, size=2000):
    r = requests.post(B + 'explore/search', headers=H, data={'idx': IDX, 'q': q, 'from': WINDOW, 'to': 'now', 'size': str(size), 'offset': '0'}, timeout=900, verify=False)
    return [d.get('_source', d) for d in (r.json().get('results') or {}).get('rows') or []]


fields = {}; resnames = collections.Counter(); docs_per = {}; values = collections.defaultdict(lambda: collections.defaultdict(collections.Counter))
for src in SOURCES:
    docs = search(f'product_source:"{src}"')
    docs_per[src] = len(docs)
    f = collections.Counter()
    for d in docs:
        for k, v in d.items():
            if v not in (None, '', [], {}):
                f[k] += 1
        for k in ('product_name', 'event_source', 'event_name', 'alert_name', 'Workload', 'Operation', 'activityDisplayName', 'category', 'result'):
            if d.get(k) not in (None, ''):
                values[src][k][str(d.get(k))] += 1
        for n in str(d.get('result_name') or '').split(', '):
            if n: resnames[n.strip()] += 1
    fields[src] = f
    print(f"{src:28s} docs={len(docs):5d} fields={len(f)}", flush=True)
json.dump({'window': WINDOW, 'docs': docs_per, 'fields': {s: dict(f) for s, f in fields.items()}, 'values': {s: {k: dict(c.most_common(40)) for k, c in v.items()} for s, v in values.items()}, 'result_names': dict(resnames)},
          open('live/m365_samples.json', 'w'), indent=1)
all_m365 = set().union(*[set(f) for f in fields.values()])

live = requests.get(B + 'scores?recursive=true&format=json', headers=H, timeout=600, verify=False).json()['results']
M365_PRODUCTS = {'azure', 'entra', 'defender', 'defenderxdr', 'purview', 'securescore', 'apprisk', '365'}


def leaves(n):
    if isinstance(n, list):
        return [x for c in n for x in leaves(c)]
    if not isinstance(n, dict):
        return []
    if n.get('class') in ('column', 'function'):
        return [n]
    return [x for c in n.get('children', []) or [] for x in leaves(c)]


def val(l):
    a = l.get('args') or {}
    for t in ('str', 'int', 'float', 'bool'):
        if t in a:
            return str(a[t].get('value'))
    return ''


rows = []
for s in live:
    rules = s.get('rules'); rules = json.loads(rules) if isinstance(rules, str) else rules
    ls = leaves(rules)
    keys = {l.get('key') for l in ls if l.get('class') == 'column'}
    prods = {val(l).lower() for l in ls if l.get('key') == 'product_name'}
    psrc = {val(l) for l in ls if l.get('key') == 'product_source'}
    vend = {val(l).lower() for l in ls if l.get('key') == 'vendor_name'}
    name = s.get('filter_name') or ''
    is_m365 = bool(prods & M365_PRODUCTS) or bool(psrc) or bool(keys & {'event_source', 'Workload', 'Operation', 'activityDisplayName', 'product_source', 'userPrincipalName', 'ResultStatus'}) \
        or re.search(r'\b(365|m365|o365|office ?365|azure|entra|exchange online|sharepoint|onedrive|teams|defender for|mfa|conditional access|sign-?in)\b', name, re.I) is not None
    if not is_m365 or not ls:
        continue
    scope = [p for p in psrc if p in fields] or SOURCES
    avail = set().union(*[set(fields[p]) for p in scope])
    col_leaves = [l for l in ls if l.get('class') == 'column']
    missing = sorted({l['key'] for l in col_leaves if l['key'] not in avail and l['key'] not in ('group_name',)})
    fired = resnames.get(name.strip(), 0)
    rows.append({'score_id': s['score_id'], 'enabled': bool(s.get('enabled')), 'filter_name': name, 'weight': s.get('correlation_action'),
                 'action': s.get('actions_category_name'), 'sigma': 'sigma' in str(s.get('tags')).lower(), 'scope': ';'.join(sorted(psrc)) or 'any-M365',
                 'columns': ';'.join(sorted(keys)), 'missing_columns': ';'.join(missing), 'fired_in_sample': fired,
                 'verdict': 'fired' if fired else ('broken-keys' if missing and len(missing) == len({l['key'] for l in col_leaves}) else ('partial-keys' if missing else 'keys-ok-no-hits'))})
with open('reports/m365_audit.csv', 'w', newline='', encoding='utf-8') as fh:
    w = csv.DictWriter(fh, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
c = collections.Counter((r['enabled'], r['verdict']) for r in rows)
print("\nM365-related scores:", len(rows))
for k, v in sorted(c.items()): print(f"  enabled={k[0]!s:5s} {k[1]:16s} {v}")
mc = collections.Counter(m for r in rows if r['enabled'] for m in r['missing_columns'].split(';') if m)
print("\nmost common missing keys on ENABLED scores:", mc.most_common(25))
