"""Plan the refresh of production Sigma scores whose logic differs from the current conversion.

Classifies every differing score (keys added/removed, values only), orders them lowest-risk first
(this sync's own imports, then value-only changes, then key changes, disabled before enabled), and
writes reports/refresh_group_<NNN>.txt (ids) + reports/refresh_group_<NNN>_diff.csv.
"""
import csv, glob, json, sys
import requests, urllib3
urllib3.disable_warnings()
SIZE = int(sys.argv[1]) if len(sys.argv) > 1 else 300
key = [l.split('=', 1)[1].strip() for l in open('hawk.env') if l.startswith('HAWK_API_KEY=')][0]
live = {str(r.get('hawk_id')).lower(): r for r in requests.get('https://portal.hawk.io:8080/API/1.1/scores?recursive=true&format=json', headers={'Authorization': 'Bearer ' + key}, timeout=600, verify=False).json()['results'] if r.get('hawk_id')}
pushed = set()
for m in glob.glob('reports/batches/batch_*Z.json'):
    for i in json.load(open(m))['items']:
        pushed.add(i['hawk_id'].lower())


def leaves(rules):
    rules = json.loads(rules) if isinstance(rules, str) else rules
    out = []

    def w(n):
        if isinstance(n, list):
            [w(c) for c in n]; return
        if n.get('class') in ('column', 'function'):
            out.append(n)
        for c in n.get('children', []) or []:
            w(c)
    w(rules)
    return out


def sig(ls):
    return sorted(json.dumps([l.get('key'), l.get('args')], sort_keys=True) for l in ls)


rows = []
for line in open('reports/converted.jsonl', encoding='utf-8'):
    x = json.loads(line); h = x['hawk_id'].lower()
    if x['_source'].startswith('deprecated') or h not in live:
        continue
    old = leaves(live[h]['rules']); new = leaves(x['rules'])
    if sig(old) == sig(new):
        continue
    ok = {l.get('key') for l in old}; nk = {l.get('key') for l in new}
    kind = 'values-only' if ok == nk else 'keys-changed'
    own = h in pushed
    en = bool(live[h].get('enabled'))
    risk = (0 if own else 1, 0 if kind == 'values-only' else 1, 1 if en else 0)
    rows.append({'hawk_id': h, 'score_id': live[h]['score_id'], 'enabled': en, 'origin': 'this-sync' if own else '2023-import', 'kind': kind,
                 'title': x['filter_name'], 'source': x['_source'], 'removed_keys': ';'.join(sorted(ok - nk)), 'added_keys': ';'.join(sorted(nk - ok)), '_risk': risk})
rows.sort(key=lambda r: r['_risk'])
for i in range(0, len(rows), SIZE):
    g = rows[i:i + SIZE]; n = i // SIZE + 1
    open(f'reports/refresh_group_{n:03d}.txt', 'w').write('\n'.join(r['hawk_id'] for r in g) + '\n')
    with open(f'reports/refresh_group_{n:03d}_diff.csv', 'w', newline='', encoding='utf-8') as fh:
        w = csv.DictWriter(fh, fieldnames=[k for k in g[0] if k != '_risk'], extrasaction='ignore'); w.writeheader(); w.writerows(g)
print('differing scores:', len(rows), '| groups of', SIZE, ':', (len(rows) + SIZE - 1) // SIZE)
import collections
print(collections.Counter((r['origin'], r['kind'], 'enabled' if r['enabled'] else 'disabled') for r in rows))
