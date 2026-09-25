import csv, json, re, sys, collections
csv.field_size_limit(10**9)
path = sys.argv[1]
rows = list(csv.DictReader(open(path, encoding='utf-8', errors='replace')))
print("rows:", len(rows))
print("columns:", list(rows[0].keys()))
c = collections.Counter
print("enabled:", c(r['enabled'] for r in rows))
print("public:", c(r['public'] for r in rows))
print("action cat:", c(r['actions_category_name'] for r in rows).most_common(10))
print("corr action (score):", c(r['correlation_action'] for r in rows).most_common(15))
print("groups top:", c(r['group_name'] for r in rows).most_common(25))
uuid = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')
sig = [r for r in rows if 'sigma' in (r['references']+r['comments']+r['tags']).lower() or 'sigma' in r['group_name'].lower()]
print("sigma-tagged rows:", len(sig))
print("sigma groups:", c(r['group_name'] for r in sig).most_common(10))
print("sample sigma refs:", [r['references'][:120] for r in sig[:5]])
print("sample sigma comments:", [r['comments'][:160] for r in sig[:5]])
print("sample sigma tags:", [r['tags'][:160] for r in sig[:5]])
print("sample sigma names:", [r['filter_name'][:90] for r in sig[:8]])
# hunt prefix
print("HUNT-prefixed:", sum(r['filter_name'].startswith('HUNT') for r in rows))
# top columns used in rule trees
colc = c()
def walk(n):
    if isinstance(n, dict):
        if n.get('class')=='column': colc[n.get('key')]+=1
        for ch in n.get('children',[]) or []: walk(ch)
    elif isinstance(n, list):
        for x in n: walk(x)
bad=0
for r in rows:
    try: walk(json.loads(r['rules']))
    except Exception: bad+=1
print("unparseable rules:", bad)
print("top columns:", colc.most_common(40))
print("distinct columns:", len(colc))
tac = c()
for r in rows:
    try:
        for t in json.loads(r['tactics'] or '[]'): tac[t]+=1
    except Exception: pass
print("tactics:", tac.most_common(20))
print("technique nonempty:", sum(bool(r['technique']) for r in rows))
