import json, collections, yaml, re, csv
live=json.load(open('live/columns.json'))['results']
colset={c['key']:c for c in live}
scores=json.load(open('live/scores.json'))['results']
TYPEMAP={'string':'str','integer':'int','unsigned integer':'uns','boolean':'bool','ip':'ip','float':'float','double':'doub','array':'arra','object':'obj','timestamp':'str'}
missing=collections.defaultdict(list); typemis=collections.defaultdict(list); nocmp=[]; funcs=collections.Counter(); leafcount=0
def walk(n,s):
    global leafcount
    if isinstance(n,dict):
        if n.get('class')=='column':
            leafcount+=1; k=n.get('key')
            if k not in colset: missing[k].append(s)
            else:
                lt=colset[k]['type']; rt=(n.get('return') or '')
                exp=TYPEMAP.get(lt,lt)
                if rt and not rt.startswith(exp) and not (exp=='str' and rt.startswith('str')): typemis[(k,lt,rt)].append(s)
            if 'comparison' not in (n.get('args') or {}): nocmp.append((s['filter_name'],k))
        elif n.get('class')=='function': funcs[n.get('key')]+=1
        for ch in n.get('children') or []: walk(ch,s)
    elif isinstance(n,list):
        for x in n: walk(x,s)
for s in scores:
    r=s['rules']; r=json.loads(r) if isinstance(r,str) else r
    walk(r,s)
print("scores:",len(scores),"column leaves:",leafcount,"function leaves:",sum(funcs.values()),dict(funcs))
print("\n== MISSING COLUMNS (used in scores but not in live columns table) ==")
rows=[]
for k,ss in sorted(missing.items(),key=lambda kv:-len(kv[1])):
    en=sum(1 for s in ss if s['enabled']); names={s['filter_name'] for s in ss}
    print(f"{k!r}: {len(ss)} leaves in {len(names)} scores ({en} enabled)  e.g. {list(names)[:3]}")
    for s in ss: rows.append({'column':k,'score_id':s['score_id'],'hawk_id':s.get('hawk_id'),'filter_name':s['filter_name'],'enabled':s['enabled'],'group':s['group_name']})
w=csv.DictWriter(open('prod_scores_missing_columns.csv','w',newline='',encoding='utf-8'),fieldnames=['column','score_id','hawk_id','filter_name','enabled','group']); w.writeheader(); w.writerows(rows)
print("\n== TYPE MISMATCH (leaf return vs column type) ==")
for (k,lt,rt),ss in sorted(typemis.items(),key=lambda kv:-len(kv[1]))[:25]:
    print(f"{k}: column type {lt!r} but leaf return {rt!r}: {len(ss)} leaves e.g. {ss[0]['filter_name'][:60]!r}")
print("total type-mismatch leaves:",sum(len(v) for v in typemis.values()))
print("leaves without comparison:",len(nocmp), nocmp[:3])
print("\n== CONVERTER TARGETS vs live columns ==")
cfg=yaml.safe_load(open('C:/Users/tshel/source/repos/pySigma-backend-hawk/sigma/backends/hawk/config/hawk_field_config.yml'))
fm=cfg.get('fieldmappings',{})
tgt=set()
for k,v in fm.items():
    for t in (v if isinstance(v,list) else [v]): tgt.add(str(t))
bad=sorted(t for t in tgt if t not in colset)
print("hawk_field_config.yml targets:",len(tgt),"NOT in live columns:",len(bad),bad)
src=open('C:/Users/tshel/source/repos/pySigma-backend-hawk/sigma/pipelines/hawk/hawk.py',encoding='utf-8').read()
ptgt=set(re.findall(r'"[A-Za-z0-9_.\-]+"\s*:\s*"([A-Za-z0-9_.\-]+)"',src))
pbad=sorted(t for t in ptgt if t not in colset)
print("pipeline mapping targets:",len(ptgt),"NOT in live columns:",len(pbad),pbad)
enr=yaml.safe_load(open('C:/Users/tshel/source/repos/pySigma-backend-hawk/sigma/backends/hawk/config/logsource_enrichments.yml'))
ek=collections.Counter()
items=enr if isinstance(enr,list) else enr.get('enrichments',enr)
for e in (items if isinstance(items,list) else items.values()):
    for k in (e.get('conditions') or {}): ek[k]+=1
print("enrichment condition keys:",dict(ek),"NOT in live:",[k for k in ek if k not in colset])
hk=set(re.findall(r'"key"\s*:\s*"([a-z_0-9]+)"',open('C:/Users/tshel/source/repos/pySigma-backend-hawk/sigma/backends/hawk/hawk.py',encoding='utf-8').read()))
print("hard-coded keys in hawk.py:",sorted(hk),"NOT in live:",[k for k in hk if k not in colset and k not in ('and','or')])
json.dump(sorted(colset),open('live/column_names.json','w'),indent=0)
