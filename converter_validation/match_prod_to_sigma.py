import csv, json, re, sys, collections, os, glob, yaml
csv.field_size_limit(10**9)
prod = list(csv.DictReader(open(sys.argv[1], encoding='utf-8', errors='replace')))
sigroot = sys.argv[2]
norm = lambda s: re.sub(r'[^a-z0-9]+',' ', s.lower()).strip()
prod_names = {norm(r['filter_name']): r for r in prod}
# extract sigma rule filenames referenced in prod references
fn_re = re.compile(r'sigma/blob/master/(rules[^\s#"]*?\.yml)')
prod_ref_files = {}
for r in prod:
    for m in fn_re.findall(r['references']+r['comments']):
        prod_ref_files[os.path.basename(m)] = r
prod_uuid = {}
ure = re.compile(r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b')
for r in prod:
    for u in ure.findall(r['references']+r['comments']+r['tags']+r['filter_details']):
        prod_uuid[u]=r
print("prod rows", len(prod), "| refs to sigma filenames:", len(prod_ref_files), "| uuids in prod text:", len(prod_uuid))
rules=[]
for d in ['rules','rules-emerging-threats','rules-threat-hunting']:
    for p in glob.glob(os.path.join(sigroot,d,'**','*.yml'), recursive=True):
        try:
            y = yaml.safe_load(open(p, encoding='utf-8'))
        except Exception: continue
        if not isinstance(y, dict) or 'title' not in y: continue
        rules.append((p,y))
print("sigma rules loaded", len(rules))
by_title = collections.Counter(); by_file=0; by_id=0; matched=set(); unmatched=[]
stats = collections.Counter()
for p,y in rules:
    hit = None
    if norm(y['title']) in prod_names: hit='title'
    elif os.path.basename(p) in prod_ref_files: hit='file'
    elif str(y.get('id')) in prod_uuid: hit='id'
    if hit: stats[hit]+=1; matched.add(p)
    else: unmatched.append((p,y))
print("matched:", stats, "total", len(matched), "unmatched", len(unmatched))
# unmatched by logsource / level / date
ls = collections.Counter((y.get('logsource',{}).get('product'), y.get('logsource',{}).get('category') or y.get('logsource',{}).get('service')) for p,y in unmatched)
print("unmatched top logsources:", ls.most_common(25))
print("unmatched by level:", collections.Counter(y.get('level') for p,y in unmatched))
print("unmatched by status:", collections.Counter(y.get('status') for p,y in unmatched))
yrs = collections.Counter(str(y.get('date'))[:4] for p,y in unmatched)
print("unmatched by year:", sorted(yrs.items()))
myrs = collections.Counter(str(y.get('date'))[:4] for p in matched for q,y in rules if q==p)
print("matched by year:", sorted(myrs.items()))
# newest matched date -> approximate last sync
md = sorted(str(y.get('date')) for p,y in rules if p in matched)
print("newest matched rule date:", md[-5:])
# high-value unmatched: level high/critical, status stable/test, product windows
hv = [(p,y) for p,y in unmatched if y.get('level') in ('high','critical') and y.get('status') in ('stable','test')]
print("high/critical unmatched:", len(hv))
json.dump([{'path':os.path.relpath(p,sigroot),'title':y['title'],'id':y.get('id'),'level':y.get('level'),'status':y.get('status'),'date':str(y.get('date')),'logsource':y.get('logsource')} for p,y in unmatched], open('unmatched_sigma_rules.json','w'), indent=1)
json.dump(sorted(os.path.relpath(p,sigroot) for p in matched), open('matched_sigma_rules.json','w'), indent=1)
