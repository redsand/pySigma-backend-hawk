import json, collections, datetime, sys, os
from streamd_client import query, ts
now=datetime.datetime.now(datetime.UTC)
beg=ts(now-datetime.timedelta(hours=3)); end=ts(now-datetime.timedelta(minutes=10))
TARGETS=[('Sysmon','1'),('Sysmon','3'),('Sysmon','7'),('Sysmon','11'),('Sysmon','13'),('Sysmon','22'),('Sysmon','8'),('Sysmon','10'),
 ('Security-Auditing','4688'),('Security-Auditing','4663'),('Security-Auditing','4657'),('Security-Auditing','5145'),('Security-Auditing','4698'),('Security-Auditing','4720'),('Security-Auditing','4776'),
 ('Service_Control_Manager',None),('TaskScheduler',None),('CodeIntegrity',None),('DNS-Client',None),('Windows_Firewall_With_Advanced_Security',None),('WMI-Activity',None),
 ('OperatingSystem',None),('Audit',None),('Azure',None),('Entra',None),('NSSWeblog',None),('IDS',None),('WAP',None)]
path='live/stream_field_profiles.json'
prof=json.load(open(path)) if os.path.exists(path) else {}
for prod,vid in TARGETS:
    key=f"{prod}:{vid or '*'}"
    if key in prof: continue
    where=[f"product_name = '{prod}'"]+([f"vendor_id = '{vid}'"] if vid else [])
    r=query(['date_added','product_name','vendor_id'],where=where,limit=80,begin=beg,end=end,timeout=200)
    rows=r['rows']
    keys=collections.Counter(k for d in rows for k,v in d.items() if v not in (None,'',[],{}))
    tax={k:collections.Counter(str(d.get(k)) for d in rows).most_common(5) for k in ('vendor_name','event_channel','hawk_source','class_type','vendor_type','product_source','hid','alerts_type_name')}
    prof[key]={'n':len(rows),'error':r['error'],'elapsed':r['elapsed'],'fields':{k:v for k,v in keys.items() if len(k)<64},'weird_keys':[k for k in keys if len(k)>=64][:5],'taxonomy':tax,'sample':rows[:2]}
    print(f"{key}: rows={len(rows)} fields={len(keys)} err={r['error']} t={r['elapsed']}s", flush=True)
    json.dump(prof,open(path,'w'),indent=1)
print("done", len(prof))
