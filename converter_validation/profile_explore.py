"""Fast field-presence profiling via /explore/search (same JSON documents as the stream).

Writes/merges into live/stream_field_profiles.json in the same shape profile_stream.py uses.
"""
import json, os, sys, time, collections, concurrent.futures as cf
import requests, urllib3
urllib3.disable_warnings()
HERE=os.path.dirname(os.path.abspath(__file__))
key=[l.split('=',1)[1].strip() for l in open(os.path.join(HERE,'hawk.env')) if l.startswith('HAWK_API_KEY=')][0]
B='https://portal.hawk.io:8080/API/1.1/'; H={'Authorization':'Bearer '+key}
IDX='hawkio-da9d0285-4cda-11e9-835b-0cc47a0f9a88'
TAX=('product_name','vendor_name','event_channel','hawk_source','class_type','vendor_type','product_source','hid','alerts_type_name','vendor_id')
def targets():
    t=[]
    for vid in ('2','6','8','12','15','17','23','25','26'): t.append((f'Sysmon:{vid}', f'product_name:"Sysmon" AND vendor_id:"{vid}"'))
    for vid in ('4624','4625','4656','4657','4662','4672','4697','4698','4702','4720','4728','4732','4740','4768','4769','4771','4776','5136','5140','5145','5156','5379'): t.append((f'Security-Auditing:{vid}', f'product_name:"Security-Auditing" AND vendor_id:"{vid}"'))
    for vid in ('4104','4103'): t.append((f'PowerShell:{vid}', f'product_name:"PowerShell" AND vendor_id:"{vid}"'))
    for vid in ('400','800'): t.append((f'Windows PowerShell:{vid}', f'event_channel:"Windows PowerShell" AND vendor_id:"{vid}"'))
    t.append(('Service_Control_Manager:7045','product_name:"Service_Control_Manager" AND vendor_id:"7045"'))
    for p in ('Windows_Defender','Windows Defender','Kernel-File','Application_Error','Application Error','Windows_Firewall_With_Advanced_Security','WMI-Activity','TaskScheduler','Service_Control_Manager','Kernel-General','Security-Mitigations','AppLocker','Defender','DefenderXDR','Entra','Azure','SecureScore','Purview','Audit','OperatingSystem','IDS','NSSWeblog','WAP','Identity and Access Management','Cloud EDR','Cloud_EDR','DNS-Server-Service','Exchange','SharePoint','Teams','Sysmon','Security-Auditing','PowerShell','CodeIntegrity','DNS-Client','Bits-Client','NTLM','LSA','PrintService','SmbClient','TerminalServices-LocalSessionManager','DriverFrameworks-UserMode','MSExchange_Management','Kernel-PnP','User_Profile_Service','Winlogon','TerminalServices-RemoteConnectionManager'):
        t.append((f'{p}:*', f'product_name:"{p}"'))
    for v in ('SentinelOne','ThreatLocker','AWS','AWS CloudTrail','Okta','Duo','Workday','LastPass','ProofPoint','Varonis','Tenable.io','Snort','Suricata','Linux'):
        t.append((f'vendor={v}:*', f'vendor_name:"{v}"'))
    return t
def one(key_, q, size=80, window='now-24h'):
    t0=time.time()
    try:
        r=requests.post(B+'explore/search',headers=H,data={'idx':IDX,'q':q,'from':window,'to':'now','size':str(size),'offset':'0'},timeout=600,verify=False)
        rows=(r.json().get('results') or {}).get('rows') or []
    except Exception as e:
        return key_,{'n':0,'error':f'{type(e).__name__}: {e}','elapsed':round(time.time()-t0,1)}
    docs=[d.get('_source',d) for d in rows]
    fields=collections.Counter(k for d in docs for k,v in d.items() if v not in (None,'',[],{}) and not k.startswith('_') and k!='@timestamp')
    tax={k:collections.Counter(str(d.get(k)) for d in docs).most_common(6) for k in TAX}
    return key_,{'n':len(docs),'error':None,'elapsed':round(time.time()-t0,1),'source':'explore','query':q,'fields':{k:v for k,v in fields.items() if len(k)<64},'weird_keys':[k for k in fields if len(k)>=64][:5],'taxonomy':tax,'sample':docs[:2]}
if __name__=='__main__':
    path=os.path.join(HERE,'live','stream_field_profiles.json')
    prof=json.load(open(path)) if os.path.exists(path) else {}
    todo=[(k,q) for k,q in targets() if not prof.get(k,{}).get('n')]
    print("targets:",len(todo),flush=True)
    with cf.ThreadPoolExecutor(max_workers=4) as ex:
        for k,res in ex.map(lambda kq: one(*kq), todo):
            cur=json.load(open(path)) if os.path.exists(path) else {}
            if res['n'] or not cur.get(k,{}).get('n'): cur[k]=res
            json.dump(cur,open(path,'w'),indent=1)
            print(f"{k}: n={res['n']} fields={len(res.get('fields',{}))} t={res['elapsed']}s {res.get('error') or ''}",flush=True)
    print("done")
