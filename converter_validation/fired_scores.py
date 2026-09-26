"""Count how often each Sigma-imported score fired, from result_name in the live stream (streamd)."""
import json, glob, collections, datetime, sys, requests, urllib3
from streamd_client import query, ts
urllib3.disable_warnings()
hours = float(sys.argv[1]) if len(sys.argv) > 1 else 12
key=[l.split('=',1)[1].strip() for l in open('hawk.env') if l.startswith('HAWK_API_KEY=')][0]
live=requests.get('https://portal.hawk.io:8080/API/1.1/scores?recursive=true&format=json',headers={'Authorization':'Bearer '+key},timeout=600,verify=False).json()['results']
pushed={}
for m in glob.glob('reports/batches/batch_*Z.json'):
    for i in json.load(open(m))['items']: pushed[i['hawk_id'].lower()]=i
imported=[r for r in live if str(r.get('hawk_id')).lower() in pushed]
now=datetime.datetime.now(datetime.UTC)
r=query(['result_name','count result_name'],where=["result_name regex '.+'"],group_by='result_name',order_by='result_name_count DESC',limit=10000,begin=ts(now-datetime.timedelta(hours=hours)),end=ts(now-datetime.timedelta(minutes=5)),timeout=3000)
print("streamd err:",r['error'],"elapsed:",r['elapsed'],"groups:",len(r['rows']))
fired=collections.Counter()
for row in r['rows']:
    n=int(row.get('result_name_count') or 0); rn=str(row.get('result_name') or '')
    for s in imported:
        if s['filter_name'] and s['filter_name'] in rn: fired[s['hawk_id'].lower()]+=n
out=[]
for s in imported:
    h=s['hawk_id'].lower()
    out.append({'hawk_id':h,'score_id':s['score_id'],'title':s['filter_name'],'enabled':bool(s.get('enabled')),'score':s['correlation_action'],'hits':fired.get(h,0),'hits_per_hour':round(fired.get(h,0)/hours,2)})
json.dump({'hours':hours,'at':now.isoformat(),'rows':out},open('reports/fired_imported.json','w'),indent=1)
en=[o for o in out if o['enabled']]
print(f"enabled imported: {len(en)} | fired: {sum(1 for o in en if o['hits'])} | total hits {sum(o['hits'] for o in en)} in {hours}h")
for o in sorted(en,key=lambda o:-o['hits'])[:15]:
    if o['hits']: print(f"  {o['hits']:7d} ({o['hits_per_hour']}/h) score {o['score']} {o['title'][:70]}")
