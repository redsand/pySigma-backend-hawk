"""Pull IR cases per day from ir.hawk.io (creds from AIWorkAssistant/.env) into live/ir_cases_<days>d.json."""
import requests, urllib3, datetime, json, sys
urllib3.disable_warnings()
days = int(sys.argv[1]) if len(sys.argv) > 1 else 14
env = {}
for l in open('C:/Users/tshel/source/repos/AIWorkAssistant/.env', encoding='utf-8'):
    if l.startswith('HAWK_IR_') and '=' in l:
        k, v = l.rstrip('\n').split('=', 1); env[k] = v.strip().strip('"').strip("'")
base = env.get('HAWK_IR_BASE_URL', 'https://ir.hawk.io').rstrip('/')
s = requests.Session(); s.verify = False
s.post(base + '/api/auth', json={'access_token': env['HAWK_IR_ACCESS_TOKEN'], 'secret_key': env['HAWK_IR_SECRET_KEY']}, timeout=30)
end = datetime.datetime.now(datetime.UTC).replace(microsecond=0)
out = []
for d in range(days):
    ws, we = end - datetime.timedelta(days=d + 1), end - datetime.timedelta(days=d)
    off = 0
    while True:
        q = {'start_date': ws.strftime('%Y-%m-%dT%H:%M:%S.000Z'), 'stop_date': we.strftime('%Y-%m-%dT%H:%M:%S.000Z'), 'limit': 1000, 'offset': off}
        r = s.get(base + '/api/cases', params=q, timeout=300); j = r.json()
        rows = j.get('data', j) if isinstance(j, dict) else j
        rows = rows if isinstance(rows, list) else []
        for c in rows: c['_day'] = ws.date().isoformat()
        out += rows
        print(f"{ws.date()} off={off} got {len(rows)}", flush=True)
        if len(rows) < 1000: break
        off += 1000
json.dump(out, open(f'live/ir_cases_{days}d.json', 'w'))
print("total", len(out))
