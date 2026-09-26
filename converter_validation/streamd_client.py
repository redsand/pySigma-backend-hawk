import websocket, ssl, json, time, uuid, datetime
import os
import requests as _rq
import urllib3 as _u3
_u3.disable_warnings()
_ENV = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'hawk.env')


def _session_cookie() -> str:
    """Mint a PHP session from the Bearer API key (HSID + parent group HS); cookies expire."""
    key = [l.split('=', 1)[1].strip() for l in open(_ENV) if l.startswith('HAWK_API_KEY=')][0]
    r = _rq.get('https://portal.hawk.io:8080/API/1.1/profile', headers={'Authorization': 'Bearer ' + key}, timeout=120, verify=False)
    hsid = r.headers.get('HSID') or r.cookies.get('HSID')
    group = (r.headers.get('HAWK-Parent-Group') or '.').lower()
    if not hsid:
        raise RuntimeError('could not obtain an HSID session from the API key')
    return f'HS={group}; realm_read_only=false; HSID={hsid}'


CK = None
CK=[l.split('=',1)[1].strip() for l in open(os.path.join(os.path.dirname(os.path.abspath(__file__)),'hawk.env')) if l.startswith('HAWK_COOKIE=')][0]
URL='wss://portal.hawk.io:8080/ws/'
def ts(dt): return dt.strftime('%Y-%m-%d %H:%M:%S')
def query(column, where=None, group_by='', order_by='', limit=10000, hours=1, begin=None, end=None, timeout=600, table='events', verbose=False):
    now=datetime.datetime.now(datetime.UTC)
    begin=begin or ts(now-datetime.timedelta(hours=hours)); end=end or ts(now)
    w={'job_id':f'tshelton:{abs(hash(str(column)))%100000}:{uuid.uuid4()}','column':column,'where':where or [],'group_by':group_by,'order_by':order_by,'limit':str(limit),'begin':begin,'end':end}
    ck=_session_cookie()
    ws=websocket.create_connection(URL,header=[f'Cookie: {ck}','Origin: https://portal.hawk.io'],sslopt={'cert_reqs':ssl.CERT_NONE},timeout=30)
    ws.settimeout(timeout)
    m=json.loads(ws.recv()); assert m.get('action')=='ready', m
    ws.send(json.dumps({'action':f'search:{table}:start','args':[w]}))
    rows=[]; t0=time.time(); status=None; err=None; master_id=None
    while True:
        try: m=json.loads(ws.recv())
        except websocket.WebSocketTimeoutException: err='timeout'; break
        a=m.get('action'); args=m.get('args',{})
        if a=='ping': ws.send(json.dumps({'action':'pong','args':{}})); continue
        if a==f'search:{table}:result':
            rows.extend(args.get('results',[]))
            if not group_by and len(rows)>=int(limit) and master_id:
                try: ws.send(json.dumps({'action':f'search:{table}:stop','args':{'master_id':master_id}}))
                except Exception: pass
                break
        elif a==f'search:{table}:done': break
        elif a==f'search:{table}:error': err=args.get('details'); break
        elif a==f'search:{table}:status': status=args.get('progress'); 
        elif a==f'search:{table}:confirm':
            master_id=args.get('master_id') or master_id
            if args.get('status')!='success': err=args.get('details'); break
        if verbose and a not in (f'search:{table}:result',): print(' ',a,str(args)[:160])
    try: ws.close()
    except Exception: pass
    return {'rows':rows,'error':err,'elapsed':round(time.time()-t0,1),'status':status,'widget':w}
if __name__=='__main__':
    r=query(['product_name','count product_name'],group_by='product_name',order_by='product_name_count DESC',limit=100,hours=1,verbose=True)
    print("error:",r['error'],"elapsed:",r['elapsed'],"rows:",len(r['rows']))
    print(sorted(((x.get('product_name'),x.get('product_name_count')) for x in r['rows']),key=lambda t:-(t[1] or 0))[:50])
