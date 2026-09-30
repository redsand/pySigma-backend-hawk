"""Run the remaining refresh groups: backtest each group of up to 300, push + enable those with an
upper-bound <= MAX hits/24h, hold the rest (reports/refresh_hold_all.txt accumulates)."""
import csv, json, subprocess, sys
MAX = 2
group = int(sys.argv[1]) if len(sys.argv) > 1 else 4
while True:
    # clear previous plan files first: a plan that shrank would otherwise leave stale group files behind
    import glob as _g, os as _o
    for _f in _g.glob('reports/refresh_group_*_diff.csv') + _g.glob('reports/refresh_group_[0-9][0-9][0-9].txt'):
        _o.remove(_f)
    subprocess.run([sys.executable, 'refresh_plan.py', '300'], check=True, capture_output=True)
    hold = set(l.strip() for l in open('reports/refresh_hold_all.txt') if l.strip())
    rows = []
    for i in range(1, 30):
        try:
            rows += list(csv.DictReader(open(f'reports/refresh_group_{i:03d}_diff.csv', encoding='utf-8')))
        except FileNotFoundError:
            break
    seen = set(); todo = []
    for r in rows:
        if r['hawk_id'] in hold or r['hawk_id'] in seen:
            continue
        seen.add(r['hawk_id']); todo.append(r)
    if not todo:
        print('refresh complete'); break
    g = todo[:300]
    open('reports/refresh_next.txt', 'w').write('\n'.join(r['hawk_id'] for r in g) + '\n')
    subprocess.run([sys.executable, 'backtest_explore.py', '--select', 'reports/refresh_next.txt', '--hours', '24', '--workers', '4',
                    '--out', f'reports/backtest_refresh_group_{group:03d}.json'], check=True, capture_output=True)
    bt = {e['hawk_id']: e for e in json.load(open(f'reports/backtest_refresh_group_{group:03d}.json'))['results']}
    go = [r['hawk_id'] for r in g if bt.get(r['hawk_id'], {}).get('status') == 'ok' and (bt[r['hawk_id']].get('hits') or 0) <= MAX]
    held = [r['hawk_id'] for r in g if r['hawk_id'] not in set(go)]
    open(f'reports/refresh_group_{group:03d}_push.txt', 'w').write('\n'.join(go) + '\n')
    with open('reports/refresh_hold_all.txt', 'a') as fh:
        fh.write(''.join(h + '\n' for h in held))
    if go:
        p = subprocess.run([sys.executable, 'sync_scores.py', '--select', f'reports/refresh_group_{group:03d}_push.txt', '--batch-size', '300', '--execute', '--verify'], capture_output=True, text=True)
        e = subprocess.run([sys.executable, 'disable_scores.py', '--hawk-ids-file', f'reports/refresh_group_{group:03d}_push.txt', '--enable', '--execute'], capture_output=True, text=True)
        ver = [l for l in p.stdout.splitlines() if l.startswith('verified')]
        en = [l for l in e.stdout.splitlines() if 'to enable' in l]
    else:
        ver, en = ['nothing pushed'], ['']
    print(f'group {group:03d}: size {len(g)} pushed {len(go)} held {len(held)} | {ver[-1] if ver else p.stdout[-200:]} | {en[-1] if en else ""}', flush=True)
    group += 1
