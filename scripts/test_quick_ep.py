import urllib.request, time, json, os

token = ''
if os.path.exists('config/dashboard_token.key'):
    with open('config/dashboard_token.key') as f:
        token = f.read().strip()

headers = {'X-Osoosi-Token': token}
for ep in ['/api/threats', '/api/gossip']:
    t0 = time.perf_counter()
    req = urllib.request.Request('http://127.0.0.1:3030' + ep, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            elapsed = (time.perf_counter() - t0) * 1000.0
            data = json.loads(resp.read().decode('utf-8'))
            cnt = len(data) if isinstance(data, list) else len(data.get('threats', []))
            print(f'{ep}: {resp.status} in {elapsed:.2f} ms (count={cnt})')
    except Exception as e:
        elapsed = (time.perf_counter() - t0) * 1000.0
        print(f'{ep}: FAILED in {elapsed:.2f} ms: {e}')
