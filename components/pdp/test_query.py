import httpx, json

r = httpx.post('https://splunk:8089/services/auth/login',
    data={'username':'admin','password':'Banana02!','output_mode':'json'},
    verify=False, timeout=10)
key = json.loads(r.text)['sessionKey']

# Test 1: cerca in TUTTI gli index
queries = [
    'search source="merged.csv" | stats count by srcstr | search count > 5',
    'search index=honeypot | stats count by srcstr | search count > 5',
    'search index=honeypot source="merged.csv" | stats count by srcstr | search count > 5',
    'search index=honeypot srcstr="172.20.0.12" | stats count',
    'search index=* source="merged.csv" | stats count',
]

for q in queries:
    r2 = httpx.post('https://splunk:8089/services/search/jobs',
        headers={'Authorization': f'Splunk {key}'},
        data={'search': q, 'output_mode': 'json', 'exec_mode': 'oneshot'},
        verify=False, timeout=120)
    data = json.loads(r2.text)
    results = data.get('results', [])
    n = len(results)
    detail = ""
    if n > 0 and n <= 3:
        detail = f" => {results}"
    elif n > 3:
        detail = f" => primi 3: {results[:3]}"
    print(f"[{n:3d} risultati] {q}{detail}")
