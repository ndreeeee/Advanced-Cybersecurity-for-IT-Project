import httpx, json

try:
    r = httpx.post('https://splunk:8089/services/auth/login',
        data={'username':'admin','password':'Banana02!','output_mode':'json'},
        verify=False, timeout=10)
    key = json.loads(r.text)['sessionKey']

    # Query 1: Cerca tutto
    r1 = httpx.post('https://splunk:8089/services/search/jobs',
        headers={'Authorization': f'Splunk {key}'},
        data={'search': 'search index=* | stats count by index, source | head 20', 'output_mode': 'json', 'exec_mode': 'oneshot'},
        verify=False, timeout=120)
    
    print("--- TUTTI GLI INDEX E SOURCE PRESENTI IN SPLUNK ---")
    results1 = json.loads(r1.text).get('results', [])
    for row in results1:
        print(f"Index: {row.get('index')} | Source: {row.get('source')} | Conteggio: {row.get('count')}")

    # Query 2: Cerca Bob a prescindere dall'index o dal source
    r2 = httpx.post('https://splunk:8089/services/search/jobs',
        headers={'Authorization': f'Splunk {key}'},
        data={'search': 'search srcstr="172.20.0.12" index=* | stats count by index, source', 'output_mode': 'json', 'exec_mode': 'oneshot'},
        verify=False, timeout=120)
    
    print("\n--- DOVE SI TROVA BOB? ---")
    results2 = json.loads(r2.text).get('results', [])
    if not results2:
        print("Bob NON è stato trovato in nessun index/source in Splunk!")
    for row in results2:
        print(f"Trovato in Index: {row.get('index')} | Source: {row.get('source')} | Conteggio: {row.get('count')}")

except Exception as e:
    print(f"Errore: {e}")
