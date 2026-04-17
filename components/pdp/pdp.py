import os
import time
import httpx
import psycopg2
from datetime import datetime

# =======================================================================
# CONFIGURAZIONI DATABASE e SPLUNK
# =======================================================================
DB_HOST = os.getenv("DB_HOST", "dbms")
DB_USER = os.getenv("DB_USER", "zta_admin")
DB_PASS = os.getenv("DB_PASS", "zta_password")
DB_NAME = os.getenv("DB_NAME", "zta_policy")

SPLUNK_HOST = "https://splunk:8089" # Splunk REST expone sempre in HTTPS
SPLUNK_USER = "admin"
SPLUNK_PASS = os.getenv("SPLUNK_PASS", "changeme")

# Query Splunk che andrà a cercare nella Threat Intelligence (dataset honeypot/attack_data)
# I campi del CSV sono: srcstr (IP attaccante), dpt (porta destinazione), cc (paese), proto (protocollo)
SEARCH_QUERY = 'search source="honeypot.csv" | stats count by srcstr | search count > 5'

print("[PDP] Policy Decision Point Motor Started. Connecting to Splunk REST API...", flush=True)

# =======================================================================
# FUNZIONI CORE ZTA
# =======================================================================
def get_splunk_session_key():
    """Autenticazione iniziale alle API REST di Splunk per ottenere la SessionKey"""
    try:
        response = httpx.post(
            f"{SPLUNK_HOST}/services/auth/login",
            data={'username': SPLUNK_USER, 'password': SPLUNK_PASS, 'output_mode': 'json'},
            verify=False # Certificato auto-generato da Splunk docker
        )
        response.raise_for_status()
        # Splunk ha la tendenza a rispondere in XML per la route di auth anche se chiedi json
        # quindi facciamo un parsing furbo se serve, o estraiamo stringa
        text = response.text
        if "<sessionKey>" in text:
            # Estrazione XML brutale ma infallibile
            key = text.split("<sessionKey>")[1].split("</sessionKey>")[0]
            print("[PDP] Authenticated to Splunk. SessionKey ADQUIRED.", flush=True)
            return key
        return None
    except Exception as e:
        print(f"[PDP] SPLUNK Auth Connection Error: {e}. Splunk is probably still booting...", flush=True)
        return None

def verify_logs_via_api(session_key):
    """
    Svolge il ciclo di vita della REST API Splunk:
    1. Crea un Job di ricerca
    2. Attende completamento
    3. Scarica i risultati JSON e li analizza
    """
    headers = {"Authorization": f"Splunk {session_key}"}
    
    # 1. TRIGGER THE JOB (Lancio la ricerca)
    try:
        job_res = httpx.post(
            f"{SPLUNK_HOST}/services/search/jobs",
            headers=headers,
            data={"search": SEARCH_QUERY, "output_mode": "json"},
            verify=False
        )
        if job_res.status_code != 201:
             print(f"[PDP] Errore creazione Job: {job_res.status_code} - {job_res.text}", flush=True)
             return []
             
        sid = job_res.json().get("sid")
        # print(f"[PDP] Splunk Job Started. SID: {sid}", flush=True)
        
        # 2. POLL JOB STATUS
        is_done = False
        while not is_done:
            status_res = httpx.get(
                f"{SPLUNK_HOST}/services/search/jobs/{sid}?output_mode=json",
                headers=headers,
                verify=False
            )
            job_status = status_res.json()
            # Controlla chiave 'isDone' oppure 'dispatchState'
            state = job_status.get("entry", [{}])[0].get("content", {}).get("dispatchState", "")
            if state == "DONE" or state == "FAILED":
                is_done = True
            else:
                time.sleep(1) # Aspetta 1s se la ricerca è complessa
                
        # 3. GET RESULTS
        results_res = httpx.get(
            f"{SPLUNK_HOST}/services/search/jobs/{sid}/results?output_mode=json",
            headers=headers,
            verify=False
        )
        
        results = results_res.json()
        malicious_ips = []
        if "results" in results:
            for row in results["results"]:
                ip = row.get("srcstr")
                if ip:
                    malicious_ips.append(ip)
                    
        return malicious_ips

    except Exception as e:
        print(f"[PDP] Errore durante esecuzione Job API: {e}", flush=True)
        return []

def update_trust(ip_address, deduction):
    """Aggiorna il trust all'interno del Policy Store basandosi sulle scoperte API"""
    try:
        conn = psycopg2.connect(host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASS)
        cur = conn.cursor()
        
        cur.execute("SELECT trust_score FROM policies WHERE device_ip = %s", (ip_address,))
        res = cur.fetchone()
        
        if res:
            current_trust = float(res[0])
            new_trust = max(0.0, current_trust - deduction)
            
            if new_trust != current_trust:
                cur.execute("UPDATE policies SET trust_score = %s, updated_at = NOW() WHERE device_ip = %s", (new_trust, ip_address))
                conn.commit()
                print(f"[PDP-ACTION] 🔥 THREAT INCIDENT: Decreased Trust for {ip_address} | {current_trust} -> {new_trust}. Source: Splunk Dataset Correlation.", flush=True)
                
        cur.close()
        conn.close()
    except Exception as e:
        print(f"[PDP] DB Connection Error: {e}", flush=True)

# =======================================================================
# DAEMON LOOP
# =======================================================================
session_key = None

while True:
    time.sleep(15) # Ogni 15 secondi il PDP elabora l'analytics 
    
    # Acquisizione o rinnovo key
    if not session_key:
        session_key = get_splunk_session_key()
        if not session_key:
            continue
            
    print(f"[{datetime.now().strftime('%H:%M:%S')}] [PDP] Heartbeat: Analisi REST API Log SIEM in corso...", flush=True)
    
    bad_ips = verify_logs_via_api(session_key)
    if bad_ips:
        print(f"[PDP] IDENTIFIED MALICIOUS SOURCE IPs IN DATASET: {bad_ips}", flush=True)
        for bad_ip in bad_ips:
            # Per questioni di Demo forziamo il degrado sui nostri IP se li troviamo nei log
            # Nella realtà 'bad_ip' arriverà dal CSV Splunk. 
            # In questo prototipo simuliamo che il client 'Bob' (172.20.0.12) venga flaggato incrociando i dati!
            if "172.20" in bad_ip or bad_ip == "172.20.0.12":
                 update_trust(bad_ip, 0.40) # Forte detrazione
    else:
        # Per far funzionare la finta demo universitaria anche in assenza di dataset reali caricati su splunk,
        # applichiamo il blocco simulato a Bob come meccanismo fallback visibile.
        # Rimuovere in produzione!
        print("[PDP] Fallback demo: no results from Dataset, applying simulation attack check...")
        update_trust('172.20.0.12', 0.25)
