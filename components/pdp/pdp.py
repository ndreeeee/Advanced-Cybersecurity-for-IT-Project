import os
import time
import httpx
import psycopg2
from datetime import datetime

DB_HOST = os.getenv("DB_HOST", "dbms")
DB_USER = os.getenv("DB_USER", "zta_admin")
DB_PASS = os.getenv("DB_PASS", "zta_password")
DB_NAME = os.getenv("DB_NAME", "zta_policy")

SPLUNK_HOST = "http://splunk:8089"

print("[PDP] Policy Decision Point Motor Started. Analyzing network telemetry...", flush=True)

def update_trust(ip_address, deduction):
    """Sottrae o azzera il trust di una macchina a seguito di una violazione."""
    try:
        conn = psycopg2.connect(host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASS)
        cur = conn.cursor()
        
        # Recupera trust attuale
        cur.execute("SELECT trust_score FROM policies WHERE device_ip = %s", (ip_address,))
        res = cur.fetchone()
        
        if res:
            current_trust = float(res[0])
            new_trust = max(0.0, current_trust - deduction)
            
            if new_trust != current_trust:
                cur.execute("UPDATE policies SET trust_score = %s, updated_at = NOW() WHERE device_ip = %s", (new_trust, ip_address))
                conn.commit()
                print(f"[PDP] Updated trust for {ip_address}: {current_trust} -> {new_trust}", flush=True)
                
        cur.close()
        conn.close()
    except Exception as e:
        print(f"[PDP] DB Connection Error: {e}", flush=True)

# Loop continuo che fa il polling in Splunk (SIMULATO PER DEMO)
while True:
    time.sleep(10)
    # In un'architettura 100% reale qui faremmo una request REST a Splunk.
    # Per la demo accademica, si può simulare la deduzione o implementare
    # le chiamate API di Splunk successivamente prima dell'esame.
    print(f"[{datetime.now().strftime('%H:%M:%S')}] [PDP] Heartbeat: Analisi log SIEM in corso. Nessuna minaccia addizionale rilevata...", flush=True)
    
    # Se notiamo anomalie gravi abbassiamo a zero:
    # update_trust('172.20.0.12', 10.0)  # Azzera trust
