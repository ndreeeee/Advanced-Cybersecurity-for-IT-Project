"""
Script di generazione traffico simulato per ZTA Dashboard
Eseguire da fuori i container: python generate_traffic.py
Genera traffico realistico su tutti e 3 i client per popolare Splunk.
"""

import requests
import time
import random
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ================================================================
# CONFIGURAZIONE: porta esposta da docker-compose per ogni client
# ================================================================
CLIENTS = {
    "alice":   "http://localhost:8081",
    "bob":     "http://localhost:8082",
    "charlie": "http://localhost:8083",
}

# Credenziali valide (come da simulator.py)
VALID_PASSWORD = "password123"

def login(base_url: str, username: str) -> bool:
    """Tenta il login su un client. Ritorna True se 200, False se bloccato."""
    try:
        r = requests.post(
            f"{base_url}/login",
            json={"username": username, "password": VALID_PASSWORD},
            timeout=10
        )
        print(f"  [LOGIN] {username} → {r.status_code}")
        return r.status_code == 200
    except Exception as e:
        print(f"  [ERRORE] {username} login: {e}")
        return False

def get_patients(base_url: str, username: str):
    """Richiede la lista pazienti (GET /api/patients)."""
    try:
        r = requests.get(f"{base_url}/request/patients", timeout=10)
        print(f"  [PATIENTS] {username} → {r.status_code}")
    except Exception as e:
        print(f"  [ERRORE] {username} patients: {e}")

def get_sensitive(base_url: str, username: str):
    """Richiede dati sensibili (GET /api/patients/sensitive)."""
    try:
        r = requests.get(f"{base_url}/request/sensitive", timeout=10)
        print(f"  [SENSITIVE] {username} → {r.status_code}")
    except Exception as e:
        print(f"  [ERRORE] {username} sensitive: {e}")

def drop_attack(base_url: str, username: str):
    """Simula attacco L7 injection (DELETE /request/drop)."""
    try:
        r = requests.delete(f"{base_url}/request/drop", timeout=10)
        print(f"  [DROP ATTACK] {username} → {r.status_code}")
    except Exception as e:
        print(f"  [ERRORE] {username} drop: {e}")

def run_scenario(name: str, fn, *args):
    print(f"\n{'='*50}")
    print(f"SCENARIO: {name}")
    print(f"{'='*50}")
    fn(*args)

def main():
    print("\n🚀 Avvio generazione traffico ZTA...\n")
    print("Assicurati che tutti i container siano UP con: docker ps\n")
    
    # Numero di ripetizioni per avere abbastanza eventi in Splunk
    RIPETIZIONI = 10

    for i in range(RIPETIZIONI):
        print(f"\n{'#'*50}")
        print(f"# ROUND {i+1}/{RIPETIZIONI}")
        print(f"{'#'*50}")

        # --- SCENARIO 1: Alice accede legittimamente ---
        run_scenario("Alice - Accesso Legittimo (TPM + Rete Interna)",
            login, CLIENTS["alice"], "alice")
        time.sleep(0.5)
        get_patients(CLIENTS["alice"], "alice")
        time.sleep(0.5)
        
        # A volte Alice accede anche ai dati sensibili
        if random.random() > 0.5:
            get_sensitive(CLIENTS["alice"], "alice")
            time.sleep(0.5)

        # --- SCENARIO 2: Bob bloccato (no TPM) ---
        run_scenario("Bob - BYOD senza TPM (atteso DENY)",
            login, CLIENTS["bob"], "bob")
        time.sleep(0.5)

        # --- SCENARIO 3: Charlie da rete esterna ---
        # Login ALLOW, /api/patients ALLOW, /api/patients/sensitive DENY
        run_scenario("Charlie - Rete Esterna: Login (atteso ALLOW)",
            login, CLIENTS["charlie"], "charlie")
        time.sleep(0.5)
        run_scenario("Charlie - Rete Esterna: Pazienti (atteso ALLOW)",
            get_patients, CLIENTS["charlie"], "charlie")
        time.sleep(0.5)
        run_scenario("Charlie - Rete Esterna: Dati Sensibili (atteso DENY)",
            get_sensitive, CLIENTS["charlie"], "charlie")
        time.sleep(0.5)

        # --- SCENARIO 5: Alice injection L7 (ogni 3 round) ---
        if i % 3 == 0:
            run_scenario("Alice - Attacco Injection L7 DELETE (atteso DENY)",
                drop_attack, CLIENTS["alice"], "alice")
            time.sleep(0.5)

        # Pausa tra i round per avere spread temporale nei grafici
        pause = random.uniform(1.0, 2.0)
        print(f"\n⏳ Pausa {pause:.1f}s prima del prossimo round...")
        time.sleep(pause)

    print("\n✅ Generazione traffico completata!")
    print("Vai su Splunk e verifica con: index=main sourcetype=httpevent | stats count by response_code")

if __name__ == "__main__":
    main()