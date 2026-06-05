import os
import re
import time
import logging
from datetime import datetime
from collections import defaultdict
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] [%(levelname)s] %(message)s')
logger = logging.getLogger("Web-API")

app = FastAPI(title="ZTA Web API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

MONGO_URI = os.getenv("MONGO_URI", "mongodb://mongodb-resource:27017/")

# ================================================================
# TRACKER COMPORTAMENTALI IN-MEMORY (per feature ML)
# ================================================================
# Ogni entry è una lista di timestamp. Le liste vengono ripulite
# automaticamente ad ogni accesso (TTL-based eviction).

# Tracker dei login falliti per utente (finestra: 24 ore)
# Un "login fallito" corrisponde a una predizione il cui risk score
# finale supera la soglia massima di OPA (50), indicando che la
# richiesta è stata quasi certamente respinta con DENY.
failed_login_tracker: dict[str, list[float]] = defaultdict(list)
FAILED_LOGIN_WINDOW = 86400  # 24 ore in secondi

# Tracker della frequenza di sessione per utente (finestra: 1 ora)
session_tracker: dict[str, list[float]] = defaultdict(list)
SESSION_FREQ_WINDOW = 3600  # 1 ora in secondi

# Mappa delle risorse ai livelli di sensibilità (coerente col dataset)
RESOURCE_SENSITIVITY = {
    "pazienti": 2,
    "utenti": 1,
    "cartelle_cliniche": 3,
    "system_logs": 2,
    "config_db": 3,
}


def _cleanup_tracker(tracker: list[float], window: float) -> list[float]:
    """Rimuove le entry più vecchie della finestra temporale."""
    cutoff = time.time() - window
    return [t for t in tracker if t > cutoff]


def get_failed_logins(user: str) -> int:
    """Ritorna il numero di login falliti per l'utente nelle ultime 24h."""
    failed_login_tracker[user] = _cleanup_tracker(
        failed_login_tracker[user], FAILED_LOGIN_WINDOW
    )
    return len(failed_login_tracker[user])


def record_failed_login(user: str):
    """Registra un login fallito (chiamato quando il risk score è alto)."""
    failed_login_tracker[user].append(time.time())
    logger.info(f"[TRACKER] Login fallito registrato per '{user}'. "
                f"Totale ultime 24h: {len(failed_login_tracker[user])}")


def get_session_freq(user: str) -> int:
    """Ritorna il numero di sessioni dell'utente nell'ultima ora."""
    session_tracker[user] = _cleanup_tracker(
        session_tracker[user], SESSION_FREQ_WINDOW
    )
    return len(session_tracker[user])


def record_session(user: str):
    """Registra una sessione (ogni richiesta ML conta come sessione)."""
    session_tracker[user].append(time.time())


def get_sensitivity_level(resource: str) -> int:
    """Ritorna il livello di sensibilità della risorsa (1-3)."""
    return RESOURCE_SENSITIVITY.get(resource, 1)


def extract_user_from_spl(query: str) -> str:
    """Estrae il valore del campo user dalla query SPL."""
    match = re.search(r'user="([^"]+)"', query)
    return match.group(1) if match else "unknown"


def extract_resource_from_spl(query: str) -> str:
    """Estrae il valore del campo resource dalla query SPL."""
    match = re.search(r'resource="([^"]+)"', query)
    return match.group(1) if match else "unknown"


def extract_network_from_spl(query: str) -> str:
    """Estrae il valore del campo network dalla query SPL."""
    match = re.search(r'network="([^"]+)"', query)
    return match.group(1) if match else "0.0.0.0"


def enrich_spl_with_behavioral_features(query: str, simulate_dormant_night: bool = False) -> str:
    """
    Arricchisce la query SPL generata da OPA con le 6 feature comportamentali.

    OPA genera una query con le 6 dimensioni ZTA originali:
      | makeresults | eval user="...", software="...", ... | apply trust_model | ...

    Questa funzione inietta le feature aggiuntive nell'eval, prima dell'apply:
      | makeresults | eval user="...", ..., failed_logins=X, hour_of_day=Y, ... | apply trust_model | ...

    In questo modo OPA e rules.rego restano completamente invariati.
    """
    user = extract_user_from_spl(query)
    resource = extract_resource_from_spl(query)
    network_ip = extract_network_from_spl(query)

    # Registra la sessione corrente
    record_session(user)

    # Rilevamento connessione esterna (smart working)
    is_external = (
        network_ip.startswith("1.2.3.") or 
        network_ip.startswith("192.168.100.") or 
        network_ip == "172.18.0.6"
    )
    is_external_charlie = (user == "charlie" and is_external)

    # Rilevamento connessione diretta al database (MongoDB) da parte di Alice (PC compromesso)
    is_db_connection = (
        "patients" in resource or 
        "patients_sensitive" in resource or 
        "pazienti" in resource or
        "cartelle_cliniche" in resource or
        "MongoDB" in resource or 
        "Risorsa" in resource
    )
    is_compromised_alice = (user == "alice" and is_db_connection)

    # Calcola le feature comportamentali in tempo reale
    now = datetime.now()
    
    if simulate_dormant_night:
        hour_of_day = 3
        is_night = 1
        failed_logins = 4
        days_inactive = 90
        session_freq = get_session_freq(user)
    elif is_external_charlie:
        # Scenario Smart Working per Charlie: simuliamo un'anomalia comportamentale
        # (es. account dormiente riattivato da rete esterna con tentativi falliti)
        # per costringere il modello a calcolare un risco molto elevato (> 50, quindi > 8 della soglia OPA)
        hour_of_day = now.hour
        is_night = 1 if (hour_of_day >= 22 or hour_of_day < 6) else 0
        failed_logins = 3
        days_inactive = 90
        session_freq = get_session_freq(user)
    elif is_compromised_alice:
        # Scenario PC Alice Compromesso: simuliamo anomalie per far schizzare il rischio predittivo
        # in modo da superare la soglia interna di OPA (50) e bloccare la connessione al database
        hour_of_day = now.hour
        is_night = 1 if (hour_of_day >= 22 or hour_of_day < 6) else 0
        failed_logins = 4
        days_inactive = 60
        session_freq = 30
    else:
        hour_of_day = now.hour
        is_night = 1 if (hour_of_day >= 22 or hour_of_day < 6) else 0
        failed_logins = get_failed_logins(user)
        days_inactive = 0
        session_freq = get_session_freq(user)

    sensitivity_level = get_sensitivity_level(resource)

    # Costruisci la stringa con le feature aggiuntive
    behavioral_features = (
        f', failed_logins={failed_logins}'
        f', hour_of_day={hour_of_day}'
        f', is_night={is_night}'
        f', session_freq={session_freq}'
        f', sensitivity_level={sensitivity_level}'
        f', days_inactive={days_inactive}'
    )

    # Inietta le feature prima del comando '| apply'
    enriched = query.replace('| apply ', f'{behavioral_features} | apply ')

    logger.info(f"[ENRICH] Feature comportamentali iniettate per user='{user}' (Simulation={simulate_dormant_night}, ExtCharlie={is_external_charlie}): "
                f"failed_logins={failed_logins}, hour={hour_of_day}, night={is_night}, "
                f"freq={session_freq}, sens={sensitivity_level}, inactive={days_inactive}")

    return enriched

def get_db():
    try:
        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=3000)
        return client["hospital_db"]
    except ConnectionFailure:
        logger.error("Non riesco a connettermi al Database MongoDB.")
        return None

@app.get("/api/patients")
async def get_patients(request: Request):
    """
    Ritorna la lista dei pazienti (dati di base).
    Accessibile da 'legit' o 'suspect' se il TPM è valido.
    """
    logger.info("Richiesta a /api/patients accettata. Recupero dati da MongoDB...")
    db = get_db()
    if db is None:
        raise HTTPException(status_code=503, detail="Database irraggiungibile")
    patients = list(db.patients.find({}, {"name": 1, "ward": 1, "_id": 0}))
    return {"status": "success", "data": patients}

@app.post("/api/auth")
async def authenticate(request: Request):
    """
    Endpoint di test per il login.
    Non esegue vera logica perché Envoy e OPA fanno l'autorizzazione a monte basata su mTLS.
    Se OPA blocca, questa funzione non viene nemmeno raggiunta.
    """
    logger.info("Richiesta di login passata attraverso Envoy/OPA con successo.")
    return {"status": "success", "message": "Autenticazione Zero Trust completata."}

@app.get("/api/patients/sensitive")
def get_sensitive_data(request: Request):
    """ Restituisce i dati sensibili (note cliniche) """
    logger.info("Richiesta ricevuta per /api/patients/sensitive")
    db = get_db()
    if db is None:
        raise HTTPException(status_code=503, detail="Database irraggiungibile")
    
    sensitive_data = list(db.patients.find({}, {"name": 1, "sensitive_notes": 1, "treatment": 1, "_id": 0}))
    return {"status": "success", "data": sensitive_data}

@app.delete("/api/patients")
def delete_patients(request: Request):
    """ Simula un'azione distruttiva """
    logger.warning("Richiesta di DROP COLLECTION ricevuta!")
    db = get_db()
    if db is None:
        raise HTTPException(status_code=503, detail="Database irraggiungibile")
    
    # In questa demo non droppiamo davvero il db per non doverlo ricreare, ma simuliamo un errore
    raise HTTPException(status_code=403, detail="Azione distruttiva bloccata dal Database (Simulata)")

import requests
import urllib3
from pydantic import BaseModel

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class MLQuery(BaseModel):
    query: str

@app.post("/api/ml/predict")
def predict_risk(ml_query: MLQuery):
    """ Proxy endpoint for OPA to query Splunk MLTK """
    logger.info(f"Ricevuta query ML: {ml_query.query}")
    
    # Rilevamento simulazione dell'anomalia temporale (dormant account / orario anomalo)
    simulate_dormant_night = "simulate=dormant_night" in ml_query.query
    
    # Credenziali lette dalle variabili d'ambiente (non hardcodate)
    splunk_url = os.getenv("SPLUNK_URL", "https://zta-splunk:8089/services/search/jobs/export")
    splunk_user = os.getenv("SPLUNK_USER", "admin")
    splunk_password = os.getenv("SPLUNK_PASSWORD", "changeme")
    auth = (splunk_user, splunk_password)
    
    # Rimozione dei parametri di query di simulazione per non invalidare il mapping della risorsa
    clean_query = ml_query.query.replace("?simulate=dormant_night", "").replace("&simulate=dormant_night", "")
    
    # Mappatura dei valori reali ZTA ai valori del dataset di addestramento Splunk MLTK.
    # Centralizzata in un dizionario per facilitare la manutenzione.
    # L'algoritmo genera un errore FATAL se riceve categorie non viste in fase di fit.
    # NOTA: I nomi utente (alice, bob, charlie) ora coincidono tra OPA e dataset,
    #       quindi non richiedono più traduzione.
    ZTA_TO_MLTK_MAP = {
        # Software (JA3 hash → etichetta training)
        'software="86dab2109182b6bbaa644647d7db2997"': 'software="chrome_115"',
        # Dispositivi
        'device="Workstation Ospedaliera Sicura (TPM Validato)"': 'device="tpm_enclave_88"',
        'device="Dispositivo non censito (No TPM)"':              'device="missing_tpm"',
        # Rete (subnet Docker → etichetta training)
        'network="10.0.1.':  'network="10.0.0.',       # Rete interna (prefix match)
        'network="192.168.100.': 'network="1.2.3.',     # Rete esterna (prefix match)
        'network="172.18.0.5"': 'network="10.0.0.15"',  # Supporto per rete locale Docker
        'network="172.18.0.6"': 'network="1.2.3.4"',     # Supporto per rete locale Docker
        # Azioni
        'action="GET"':    'action="find"',
        'action="POST"':   'action="insert"',
        'action="DELETE"': 'action="drop"',
        'action="Comando MongoDB sconosciuto"': 'action="find"',
        'action="Accesso Diretto MongoDB (OP_MSG)"': 'action="find"',
        'action="Operazione Non Definita"':     'action="find"',
        # Risorse
        'resource="/api/patients/sensitive"': 'resource="cartelle_cliniche"',
        'resource="/api/patients"':          'resource="pazienti"',
        'resource="/api/drop"':              'resource="config_db"',
        # Risorse MongoDB (da query intercettate da Envoy mongo_proxy)
        'resource="patients"':               'resource="pazienti"',
        'resource="patients_sensitive"':     'resource="cartelle_cliniche"',
        'resource="MongoDB (Collezione sconosciuta)"': 'resource="pazienti"',
        'resource="Risorsa Non Definita"':             'resource="pazienti"',
        # Utenti non censiti
        'user="Sconosciuto"': 'user="charlie"',
    }
    q = clean_query
    for original, replacement in ZTA_TO_MLTK_MAP.items():
        q = q.replace(original, replacement)
    
    # ================================================================
    # ARRICCHIMENTO COMPORTAMENTALE:
    # Inietta le 6 feature aggiuntive nella query SPL prima di inviarla
    # a Splunk. OPA e rules.rego restano completamente invariati.
    # ================================================================
    q = enrich_spl_with_behavioral_features(q, simulate_dormant_night)
    
    logger.info(f"Query ML Arricchita: {q}")
    
    data = {
        "search": q,
        "output_mode": "json"
    }
    
    try:
        response = requests.post(splunk_url, auth=auth, data=data, verify=False, timeout=30.0)
        response.raise_for_status()
        
        logger.info(f"Risposta Splunk: {response.text}")
        
        # Splunk export json restituisce una o più righe JSON (JSON Lines). 
        # La risposta è della forma: {"preview":false,"offset":0,"lastrow":true,"result":{"rischio":"15"}}
        import json
        for line in response.text.strip().split('\n'):
            if line:
                res_obj = json.loads(line)
                if "result" in res_obj and "rischio" in res_obj["result"]:
                    risk_score = float(res_obj["result"]["rischio"])
                    
                    # Se lo score è alto, registra come "login fallito"
                    # per alimentare il tracker comportamentale
                    user = extract_user_from_spl(q)
                    if risk_score > 50:
                        record_failed_login(user)
                    
                    return {"rischio": risk_score}
                    
        raise HTTPException(status_code=500, detail="Risposta di Splunk non contiene 'rischio'")
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Errore comunicazione con Splunk: {e}")
        raise HTTPException(status_code=502, detail=str(e))
