import os
import logging
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

def get_db():
    try:
        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=3000)
        return client["hospital_db"]
    except ConnectionFailure:
        logger.error("Non riesco a connettermi al Database MongoDB.")
        return None

@app.get("/api/patients")
def get_patients(request: Request):
    """ Restituisce i dati base dei pazienti """
    logger.info("Richiesta ricevuta per /api/patients")
    db = get_db()
    if db is None:
        raise HTTPException(status_code=503, detail="Database irraggiungibile")
    
    patients = list(db.patients.find({}, {"name": 1, "ward": 1, "_id": 0}))
    return {"status": "success", "data": patients}

@app.get("/api/patients/sensitive")
def get_sensitive_data(request: Request):
    """ Restituisce i dati sensibili (note cliniche) """
    logger.info("Richiesta ricevuta per /api/patients/sensitive")
    db = get_db()
    if db is None:
        raise HTTPException(status_code=503, detail="Database irraggiungibile")
    
    sensitive_data = list(db.patients.find({}, {"name": 1, "sensitive_notes": 1, "_id": 0}))
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
    
    # Credenziali di default per Splunk
    splunk_url = "https://zta-splunk:8089/services/search/jobs/export"
    auth = ("admin", "pratofiorito")
    
    # Mappatura dei valori reali ZTA ai valori del dataset di addestramento Splunk MLTK
    # L'algoritmo RandomForestRegressor genera un errore FATAL se riceve categorie non viste in fase di fit
    q = ml_query.query
    q = q.replace('user="alice"', 'user="alice.medico"')
    q = q.replace('user="bob"', 'user="mario.rossi"')
    q = q.replace('software="86dab2109182b6bbaa644647d7db2997"', 'software="chrome_115"')
    q = q.replace('device="Workstation Ospedaliera Sicura (TPM Validato)"', 'device="tpm_enclave_88"')
    q = q.replace('device="Dispositivo non censito (No TPM)"', 'device="missing_tpm"')
    q = q.replace('network="172.18.0.5"', 'network="10.0.0.15"') 
    q = q.replace('network="172.18.0.6"', 'network="1.2.3.4"') 
    q = q.replace('action="GET"', 'action="find"')
    q = q.replace('action="DELETE"', 'action="drop"')
    q = q.replace('resource="/api/patients"', 'resource="pazienti"')
    q = q.replace('resource="/api/patients/sensitive"', 'resource="cartelle_cliniche"')
    q = q.replace('resource="/api/drop"', 'resource="config_db"')
    
    logger.info(f"Query ML Mappata: {q}")
    
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
                    return {"rischio": float(res_obj["result"]["rischio"])}
                    
        raise HTTPException(status_code=500, detail="Risposta di Splunk non contiene 'rischio'")
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Errore comunicazione con Splunk: {e}")
        raise HTTPException(status_code=502, detail=str(e))
