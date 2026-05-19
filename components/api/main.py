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
