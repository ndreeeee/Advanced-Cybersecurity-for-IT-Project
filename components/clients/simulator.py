import time
import os
import ssl
import logging
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, OperationFailure

# Configurazione Log
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] [%(levelname)s] %(message)s')
logger = logging.getLogger("ZTA-Client")

# Parametri dall'ambiente
CLIENT_NAME = os.getenv("CLIENT_NAME", "unknown")
CLIENT_ROLE = os.getenv("CLIENT_ROLE", "legit")
TARGET_HOST = "zta-envoy"  # Envoy PEP: prima linea di difesa applicativa (mTLS + OPA)
TARGET_PORT = 27017

# Percorsi certificati (montati tramite Docker volume)
CA_CERT = "/etc/certs/ca.crt"
CLIENT_CERT = f"/etc/certs/{CLIENT_NAME.replace('employee-', '')}.crt"
CLIENT_KEY = f"/etc/certs/{CLIENT_NAME.replace('employee-', '')}.key"

def get_mongo_client():
    """Crea una connessione MongoDB protetta da mTLS tramite URI."""
    # Percorso del file combinato (certificato + chiave) - es. alice_combined.pem
    client_id = CLIENT_NAME.replace('employee-', '')
    COMBINED_PEM = f"/etc/certs/{client_id}_combined.pem"

    uri = (
        f"mongodb://{TARGET_HOST}:{TARGET_PORT}/?authSource=admin"
        f"&tls=true"
        f"&tlsCAFile={CA_CERT}"
        f"&tlsCertificateKeyFile={COMBINED_PEM}"
        f"&serverSelectionTimeoutMS=5000"
        f"&tlsInsecure=true"  # Evita errori di hostname matching nei nomi interni Docker
    )

    try:
        logger.info(f"Connessione a: mongodb://{TARGET_HOST}:{TARGET_PORT}/ (TLS attivo, cert: {client_id})")
        client = MongoClient(uri)
        return client
    except Exception as e:
        logger.error(f"Errore creazione client MongoDB: {e}")
        return None

def run_simulation():
    logger.info(f"🚀 Avvio simulatore ZTA per: {CLIENT_NAME} (Ruolo: {CLIENT_ROLE})")
    
    while True:
        client = get_mongo_client()
        if not client:
            time.sleep(10)
            continue

        try:
            db = client["hospital_db"]
            
            # SCENARIO 1: Lettura dati non sensibili (Permesso a tutti i certificati validi)
            logger.info(f"🔍 {CLIENT_NAME} tenta lettura lista pazienti (Dati base)...")
            patients = db.patients.find({}, {"name": 1, "ward": 1, "_id": 0}).limit(3)
            for p in patients:
                logger.info(f"   [DATA] Paziente: {p.get('name')} | Reparto: {p.get('ward')}")

            # SCENARIO 2: Lettura dati sensibili (Richiede TPM OID secondo le policy ZTA)
            logger.info(f"🔐 {CLIENT_NAME} tenta lettura NOTE SENSIBILI...")
            sensitive_data = db.patients.find({}, {"name": 1, "sensitive_notes": 1, "_id": 0}).limit(1)
            for s in sensitive_data:
                notes = s.get('sensitive_notes', '🚫 [ACCESSO NEGATO DAL PEP]')
                logger.info(f"   [SENSITIVE] {s.get('name')}: {notes}")

            # SCENARIO 3: Tentativo di attacco (Solo se Bob)
            if CLIENT_ROLE == "suspect":
                logger.warning(f"💀 {CLIENT_NAME} tenta attacco: DROP COLLECTION!")
                try:
                    db.patients.drop()
                except OperationFailure as oe:
                    logger.error(f"   [BLOCCATO] Il PEP/OPA ha impedito l'operazione distruttiva: {oe}")

        except ConnectionFailure:
            logger.error("❌ Connessione ad Envoy fallita. mTLS rifiutato o PEP offline.")
        except Exception as e:
            logger.error(f"⚠️ Errore durante l'operazione: {e}")
        finally:
            client.close()
            
        time.sleep(15)

if __name__ == "__main__":
    run_simulation()
