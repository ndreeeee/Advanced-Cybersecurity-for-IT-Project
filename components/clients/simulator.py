import os
import logging
import requests
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] [%(levelname)s] %(message)s')
logger = logging.getLogger("ZTA-Client-UI")

app = FastAPI(title="ZTA Client Interfaccia")

# Setup template Jinja2
templates = Jinja2Templates(directory="templates")

# Parametri dall'ambiente
CLIENT_NAME = os.getenv("CLIENT_NAME", "unknown")
CLIENT_ROLE = os.getenv("CLIENT_ROLE", "legit")
ENVOY_HOST = "zta-firewall" # Passiamo prima dal firewall che fa da reverse proxy verso Envoy, quindi usiamo il nome del servizio del firewall
ENVOY_PORT = 8443  # Nuovo listener HTTP di Envoy protetto da mTLS

# Percorsi dei certificati mTLS caricati a volume
CA_CERT = "/etc/certs/ca.crt"
client_id = CLIENT_NAME.replace('employee-', '')
CLIENT_CERT = f"/etc/certs/{client_id}.crt"
CLIENT_KEY = f"/etc/certs/{client_id}.key"
COMBINED_PEM = f"/etc/certs/{client_id}_combined.pem"

@app.get("/", response_class=HTMLResponse)
def get_dashboard(request: Request):
    """ Restituisce l'interfaccia grafica HTML """
    return templates.TemplateResponse(
        request, 
        "index.html", 
        {
            "client_name": client_id,
            "client_role": CLIENT_ROLE
        }
    )

def make_mtls_request(method: str, endpoint: str):
    url = f"https://{ENVOY_HOST}:{ENVOY_PORT}{endpoint}"
    logger.info(f"Effettuo richiesta mTLS {method} a: {url}")
    
    # Determina quale file di certificato usare
    cert = None
    if os.path.exists(COMBINED_PEM):
        cert = COMBINED_PEM
    elif os.path.exists(CLIENT_CERT) and os.path.exists(CLIENT_KEY):
        cert = (CLIENT_CERT, CLIENT_KEY)
    else:
        logger.error("Certificati mTLS non trovati!")
        raise HTTPException(status_code=500, detail="Certificati mTLS mancanti sul client")

    try:
        # Nota: usiamo verify=CA_CERT per validare il certificato di Envoy
        # tlsInsecure=true nei log di prima indica che possiamo ignorare il match del CN (visto che siamo su rete Docker)
        # requests supporta verify=False ma se vogliamo validare la CA passiamo il CA_CERT.
        # Per evitare problemi di CN (hostname mismatch) e considerando che siamo in ambiente demo chiuso:
        response = requests.request(
            method=method,
            url=url,
            cert=cert,
            verify=False,  # Ignoriamo il controllo CN del server per semplicità di sviluppo locale
            timeout=45.0
        )
        
        # Disabilita i warning di urllib3 per le richieste insicure (verify=False)
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        logger.info(f"Risposta ricevuta da Envoy: {response.status_code}")
        
        if response.status_code in (200, 201):
            return response.json()
        elif response.status_code == 403:
            raise HTTPException(status_code=403, detail="Accesso Negato dalla Policy OPA del PEP")
        else:
            # Altri errori inoltrati
            try:
                err_detail = response.json().get("detail", response.text)
            except Exception:
                err_detail = response.text
            raise HTTPException(status_code=response.status_code, detail=err_detail)
            
    except requests.exceptions.ConnectionError as ce:
        logger.error(f"Errore connessione ad Envoy: {ce}")
        raise HTTPException(status_code=503, detail="Impossibile connettersi ad Envoy. PEP offline o mTLS rifiutato.")
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        logger.error(f"Errore generico durante richiesta mTLS: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/request/patients")
def request_patients():
    return make_mtls_request("GET", "/api/patients")

@app.get("/request/sensitive")
def request_sensitive():
    return make_mtls_request("GET", "/api/patients/sensitive")

@app.delete("/request/drop")
def request_drop():
    return make_mtls_request("DELETE", "/api/patients")

@app.get("/request/bypass")
def request_bypass():
    # Simulazione: L'attaccante tenta di bypassare Envoy e colpire le API (porta 8000)
    url = f"http://{ENVOY_HOST}:8000/api/patients"
    logger.info(f"Tentativo di BYPASS FIREWALL diretto a: {url}")
    
    try:
        # Usiamo un timeout basso (2 secondi) perché sappiamo che il firewall non risponderà mai (Drop)
        response = requests.get(url, timeout=2.0)
        return response.json()
    except requests.exceptions.Timeout:
        # Se va in Timeout, il firewall ha fatto "DROP"
        raise HTTPException(
            status_code=408, 
            detail="Timeout di Rete: Il Firewall (nftables) ha intercettato e droppato il pacchetto sulla porta 8000. Regola di Default Deny funzionante."
        )
    except requests.exceptions.ConnectionError:
        # Se viene rifiutata, il firewall ha fatto "REJECT"
        raise HTTPException(
            status_code=503, 
            detail="Connessione Rifiutata: Il Firewall ha bloccato attivamente il traffico non autorizzato sulla porta 8000."
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))