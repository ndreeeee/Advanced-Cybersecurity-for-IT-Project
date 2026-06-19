import os
import logging
import requests
import socket
from fastapi import FastAPI, HTTPException, Request, Body
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] [%(levelname)s] %(message)s')
logger = logging.getLogger("ZTA-Client-UI")

app = FastAPI(title="ZTA Client Interfaccia")

# Setup static and templates
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Parametri dall'ambiente
CLIENT_NAME = os.getenv("CLIENT_NAME", "unknown")
ENVOY_HOST = "zta-firewall" # Passiamo prima dal firewall
ENVOY_PORT = 8443

# Percorsi dei certificati mTLS
CA_CERT = "/etc/certs/ca.crt"
client_id = CLIENT_NAME.replace('employee-', '')
CLIENT_CERT = f"/etc/certs/{client_id}.crt"
CLIENT_KEY = f"/etc/certs/{client_id}.key"
COMBINED_PEM = f"/etc/certs/{client_id}_combined.pem"

class LoginRequest(BaseModel):
    username: str
    password: str

@app.get("/", response_class=HTMLResponse)
def get_login(request: Request):
    """ Mostra la pagina di login """
    return templates.TemplateResponse(
        request, 
        "login.html", 
        {"client_name": client_id}
    )

def get_device_posture(cid: str) -> str:
    """ 
    Calcola lo stato veritiero del dispositivo in base al certificato/scenario.
    Restituisce markup HTML professionale con icone SVG integrate.
    """
    cid = cid.lower()
    
    # Stile comune per le icone SVG in linea
    svg_style = "width: 16px; height: 16px; vertical-align: middle; margin-right: 6px;"
    
    if cid == "alice":
        return (
            f'<span style="color: #059669; font-weight: 600; display: inline-flex; align-items: center;">'
            f'<svg style="{svg_style}" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">'
            f'<rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>'
            f'<path d="M7 11V7a5 5 0 0110 0v4"></path></svg>'
            f'Workstation Interna (TPM Validato)</span>'
        )
    elif cid == "bob":
        return (
            f'<span style="color: #d97706; font-weight: 600; display: inline-flex; align-items: center;">'
            f'<svg style="{svg_style}" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">'
            f'<path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"></path>'
            f'<line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>'
            f'Rete Interna (Dispositivo Privo di TPM)</span>'
        )
    elif cid == "charlie":
        return (
            f'<span style="color: #2563eb; font-weight: 600; display: inline-flex; align-items: center;">'
            f'<svg style="{svg_style}" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">'
            f'<circle cx="12" cy="12" r="10"></circle>'
            f'<line x1="2" y1="12" x2="22" y2="12"></line>'
            f'<path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z"></path></svg>'
            f'Rete Esterna (Connessione Remota ZTA)</span>'
        )
    else:
        return (
            f'<span style="color: #dc2626; font-weight: 600; display: inline-flex; align-items: center;">'
            f'<svg style="{svg_style}" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">'
            f'<path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"></path>'
            f'<line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>'
            f'Dispositivo Non Censito</span>'
        )

@app.get("/dashboard", response_class=HTMLResponse)
def get_dashboard(request: Request):
    """ Mostra il portale medico dopo il login """
    # Calcola la postura reale al posto della variabile statica di Docker
    posture_reale = get_device_posture(client_id)
    
    return templates.TemplateResponse(
        request, 
        "dashboard.html", 
        {
            "client_name": client_id,
            "client_role": posture_reale  # Ora passa la stringa Enterprise!
        }
    )

def make_mtls_request(method: str, endpoint: str, json_data=None):
    url = f"https://{ENVOY_HOST}:{ENVOY_PORT}{endpoint}"
    
    try:
        # Ottieni l'indirizzo IP locale del container
        local_ip = socket.gethostbyname(socket.gethostname())
    except Exception:
        local_ip = "127.0.0.1"

    headers = {
        "X-Forwarded-For": local_ip
    }

    logger.info(f"Effettuo richiesta mTLS {method} a: {url} (IP Sorgente Simulato: {local_ip})")
    
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
            headers=headers,
            json=json_data,
            timeout=45.0
        )
        
        # Disabilita i warning di urllib3 per le richieste insicure (verify=False)
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        logger.info(f"Risposta ricevuta da Envoy: {response.status_code}")
        
        if response.status_code in (200, 201):
            return response.json()
        elif response.status_code == 403:
            raise HTTPException(status_code=403, detail="Accesso Negato: Dispositivo non autorizzato (TPM mancante o policy violata).")
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

@app.post("/login")
def login(login_req: LoginRequest):
    """ Tenta il login inoltrando le credenziali al backend tramite mTLS """
    logger.info(f"Tentativo di login per l'utente: {login_req.username}")
    
    utenti_validi = ["alice", "bob", "charlie"]
    
    # Controllo credenziali base (Livello Applicativo)
    if login_req.username.lower() not in utenti_validi or login_req.password != "password123":
        raise HTTPException(status_code=401, detail="Credenziali errate. Riprovare.")
        
    # Se le credenziali "tradizionali" sono corrette, verifichiamo la policy Zero Trust
    # Facciamo una chiamata al backend protetto tramite Envoy
    return make_mtls_request("POST", "/api/auth", json_data={"username": login_req.username})

@app.get("/request/patients")
def request_patients():
    return make_mtls_request("GET", "/api/patients")

@app.get("/request/sensitive")
def request_sensitive():
    return make_mtls_request("GET", "/api/patients/sensitive")

@app.delete("/request/drop")
def request_drop():
    return make_mtls_request("DELETE", "/api/patients")

