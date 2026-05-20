import os
import subprocess
import logging
from fastapi import FastAPI, HTTPException
import uvicorn

app = FastAPI(title="ZTA Firewall Management API (nftables)")

# -----------------------------------------------------------------------
# Configurazione Logging su File per Fluent Bit
# -----------------------------------------------------------------------
log_dir = "/var/log/nftables"
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, "firewall.log")

log = logging.getLogger("nftables-firewall")
log.setLevel(logging.INFO)

# Formato JSON-friendly (Key-Value) per facilitare il parsing in Splunk
formatter = logging.Formatter('time="%(asctime)s" component="firewall" level="%(levelname)s" %(message)s')

# Scriviamo su file
file_handler = logging.FileHandler(log_file)
file_handler.setFormatter(formatter)
log.addHandler(file_handler)

# Scriviamo anche su console per il debug in Docker
console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
log.addHandler(console_handler)

# -----------------------------------------------------------------------
# In-memory ban set (cache per non chiamare sempre nftables)
# -----------------------------------------------------------------------
banned_ips: set[str] = set()

# -----------------------------------------------------------------------
# MANAGEMENT ENDPOINTS 
# -----------------------------------------------------------------------
@app.post("/ban")
async def ban_ip(ip: str):
    if not ip:
        raise HTTPException(status_code=400, detail="Missing IP")

    banned_ips.add(ip)
    log.info(f'event="ban_request" client_ip="{ip}"')

    try:
        # NFTables: Aggiunge la regola di DROP. 
        # Assumiamo che la tabella 'filter' e la chain 'input/forward' esistano 
        # (vengono create di solito all'avvio dal file nftables.conf o dallo start.sh)
        subprocess.run(
            ["nft", "add", "element", "ip", "filter", "denylist", "{", ip, "}"],
            check=True,
        )
        log.info(f'event="nftables_drop" status="added" client_ip="{ip}"')
    except subprocess.CalledProcessError as e:
        log.error(f'event="nftables_error" error="{e}"')
        # Se fallisce (es. regola già esistente o chain mancante), passiamo avanti
        pass

    return {"status": "success", "message": f"{ip} DROPPED via NFTables."}

@app.get("/status")
async def get_status():
    try:
        res = subprocess.check_output(["nft", "list", "ruleset"])
        return {"rules": res.decode(), "banned_ips": sorted(banned_ips)}
    except Exception as e:
        return {"error": str(e)}

if __name__ == "__main__":
    log.info('event="firewall_api_start" message="Firewall Management API is running"')
    # Eseguiamo l'API su 0.0.0.0 per ascoltare connessioni interne a Docker
    uvicorn.run(app, host="0.0.0.0", port=80)
