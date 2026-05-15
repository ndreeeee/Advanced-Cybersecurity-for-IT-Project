import os
import subprocess
import logging
import httpx  # pyrefly: ignore [missing-import]
from fastapi import FastAPI, Request, HTTPException  # pyrefly: ignore [missing-import]
from fastapi.responses import Response  # pyrefly: ignore [missing-import]

app = FastAPI(title="ZTA Firewall — NFTables + L3/L4 Reverse Proxy")

# -----------------------------------------------------------------------
# In-memory ban set (mirrors iptables DROP rules for fast app-level check)
# -----------------------------------------------------------------------
banned_ips: set[str] = set()

NEXT_HOP = os.getenv("NEXT_HOP", "http://pep:80")

# Syslog-style logger → stdout (Docker) + syslog (Splunk)
log = logging.getLogger("firewall")
log.setLevel(logging.INFO)
# Standard KV format for Splunk (Rsyslog will add the timestamp)
formatter = logging.Formatter('component=firewall %(message)s')

sh = logging.StreamHandler()
sh.setFormatter(formatter)
log.addHandler(sh)

from datetime import datetime
import socket
class SplunkUDPHandler(logging.Handler):
    def __init__(self, host, port):
        super().__init__()
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def emit(self, record):
        try:
            msg = self.format(record)
            # Aggiungiamo il timestamp corrente per Splunk
            full_msg = f"{datetime.now().strftime('%b %d %H:%M:%S')} {msg}"
            self.sock.sendto(full_msg.encode('utf-8'), (self.host, self.port))
        except Exception:
            self.handleError(record)

try:
    sysh = SplunkUDPHandler('splunk', 1514)
    sysh.setFormatter(formatter)
    log.addHandler(sysh)
except Exception as e:
    print(f"[FIREWALL] Splunk setup failed: {e}", flush=True)

# -----------------------------------------------------------------------
# MANAGEMENT ENDPOINTS  (called by PEP to ban an IP)
# -----------------------------------------------------------------------
@app.post("/ban")
async def ban_ip(ip: str):
    if not ip:
        raise HTTPException(status_code=400, detail="Missing IP")

    banned_ips.add(ip)
    log.info(f"event=ban_request client_ip={ip}")

    try:
        # NFTables: Add rule to the 'forward' chain in the 'filter' table
        # Sintassi: nft add rule ip filter forward ip saddr <IP> drop
        subprocess.run(
            ["nft", "add", "rule", "ip", "filter", "forward", "ip", "saddr", ip, "drop"],
            check=True,
        )
        log.info(f"event=nftables_drop status=added client_ip={ip}")
    except subprocess.CalledProcessError as e:
        log.error(f"nftables error: {e}")
        # Se fallisce perché la regola esiste già, procediamo
        pass

    return {"status": "success", "message": f"{ip} DROPPED via NFTables."}


@app.get("/status")
async def get_status():
    try:
        res = subprocess.check_output(["nft", "list", "table", "ip", "filter"])
        return {"rules": res.decode(), "banned_ips": sorted(banned_ips)}
    except Exception as e:
        return {"error": str(e)}


# -----------------------------------------------------------------------
# TRAFFIC PROXY  (catch-all → forward to Squid, the next hop)
# -----------------------------------------------------------------------
@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def proxy_traffic(request: Request, path: str):
    client_ip = request.headers.get("X-Forwarded-For", request.client.host)

    # --- L3/L4 check: is this IP banned? ---
    if client_ip in banned_ips:
        log.warning(f"event=access_denied reason=banned client_ip={client_ip} path=/{path}")
        raise HTTPException(status_code=403, detail="Firewall: IP is banned.")

    log.info(f"event=access_allowed client_ip={client_ip} path=/{path} action=forward_to_squid")

    # --- Forward to next hop (Squid reverse proxy) ---
    try:
        url = f"{NEXT_HOP}/{path}"
        if request.url.query:
            url += f"?{request.url.query}"

        # Preserve original client IP for the rest of the chain
        fwd_headers = {
            "X-Forwarded-For": client_ip,
            "X-Real-IP": client_ip,
        }

        body = await request.body()

        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.request(
                method=request.method,
                url=url,
                headers=fwd_headers,
                content=body,
            )

        # Strip hop-by-hop headers from response
        resp_headers = {
            k: v for k, v in resp.headers.items()
            if k.lower() not in ("transfer-encoding", "connection", "content-encoding", "content-length")
        }
        return Response(content=resp.content, status_code=resp.status_code, headers=resp_headers)

    except httpx.RequestError as e:
        log.error(f"❌ Upstream error (Squid): {e}")
        raise HTTPException(status_code=502, detail="Firewall: next hop unreachable")
