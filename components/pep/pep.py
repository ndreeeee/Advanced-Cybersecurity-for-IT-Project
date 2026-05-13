import os
# pyrefly: ignore [missing-import]
import httpx  # pyrefly: ignore [missing-import]
import psycopg2  # pyrefly: ignore [missing-import]
from fastapi import FastAPI, Request, HTTPException, status  # pyrefly: ignore [missing-import]
from fastapi.responses import JSONResponse  # pyrefly: ignore [missing-import]
from datetime import datetime
import logging
from logging.handlers import SysLogHandler

app = FastAPI(title="PEP - Policy Enforcement Point")

DB_HOST = os.getenv("DB_HOST", "dbms")
DB_USER = os.getenv("DB_USER", "zta_admin")
DB_PASS = os.getenv("DB_PASS", "zta_password")
DB_NAME = os.getenv("DB_NAME", "zta_policy")

TARGET_API = "http://api-server:80"
FIREWALL_URL = "http://firewall:80"
NEXT_HOP = os.getenv("NEXT_HOP", "http://api-server:80")

# Syslog / Splunk Logging
log = logging.getLogger("pep")
log.setLevel(logging.INFO)
formatter = logging.Formatter('component=pep %(message)s')

sh = logging.StreamHandler()
sh.setFormatter(formatter)
log.addHandler(sh)

class SplunkUDPHandler(logging.Handler):
    def __init__(self, host, port):
        super().__init__()
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def emit(self, record):
        try:
            msg = self.format(record)
            # Add current timestamp for Splunk
            full_msg = f"{datetime.now().strftime('%b %d %H:%M:%S')} {msg}"
            self.sock.sendto(full_msg.encode('utf-8'), (self.host, self.port))
        except Exception:
            self.handleError(record)

try:
    import socket
    sysh = SplunkUDPHandler('splunk', 1514)
    sysh.setFormatter(formatter)
    log.addHandler(sysh)
except Exception as e:
    print(f"[PEP] Splunk setup failed: {e}", flush=True)


def get_db_connection():
    """Create a fresh DB connection."""
    return psycopg2.connect(
        host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASS
    )


def get_trust_score(ip_address: str) -> float:
    """Query the DBMS (Policy Store) for the device's trust score."""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT trust_score FROM policies WHERE device_ip = %s", (ip_address,))
        result = cur.fetchone()
        cur.close()
        conn.close()
        if result:
            return float(result[0])
    except Exception as e:
        print(f"[PEP] DB Error (get_trust): {e}", flush=True)
    return 0.0


def log_access(ip: str, endpoint: str, action: str, reason: str):
    """Write every PEP decision to the access_logs table for audit trail."""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO access_logs (device_ip, endpoint, action, reason) VALUES (%s, %s, %s, %s)",
            (ip, endpoint, action, reason),
        )
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print(f"[PEP] DB Error (log_access): {e}", flush=True)
    
    # Also log to Splunk via Syslog
    log.info(f"event=access_decision action={action} client_ip={ip} endpoint=/{endpoint} reason=\"{reason}\"")


async def forward_request(request: Request, path: str):
    """Proxy the allowed request to the protected API Server."""
    async with httpx.AsyncClient() as client:
        url = f"{TARGET_API}/{path}"
        if request.url.query:
            url += f"?{request.url.query}"

        try:
            body = await request.body()
            req = client.build_request(
                request.method, url, content=body
            )
            response = await client.send(req)
            return JSONResponse(content=response.json(), status_code=response.status_code)
        except httpx.RequestError:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="API Server offline",
            )


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def pep_gateway(request: Request, path: str):
    # Use X-Forwarded-For from upstream (firewall/squid) to get the real client IP
    xfwd = request.headers.get("X-Forwarded-For")
    client_ip = xfwd.split(',')[0].strip() if xfwd else request.client.host
    trust = get_trust_score(client_ip)

    print(f"[PEP] Incoming: {client_ip} → /{path} | Trust: {trust}", flush=True)

    # ============ POLICY ENFORCEMENT RULES ============

    # --- RULE 0: Trust = 0 → BAN at network level ---
    if trust <= 0.0:
        log_access(client_ip, path, "DENY", f"Trust={trust} → IP BANNED")
        try:
            async with httpx.AsyncClient() as client:
                await client.post(f"{FIREWALL_URL}/ban?ip={client_ip}")
        except Exception:
            pass
        print(f"[PEP] ⛔ BANNED {client_ip} (trust={trust})", flush=True)
        raise HTTPException(status_code=403, detail="IP Banned — Zero Trust enforcement.")

    # --- RULE 1: /admin/dump requires Trust > 0.90 ---
    if "admin/dump" in path and trust < 0.90:
        log_access(client_ip, path, "DENY", f"Trust={trust} < 0.90 required for admin")
        print(f"[PEP] 🚫 DENY {client_ip} → /{path} (trust {trust} < 0.90)", flush=True)
        raise HTTPException(status_code=403, detail="Trust too low for admin access")

    # --- RULE 2: /transfer requires Trust > 0.70 ---
    if "transfer" in path and trust < 0.70:
        log_access(client_ip, path, "DENY", f"Trust={trust} < 0.70 required for transfer")
        print(f"[PEP] 🚫 DENY {client_ip} → /{path} (trust {trust} < 0.70)", flush=True)
        raise HTTPException(status_code=403, detail="Trust too low for transfers")

    # --- RULE 3: /balance requires Trust > 0.40 ---
    if "balance" in path and trust < 0.40:
        log_access(client_ip, path, "DENY", f"Trust={trust} < 0.40 required for balance")
        print(f"[PEP] 🚫 DENY {client_ip} → /{path} (trust {trust} < 0.40)", flush=True)
        raise HTTPException(status_code=403, detail="Trust too low for balance check")

    # --- ALLOWED → forward to API Server ---
    log_access(client_ip, path, "ALLOW", f"Trust={trust}")
    print(f"[PEP] ✅ ALLOW {client_ip} → /{path} (trust={trust})", flush=True)
    return await forward_request(request, path)
