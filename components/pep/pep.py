import os
import httpx
import psycopg2
from fastapi import FastAPI, Request, HTTPException, status
from fastapi.responses import JSONResponse

app = FastAPI(title="PEP - Policy Enforcement Point")

DB_HOST = os.getenv("DB_HOST", "dbms")
DB_USER = os.getenv("DB_USER", "zta_admin")
DB_PASS = os.getenv("DB_PASS", "zta_password")
DB_NAME = os.getenv("DB_NAME", "zta_policy")

TARGET_API = "http://api-server:80"

def get_trust_score(ip_address: str):
    """Interroga il DB per ottenere il trust score dell'IP sorgente."""
    try:
        conn = psycopg2.connect(
            host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASS
        )
        cur = conn.cursor()
        cur.execute("SELECT trust_score FROM policies WHERE device_ip = %s", (ip_address,))
        result = cur.fetchone()
        cur.close()
        conn.close()
        if result:
            return float(result[0])
    except Exception as e:
        print(f"DB Error: {e}")
    return 0.0

async def forward_request(request: Request, path: str):
    async with httpx.AsyncClient() as client:
        url = f"{TARGET_API}/{path}"
        if request.url.query:
            url += f"?{request.url.query}"
            
        try:
            req = client.build_request(
                request.method, url, headers=request.headers.raw, content=await request.body()
            )
            response = await client.send(req)
            return JSONResponse(content=response.json(), status_code=response.status_code)
        except httpx.RequestError:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="API Server offline")

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def pep_gateway(request: Request, path: str):
    client_ip = request.client.host
    trust = get_trust_score(client_ip)
    
    print(f"[PEP] Incoming req from {client_ip} to /{path} | Trust: {trust}")

    # POLICY ENFORCEMENT RULES
    if trust <= 0.0:
        try:
            async with httpx.AsyncClient() as client:
                await client.post(f"http://firewall:8081/ban?ip={client_ip}")
        except Exception:
            pass
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="IP Banned.")

    if path == "api/v1/admin/dump" and trust < 0.90:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Trust too low")
        
    if path == "api/v1/transfer" and trust < 0.70:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Trust too low")
        
    if path == "api/v1/balance" and trust < 0.40:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Trust too low")

    return await forward_request(request, path)
