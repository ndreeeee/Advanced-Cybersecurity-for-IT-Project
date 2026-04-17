from fastapi import FastAPI, Request
from datetime import datetime

app = FastAPI(title="Core Banking API")

@app.get("/api/v1/balance")
async def get_balance(request: Request):
    client_ip = request.client.host
    return {
        "status": "success",
        "message": f"Welcome! Identity verified from IP {client_ip}.",
        "balance": "€ 15,340.00",
        "timestamp": datetime.now().isoformat()
    }

@app.post("/api/v1/transfer")
async def do_transfer(request: Request):
    client_ip = request.client.host
    return {
        "status": "success",
        "message": "Transfer of € 500 completed successfully.",
        "transaction_id": "TRX-998827",
        "timestamp": datetime.now().isoformat()
    }

@app.get("/api/v1/admin/dump")
async def admin_dump(request: Request):
    return {
        "status": "success",
        "data": [
            {"client": "Mario Rossi", "account": "IT99..."},
            {"client": "Luigi Verdi", "account": "IT98..."}
        ]
    }
