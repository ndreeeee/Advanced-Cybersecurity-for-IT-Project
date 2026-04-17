import os
import subprocess
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="Firewall Internal API")

@app.post("/ban")
async def ban_ip(ip: str):
    if not ip:
        raise HTTPException(status_code=400, detail="Missing IP")
    
    print(f"[FW] Banning IP from Data-Plane: {ip}")
    try:
        cmd = ["iptables", "-A", "FORWARD", "-s", ip, "-j", "DROP"]
        subprocess.run(cmd, check=True)
        return {"status": "success", "message": f"{ip} has been dropped."}
    except subprocess.CalledProcessError as e:
        print(f"Failed to execute iptables: {e}")
        raise HTTPException(status_code=500, detail="Failed to drop IP")

@app.get("/status")
async def get_status():
    try:
        res = subprocess.check_output(["iptables", "-L", "FORWARD", "-n"])
        return {"rules": res.decode("utf-8")}
    except Exception as e:
        return {"error": str(e)}
