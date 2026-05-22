"""
ZTA 2026 — Trust Score Engine (SIEM client + Policy Store MongoDB)

Workflow (Adv-2026 / workflow.md):
  1. Splunk aggrega log (Fluent Bit → HEC): density / frequenza / deny
  2. Questo servizio interroga Splunk via REST, calcola trust e risk
  3. Scrive su MongoDB (identities, trust_history)
  4. OPA legge contesto SIEM in tempo reale via GET /v1/context (http.send)
"""

from __future__ import annotations

import json
import math
import os
import threading
import time
from datetime import datetime
from typing import Any

import httpx
from fastapi import FastAPI, Query
from pymongo import MongoClient

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
MONGO_URI = os.getenv("MONGO_URI", "mongodb://mongodb-resource:27017/hospital_db")
SPLUNK_HOST = os.getenv("SPLUNK_HOST", "https://splunk-siem:8089")
SPLUNK_USER = os.getenv("SPLUNK_USER", "admin")
SPLUNK_PASS = os.getenv("SPLUNK_PASS", os.getenv("SPLUNK_PASSWORD", "changeme"))
FIREWALL_URL = os.getenv("FIREWALL_URL", "http://nftables-firewall")
POLL_SECONDS = int(os.getenv("TRUST_POLL_SECONDS", "15"))
LAMBDA = float(os.getenv("TRUST_LAMBDA", "0.005"))
Z_THRESHOLD = float(os.getenv("TRUST_Z_THRESHOLD", "2.0"))
RISK_DENY_THRESHOLD = float(os.getenv("TRUST_RISK_DENY_THRESHOLD", "50"))
TRUST_MIN_ACCESS = float(os.getenv("TRUST_MIN_ACCESS", "0.40"))

USER_TO_PRINCIPAL = {
    "alice": "spiffe://zta.hospital/ns/default/sa/client-alice",
    "bob": "spiffe://zta.hospital/ns/default/sa/client-bob",
}

PRINCIPAL_TO_USER = {v: k for k, v in USER_TO_PRINCIPAL.items()}

EVENT_IMPACTS = {
    "deny": -0.08,
    "allow": 0.02,
    "anomaly": -0.12,
    "clean": 0.03,
}

# SPL: density function su log OPA/Envoy indicizzati da Fluent Bit (index main)
QUERY_SIEM_ACTIVITY = """
search index=main earliest=-24h latest=now ("[OPA-PDP]" OR tag=opa.decisions OR tag=envoy.access)
| rex field=_raw "network_ip\\\\\":\\\\s*\\\\\"(?<network_ip>[^\\\\\"]+)\\\\\""
| rex field=_raw "\\\\\"user\\\\\":\\\\s*\\\\\"(?<user>[^\\\\\"]+)\\\\\""
| eval user=coalesce(user, "unknown")
| eval network_ip=coalesce(network_ip, "unknown")
| eval is_deny=if(match(_raw, "Access Denied"), 1, 0)
| eval is_allow=if(match(_raw, "Access Allowed"), 1, 0)
| bucket _time span=1h
| stats
    sum(is_deny) as deny_count,
    sum(is_allow) as allow_count,
    count as hourly_events
  by user, network_ip, _time
| eventstats avg(hourly_events) as mean_rate, stdev(hourly_events) as std_rate by user, network_ip
| eval z_score=if(std_rate>0, (hourly_events-mean_rate)/std_rate, 0)
| stats
    sum(deny_count) as deny_count,
    sum(allow_count) as allow_count,
    sum(hourly_events) as total_events,
    max(z_score) as max_z_score
  by user, network_ip
""".strip()

# Cache in-memory per risposte OPA (aggiornata dal poll Splunk)
_context_cache: dict[str, dict[str, Any]] = {}
_cache_lock = threading.Lock()

app = FastAPI(title="ZTA Trust Engine", version="1.0.0")


# ---------------------------------------------------------------------------
# Math (density / frequenza — come da specifiche corso)
# ---------------------------------------------------------------------------
def attack_probability(count: int, lam: float = LAMBDA) -> float:
    """P(attacco) = 1 - e^(-λ · count)"""
    return 1.0 - math.exp(-lam * max(0, count))


def risk_score_from_metrics(total_events: int, deny_count: int, max_z: float) -> float:
    """Rischio 0-100 per OPA (workflow: Splunk → statistiche → soglia < 50)."""
    p = attack_probability(total_events)
    base = min(100.0, p * 100.0)
    deny_boost = min(30.0, deny_count * 5.0)
    z_boost = min(25.0, max(0.0, (max_z - Z_THRESHOLD) * 10.0)) if max_z > Z_THRESHOLD else 0.0
    return min(100.0, base + deny_boost + z_boost)


def compute_trust_delta(metrics: dict[str, Any]) -> tuple[float, str]:
    """Delta trust da metriche SIEM."""
    deny = int(metrics.get("deny_count", 0))
    allow = int(metrics.get("allow_count", 0))
    max_z = float(metrics.get("max_z_score", 0))
    total = int(metrics.get("total_events", 0))

    delta = 0.0
    reasons: list[str] = []

    if deny > 0:
        delta += EVENT_IMPACTS["deny"] * deny
        reasons.append(f"deny×{deny}")
    if allow > 0:
        delta += EVENT_IMPACTS["allow"] * min(allow, 20)
        reasons.append(f"allow×{allow}")
    if max_z > Z_THRESHOLD:
        delta += EVENT_IMPACTS["anomaly"] * min(max_z / Z_THRESHOLD, 3.0)
        reasons.append(f"z={max_z:.2f}")
    if deny == 0 and total <= 2:
        delta += EVENT_IMPACTS["clean"]
        reasons.append("clean_session")

    return delta, " | ".join(reasons) if reasons else "no_events"


# ---------------------------------------------------------------------------
# MongoDB
# ---------------------------------------------------------------------------
def get_mongo():
    return MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)


def _mongo_db():
    client = get_mongo()
    return client, client.hospital_db


def load_identities() -> list[dict[str, Any]]:
    client, db = _mongo_db()
    try:
        return list(db.identities.find())
    finally:
        client.close()


def update_identity(
    principal: str,
    new_trust: float,
    reason: str,
    network_ip: str = "",
    metrics: dict[str, Any] | None = None,
) -> None:
    client, db = _mongo_db()
    try:
        old = db.identities.find_one({"principal": principal})
        if not old:
            return
        old_score = float(old.get("trust_score", 0.5))
        if abs(new_trust - old_score) < 0.001:
            return

        db.identities.update_one(
            {"principal": principal},
            {
                "$set": {
                    "trust_score": round(new_trust, 4),
                    "last_network_ip": network_ip or old.get("last_network_ip", ""),
                    "updated_at": datetime.utcnow(),
                    "last_siem_metrics": metrics or {},
                }
            },
        )
        db.trust_history.insert_one(
            {
                "principal": principal,
                "device_name": old.get("device_name"),
                "old_score": round(old_score, 4),
                "new_score": round(new_trust, 4),
                "reason": reason,
                "timestamp": datetime.utcnow(),
            }
        )
        print(
            f"[TRUST-ENGINE] {principal}: {old_score:.4f} → {new_trust:.4f} | {reason}",
            flush=True,
        )
    finally:
        client.close()


def ban_ip_if_needed(principal: str, trust: float, network_ip: str) -> None:
    if trust > 0.05 or not network_ip or network_ip in ("unknown", "0.0.0.0"):
        return
    try:
        httpx.post(f"{FIREWALL_URL}/ban", params={"ip": network_ip}, timeout=5.0)
        print(f"[TRUST-ENGINE] Firewall ban requested for {network_ip} ({principal})", flush=True)
    except Exception as e:
        print(f"[TRUST-ENGINE] Firewall ban failed: {e}", flush=True)


# ---------------------------------------------------------------------------
# Splunk REST
# ---------------------------------------------------------------------------
def splunk_login() -> str | None:
    try:
        r = httpx.post(
            f"{SPLUNK_HOST}/services/auth/login",
            data={"username": SPLUNK_USER, "password": SPLUNK_PASS, "output_mode": "json"},
            verify=False,
            timeout=20.0,
        )
        r.raise_for_status()
        try:
            return r.json().get("sessionKey")
        except Exception:
            text = r.text
            if "<sessionKey>" in text:
                return text.split("<sessionKey>")[1].split("</sessionKey>")[0]
    except Exception as e:
        print(f"[TRUST-ENGINE] Splunk auth error: {e}", flush=True)
    return None


def splunk_search(session_key: str, query: str) -> list[dict[str, Any]] | None:
    headers = {"Authorization": f"Splunk {session_key}"}
    try:
        job = httpx.post(
            f"{SPLUNK_HOST}/services/search/jobs",
            headers=headers,
            data={"search": query, "output_mode": "json"},
            verify=False,
            timeout=20.0,
        )
        if job.status_code == 401:
            return None
        if job.status_code != 201:
            print(f"[TRUST-ENGINE] Splunk job error: {job.status_code}", flush=True)
            return []
        sid = job.json().get("sid")
        for _ in range(45):
            st = httpx.get(
                f"{SPLUNK_HOST}/services/search/jobs/{sid}?output_mode=json",
                headers=headers,
                verify=False,
                timeout=15.0,
            )
            state = st.json().get("entry", [{}])[0].get("content", {}).get("dispatchState", "")
            if state in ("DONE", "FAILED"):
                break
            time.sleep(1)
        res = httpx.get(
            f"{SPLUNK_HOST}/services/search/jobs/{sid}/results?output_mode=json&count=0",
            headers=headers,
            verify=False,
            timeout=20.0,
        )
        return res.json().get("results", [])
    except Exception as e:
        print(f"[TRUST-ENGINE] Splunk search error: {e}", flush=True)
        return []


def metrics_key(user: str, network_ip: str) -> str:
    principal = USER_TO_PRINCIPAL.get(user)
    if principal:
        return principal
    return f"ip:{network_ip}"


def build_context_for_principal(doc: dict[str, Any], metrics: dict[str, Any] | None) -> dict[str, Any]:
    trust = float(doc.get("trust_score", 0.5))
    m = metrics or doc.get("last_siem_metrics") or {}
    total = int(float(m.get("total_events", 0)))
    deny = int(float(m.get("deny_count", 0)))
    max_z = float(m.get("max_z_score", 0))
    risk = risk_score_from_metrics(total, deny, max_z)
    return {
        "principal": doc["principal"],
        "device_name": doc.get("device_name"),
        "last_network_ip": doc.get("last_network_ip", m.get("network_ip", "")),
        "trust_score": round(trust, 4),
        "trust_baseline": float(doc.get("trust_baseline", trust)),
        "risk_score": round(risk, 2),
        "deny_count": deny,
        "allow_count": int(float(m.get("allow_count", 0))),
        "total_events": total,
        "max_z_score": round(max_z, 3),
        "attack_probability": round(attack_probability(total), 4),
        "trust_min_required": TRUST_MIN_ACCESS,
        "risk_max_allowed": RISK_DENY_THRESHOLD,
        "updated_at": doc.get("updated_at", datetime.utcnow()).isoformat(),
    }


# ---------------------------------------------------------------------------
# Poll loop
# ---------------------------------------------------------------------------
def poll_splunk_and_update() -> None:
    global _context_cache
    session = splunk_login()
    if not session:
        return

    rows = splunk_search(session, QUERY_SIEM_ACTIVITY)
    if rows is None:
        return

    metrics_by_principal: dict[str, dict[str, Any]] = {}
    for row in rows or []:
        user = (row.get("user") or "unknown").strip()
        ip = (row.get("network_ip") or "unknown").strip()
        key = metrics_key(user, ip)
        metrics_by_principal[key] = {
            "user": user,
            "network_ip": ip,
            "deny_count": int(float(row.get("deny_count", 0))),
            "allow_count": int(float(row.get("allow_count", 0))),
            "total_events": int(float(row.get("total_events", 0))),
            "max_z_score": float(row.get("max_z_score", 0)),
        }

    identities = load_identities()
    new_cache: dict[str, dict[str, Any]] = {}

    for doc in identities:
        principal = doc["principal"]
        user = PRINCIPAL_TO_USER.get(principal, "")
        metrics = None
        for key, m in metrics_by_principal.items():
            if key == principal or (user and m.get("user") == user):
                metrics = m
                break
        if metrics is None:
            metrics = {
                "deny_count": 0,
                "allow_count": 0,
                "total_events": 0,
                "max_z_score": 0,
                "network_ip": doc.get("last_network_ip", ""),
                "user": user,
            }

        baseline = float(doc.get("trust_baseline", 0.5))
        current = float(doc.get("trust_score", baseline))
        delta, reason = compute_trust_delta(metrics)
        new_trust = max(0.0, min(1.0, baseline + delta))
        ip = metrics.get("network_ip", "")

        update_identity(principal, new_trust, f"SIEM: {reason}", ip, metrics)
        ban_ip_if_needed(principal, new_trust, ip)
        doc = {**doc, "trust_score": new_trust, "last_siem_metrics": metrics}
        new_cache[principal] = build_context_for_principal(doc, metrics)
        if ip and ip not in ("unknown", ""):
            new_cache[f"ip:{ip}"] = new_cache[principal]

    with _cache_lock:
        _context_cache = new_cache

    print(f"[TRUST-ENGINE] SIEM poll OK — {len(rows or [])} righe, {len(new_cache)} contesti", flush=True)


def background_poller() -> None:
    print("[TRUST-ENGINE] Background Splunk poller avviato", flush=True)
    while True:
        try:
            poll_splunk_and_update()
        except Exception as e:
            print(f"[TRUST-ENGINE] Poll error: {e}", flush=True)
        time.sleep(POLL_SECONDS)


# ---------------------------------------------------------------------------
# API per OPA (http.send)
# ---------------------------------------------------------------------------
@app.get("/health")
def health():
    return {"status": "ok", "service": "trust-engine"}


@app.get("/v1/context")
def get_context(
    principal: str | None = Query(None),
    network_ip: str | None = Query(None),
    user: str | None = Query(None),
    ja3: str | None = Query(None),
):
    """
    Contesto SIEM + trust per decisione OPA (workflow Fase 3).
    OPA chiama questo endpoint; i dati provengono dall'ultimo poll Splunk.
    """
    _ = ja3  # riservato per estensioni future (correlazione JA3 in SPL)
    with _cache_lock:
        cache = dict(_context_cache)

    if principal and principal in cache:
        return cache[principal]

    if user:
        p = USER_TO_PRINCIPAL.get(user)
        if p and p in cache:
            return cache[p]

    if network_ip:
        if f"ip:{network_ip}" in cache:
            return cache[f"ip:{network_ip}"]
        for ctx in cache.values():
            if isinstance(ctx, dict) and ctx.get("last_network_ip") == network_ip:
                return ctx

    # Fallback: leggi Mongo senza metriche SIEM fresche
    try:
        client, db = _mongo_db()
        try:
            query: dict[str, Any] = {}
            if principal:
                query = {"principal": principal}
            elif user:
                query = {"device_name": user}
            doc = db.identities.find_one(query) if query else None
            if doc:
                return build_context_for_principal(doc, doc.get("last_siem_metrics"))
        finally:
            client.close()
    except Exception:
        pass

    # Fail-safe Zero Trust
    return {
        "principal": principal or "",
        "trust_score": 0.0,
        "risk_score": 100.0,
        "deny_count": 0,
        "total_events": 0,
        "max_z_score": 0,
        "attack_probability": 1.0,
        "trust_min_required": TRUST_MIN_ACCESS,
        "risk_max_allowed": RISK_DENY_THRESHOLD,
        "note": "fail_safe_no_data",
    }


def seed_cache_from_mongo() -> None:
    """Contesto immediato per OPA prima del primo poll Splunk."""
    global _context_cache
    try:
        new_cache: dict[str, dict[str, Any]] = {}
        for doc in load_identities():
            ctx = build_context_for_principal(doc, doc.get("last_siem_metrics"))
            new_cache[doc["principal"]] = ctx
            ip = doc.get("last_network_ip") or ""
            if ip and ip not in ("unknown", ""):
                new_cache[f"ip:{ip}"] = ctx
        with _cache_lock:
            _context_cache = new_cache
        print(f"[TRUST-ENGINE] Cache Mongo seed: {len(new_cache)} contesti", flush=True)
    except Exception as e:
        print(f"[TRUST-ENGINE] Mongo seed failed: {e}", flush=True)


@app.on_event("startup")
def startup():
    seed_cache_from_mongo()
    threading.Thread(target=background_poller, daemon=True).start()
    threading.Timer(30.0, poll_splunk_and_update).start()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8182)
