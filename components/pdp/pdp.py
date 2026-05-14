import os
import time
import math
import json
import httpx
import psycopg2
from datetime import datetime

# =======================================================================
# CONFIGURAZIONI
# =======================================================================
DB_HOST = os.getenv("DB_HOST", "dbms")
DB_USER = os.getenv("DB_USER", "zta_admin")
DB_PASS = os.getenv("DB_PASS", "zta_password")
DB_NAME = os.getenv("DB_NAME", "zta_policy")

SPLUNK_HOST = "https://splunk:8089"
SPLUNK_USER = "admin"
SPLUNK_PASS = os.getenv("SPLUNK_PASS", "changeme")

# =======================================================================
# CONFIGURAZIONE TRUST SCORE
# -----------------------------------------------------------------------
# Formula ispirata a NIST SP 800-207 e al modello di SbattellaMattia:
#
#   TS(u) = TS_0 + Σ [ I_i × W(t_i) ]
#
# dove:
#   TS_0       = baseline iniziale del device (dal DB)
#   I_i        = impatto dell'evento i-esimo (bonus o malus)
#   W(t_i)     = e^(-t_i / T)  — peso con decadimento esponenziale
#   t_i        = minuti trascorsi dall'evento
#   T          = costante di scala temporale (in minuti)
#
# Lo score finale viene clippato a [0.0, 1.0].
#
# La probabilità d'attacco basata sulla frequenza è calcolata come:
#   P(attacco) = 1 - e^(-λ × count)
# dove λ è il parametro di sensibilità e count sono le occorrenze.
# =======================================================================

SCORING_CONFIG = {
    # --- Parametri decadimento temporale ---
    "T_SCALE_MINUTES": 1440,          # 1 giorno: dopo 1g un evento pesa ~37% del suo valore

    # --- Parametro sensibilità per probabilità d'attacco ---
    "LAMBDA": 0.005,                  # Sensibilità: più alto = più aggressivo

    # --- Mapping evento → impatto (sulla scala 0.0-1.0) ---
    "EVENT_IMPACTS": {
        # Eventi negativi (malus) — rilevati da Splunk/SIEM
        "honeypot_match":       -0.15,   # IP trovato nel dataset honeypot (correlazione threat intel)
        "pep_deny":             -0.05,   # Accesso negato dal PEP (tentativo su risorsa non autorizzata)
        "squid_blocked":        -0.08,   # Navigazione su dominio malevolo bloccata da Squid
        "snort_alert":          -0.12,   # Alert IDS (SQL injection, pattern malevolo)
        "snort_sqli":           -0.20,   # SQL injection rilevata (Snort sid:1000001)
        "snort_admin_probe":    -0.10,   # Tentativo accesso admin dump (Snort sid:1000002)

        # Eventi positivi (bonus) — comportamento legittimo
        "pep_allow":            +0.02,   # Accesso legittimo riuscito
        "clean_session":        +0.03,   # Sessione senza anomalie (reward per buon comportamento)
    },

    # --- Baseline di default per device non in DB ---
    "DEFAULT_BASELINE": 0.50,

    # --- Soglia z-score per anomalia statistica (density function) ---
    "ANOMALY_Z_THRESHOLD": 2.0,

    # --- Finestra temporale per query Splunk ---
    "EARLIEST": "-24h",
    "LATEST":   "now",
}

print("=" * 70, flush=True)
print("[PDP] Policy Decision Point — Trust Score Engine v2.0", flush=True)
print("[PDP] Formula: TS = baseline + Σ(impact × e^(-t/T))", flush=True)
print(f"[PDP] T_SCALE = {SCORING_CONFIG['T_SCALE_MINUTES']} min | λ = {SCORING_CONFIG['LAMBDA']}", flush=True)
print("=" * 70, flush=True)

# =======================================================================
# FUNZIONI MATEMATICHE — TRUST SCORE
# =======================================================================

def exponential_decay_weight(minutes_ago, T=None):
    """
    Calcola il peso con decadimento esponenziale W(t) = e^(-t/T).
    Eventi recenti → W ≈ 1.0, eventi vecchi → W → 0.0
    """
    if T is None:
        T = SCORING_CONFIG["T_SCALE_MINUTES"]
    if T <= 0:
        return 1.0
    return math.exp(-minutes_ago / T)


def attack_probability(event_count, lam=None):
    """
    Calcola la probabilità d'attacco basata sulla frequenza:
    P(attacco) = 1 - e^(-λ × count)

    Questa è la density function richiesta dal prof:
    - 3 eventi → P ≈ 0.015 (probabilità bassa, rischio contenuto)
    - 50 eventi → P ≈ 0.22 (probabilità media)
    - 500 eventi → P ≈ 0.92 (quasi certo che sia un attacco)
    """
    if lam is None:
        lam = SCORING_CONFIG["LAMBDA"]
    return 1.0 - math.exp(-lam * event_count)


def calculate_new_trust(baseline, events):
    """
    Calcola il nuovo Trust Score con la formula completa:
    TS = baseline + Σ(impact_i × W(t_i))

    Args:
        baseline: trust score iniziale del device (da DB)
        events:   lista di dict con chiavi 'impact' e 'minutes_ago'

    Returns:
        float clippato a [0.0, 1.0]
    """
    weighted_sum = 0.0
    for event in events:
        impact = event["impact"]
        minutes_ago = event.get("minutes_ago", 0)
        weight = exponential_decay_weight(minutes_ago)
        weighted_sum += impact * weight

    new_score = baseline + weighted_sum
    return max(0.0, min(1.0, new_score))


# =======================================================================
# FUNZIONI SPLUNK
# =======================================================================

def get_splunk_session_key():
    """Autenticazione alle API REST di Splunk per ottenere la SessionKey."""
    try:
        response = httpx.post(
            f"{SPLUNK_HOST}/services/auth/login",
            data={'username': SPLUNK_USER, 'password': SPLUNK_PASS, 'output_mode': 'json'},
            verify=False,
            timeout=15.0
        )
        response.raise_for_status()
        text = response.text

        # JSON parsing (versioni recenti Splunk)
        try:
            data = json.loads(text)
            if "sessionKey" in data:
                print("[PDP] ✅ Authenticated to Splunk (JSON). SessionKey ACQUIRED.", flush=True)
                return data["sessionKey"]
        except (json.JSONDecodeError, TypeError):
            pass

        # XML fallback (versioni precedenti)
        if "<sessionKey>" in text:
            key = text.split("<sessionKey>")[1].split("</sessionKey>")[0]
            print("[PDP] ✅ Authenticated to Splunk (XML). SessionKey ACQUIRED.", flush=True)
            return key

        print(f"[PDP] WARNING: Auth OK but no sessionKey found. Response: {text[:200]}", flush=True)
        return None
    except Exception as e:
        print(f"[PDP] Splunk Auth Error: {e}. Splunk is probably still booting...", flush=True)
        return None


def run_splunk_search(session_key, query):
    """
    Esegue una ricerca Splunk tramite REST API:
    1. Crea un Job
    2. Polling fino a completamento
    3. Scarica risultati JSON
    Ritorna None se la session key è scaduta (per rinnovo).
    """
    headers = {"Authorization": f"Splunk {session_key}"}

    try:
        # 1. CREA JOB
        job_res = httpx.post(
            f"{SPLUNK_HOST}/services/search/jobs",
            headers=headers,
            data={"search": query, "output_mode": "json"},
            verify=False,
            timeout=15.0
        )
        if job_res.status_code == 401:
            print("[PDP] SessionKey expired. Resetting...", flush=True)
            return None
        if job_res.status_code != 201:
            print(f"[PDP] Errore creazione Job: {job_res.status_code}", flush=True)
            return []

        sid = job_res.json().get("sid")

        # 2. POLLING STATUS
        for _ in range(30):  # Max 30 secondi di attesa
            status_res = httpx.get(
                f"{SPLUNK_HOST}/services/search/jobs/{sid}?output_mode=json",
                headers=headers, verify=False, timeout=15.0
            )
            state = status_res.json().get("entry", [{}])[0].get("content", {}).get("dispatchState", "")
            if state in ("DONE", "FAILED"):
                break
            time.sleep(1)

        # 3. SCARICA RISULTATI
        results_res = httpx.get(
            f"{SPLUNK_HOST}/services/search/jobs/{sid}/results?output_mode=json&count=0",
            headers=headers, verify=False, timeout=15.0
        )
        data = results_res.json()
        return data.get("results", [])

    except Exception as e:
        print(f"[PDP] Splunk search error: {e}", flush=True)
        return []


# =======================================================================
# QUERY SPLUNK — DENSITY FUNCTION + FREQUENZA ATTACCHI
# -----------------------------------------------------------------------
# Usa la Density Function di Splunk (eventstats + stdev + z-score)
# per analizzare statisticamente la distribuzione degli attacchi e
# identificare i device con comportamento anomalo.
# =======================================================================

QUERY_HONEYPOT_DENSITY = """search index=* (source="honeypot.csv" OR source="merged.csv") srcstr="172.20.*"
| bucket _time span=1h
| stats count as hourly_attacks by srcstr, _time
| eventstats avg(hourly_attacks) as mean_rate, stdev(hourly_attacks) as std_rate by srcstr
| eval z_score = if(std_rate > 0, (hourly_attacks - mean_rate) / std_rate, 0)
| eval is_anomalous = if(z_score > {z_threshold}, 1, 0)
| stats
    sum(hourly_attacks) as total_attacks,
    max(z_score) as max_z_score,
    sum(is_anomalous) as anomalous_hours,
    avg(hourly_attacks) as avg_hourly_rate
  by srcstr""".format(z_threshold=SCORING_CONFIG["ANOMALY_Z_THRESHOLD"])

# Query semplice per conteggio totale (fallback se la density è troppo pesante)
QUERY_HONEYPOT_COUNT = """search index=* (source="honeypot.csv" OR source="merged.csv") srcstr="172.20.*"
| stats count as total_attacks by srcstr
| where total_attacks > 5"""

# Query per eventi PEP (deny/allow dai syslog)
QUERY_PEP_EVENTS = """search index=* sourcetype="syslog" component=pep event=access_decision
| stats
    count(eval(action="DENY")) as deny_count,
    count(eval(action="ALLOW")) as allow_count
  by client_ip"""


# =======================================================================
# FUNZIONI DATABASE
# =======================================================================

def get_db_connection():
    """Crea una connessione fresca al DB."""
    return psycopg2.connect(host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASS)


def get_all_devices():
    """Recupera tutti i device dal Policy Store con il loro trust score attuale."""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT device_ip, device_name, trust_score FROM policies")
        devices = cur.fetchall()
        cur.close()
        conn.close()
        return [(row[0], row[1], float(row[2])) for row in devices]
    except Exception as e:
        print(f"[PDP] DB Error (get_all_devices): {e}", flush=True)
        return []


def update_trust_with_history(ip_address, old_score, new_score, reason):
    """
    Aggiorna il trust score nel Policy Store e registra la variazione
    nella tabella trust_history per audit trail.
    """
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # Aggiorna solo se lo score è effettivamente cambiato
        if abs(new_score - old_score) < 0.001:
            cur.close()
            conn.close()
            return

        cur.execute(
            "UPDATE policies SET trust_score = %s, updated_at = NOW() WHERE device_ip = %s",
            (round(new_score, 4), ip_address)
        )

        # Registra nella trust_history
        cur.execute(
            "INSERT INTO trust_history (device_ip, old_score, new_score, reason) VALUES (%s, %s, %s, %s)",
            (ip_address, round(old_score, 4), round(new_score, 4), reason)
        )

        conn.commit()
        cur.close()
        conn.close()

        # Log con emoji per leggibilità nei docker logs
        direction = "📉" if new_score < old_score else "📈"
        print(
            f"[PDP-ACTION] {direction} Trust Update: {ip_address} | "
            f"{old_score:.4f} → {new_score:.4f} | Reason: {reason}",
            flush=True
        )

    except Exception as e:
        print(f"[PDP] DB Error (update_trust): {e}", flush=True)


# =======================================================================
# MOTORE PRINCIPALE — ANALISI E CALCOLO TRUST SCORE
# =======================================================================

def analyze_and_update_trust(session_key):
    """
    Ciclo principale del PDP Trust Score Engine:
    1. Recupera tutti i device dal DB
    2. Interroga Splunk con density function per threat intelligence
    3. Interroga Splunk per eventi PEP (deny/allow)
    4. Per ogni device, accumula gli eventi e ricalcola il trust score
    5. Aggiorna il DB con il nuovo score

    Returns None se la session key è scaduta (per rinnovo).
    """

    # --- 1. Recupera device ---
    devices = get_all_devices()
    if not devices:
        print("[PDP] Nessun device in DB.", flush=True)
        return True

    # --- 2. Query Splunk: Honeypot Density Function ---
    print("[PDP] 📊 Executing Splunk Density Function query...", flush=True)
    honeypot_results = run_splunk_search(session_key, QUERY_HONEYPOT_DENSITY)
    if honeypot_results is None:
        return None  # Session expired

    # Fallback a query semplice se la density non produce risultati
    if not honeypot_results:
        print("[PDP] Density query empty, trying simple count query...", flush=True)
        honeypot_results = run_splunk_search(session_key, QUERY_HONEYPOT_COUNT)
        if honeypot_results is None:
            return None

    # Indicizza i risultati per IP
    threat_intel = {}
    for row in (honeypot_results or []):
        ip = row.get("srcstr", "")
        if ip and "172.20" in ip:
            threat_intel[ip] = {
                "total_attacks": int(float(row.get("total_attacks", 0))),
                "max_z_score": float(row.get("max_z_score", 0)),
                "anomalous_hours": int(float(row.get("anomalous_hours", 0))),
                "avg_hourly_rate": float(row.get("avg_hourly_rate", 0)),
            }

    if threat_intel:
        print(f"[PDP] 🔍 Threat Intel from Splunk Density: {json.dumps(threat_intel, indent=2)}", flush=True)

    # --- 3. Query Splunk: PEP Events ---
    pep_results = run_splunk_search(session_key, QUERY_PEP_EVENTS)
    if pep_results is None:
        return None

    pep_events = {}
    for row in (pep_results or []):
        ip = row.get("client_ip", "")
        if ip:
            pep_events[ip] = {
                "deny_count": int(float(row.get("deny_count", 0))),
                "allow_count": int(float(row.get("allow_count", 0))),
            }

    # --- 4. Per ogni device, calcola il nuovo Trust Score ---
    for device_ip, device_name, current_trust in devices:
        events = []
        reasons = []

        # ---- SORGENTE 1: Honeypot/Threat Intelligence (con density function) ----
        if device_ip in threat_intel:
            ti = threat_intel[device_ip]
            count = ti["total_attacks"]
            z = ti["max_z_score"]

            # Calcolo probabilità d'attacco con formula esponenziale:
            # P(attacco) = 1 - e^(-λ × count)
            prob = attack_probability(count)

            # L'impatto base viene scalato dalla probabilità
            # Se P alta → impatto pieno, se P bassa → impatto ridotto
            base_impact = SCORING_CONFIG["EVENT_IMPACTS"]["honeypot_match"]
            scaled_impact = base_impact * prob

            # BONUS: se il z-score indica anomalia statistica, rinforza la penalità
            # (questo è il contributo della Density Function di Splunk)
            if z > SCORING_CONFIG["ANOMALY_Z_THRESHOLD"]:
                anomaly_multiplier = min(z / SCORING_CONFIG["ANOMALY_Z_THRESHOLD"], 3.0)  # Cap a 3x
                scaled_impact *= anomaly_multiplier
                reasons.append(
                    f"ANOMALY z={z:.2f} (>{SCORING_CONFIG['ANOMALY_Z_THRESHOLD']}), "
                    f"multiplier={anomaly_multiplier:.2f}"
                )

            events.append({"impact": scaled_impact, "minutes_ago": 0})
            reasons.append(
                f"Honeypot: {count} attacks, P(attack)={prob:.4f}, "
                f"impact={scaled_impact:.4f}"
            )

        # ---- SORGENTE 2: Decisioni PEP (DENY = malus, ALLOW = bonus) ----
        if device_ip in pep_events:
            pe = pep_events[device_ip]

            if pe["deny_count"] > 0:
                deny_impact = SCORING_CONFIG["EVENT_IMPACTS"]["pep_deny"] * pe["deny_count"]
                events.append({"impact": deny_impact, "minutes_ago": 5})
                reasons.append(f"PEP DENY ×{pe['deny_count']}")

            if pe["allow_count"] > 0:
                # Bonus per accessi legittimi (decadimento più rapido, peso minore)
                allow_impact = SCORING_CONFIG["EVENT_IMPACTS"]["pep_allow"] * min(pe["allow_count"], 20)
                events.append({"impact": allow_impact, "minutes_ago": 10})
                reasons.append(f"PEP ALLOW ×{pe['allow_count']} (max 20)")

        # ---- SORGENTE 3: Clean session bonus ----
        # Se un device non ha NESSUN evento negativo, riceve un piccolo bonus
        # (reward per buon comportamento — il sistema "perdona" col tempo)
        if device_ip not in threat_intel and (device_ip not in pep_events or pep_events[device_ip]["deny_count"] == 0):
            events.append({
                "impact": SCORING_CONFIG["EVENT_IMPACTS"]["clean_session"],
                "minutes_ago": 0
            })
            reasons.append("Clean session bonus")

        # ---- CALCOLO FINALE ----
        if events:
            # Recupera la baseline originale dal DB (il trust iniziale)
            baseline = get_device_baseline(device_ip)
            new_trust = calculate_new_trust(baseline, events)

            # Log dettagliato
            reason_str = " | ".join(reasons)

            if abs(new_trust - current_trust) >= 0.001:
                update_trust_with_history(device_ip, current_trust, new_trust, reason_str)

    return True


def get_device_baseline(device_ip):
    """
    Recupera la baseline originale del device.
    La baseline è il trust score di partenza (quello iniziale in init.sql).
    Usiamo i valori noti hardcoded per la demo, ma in produzione
    verrebbero da una tabella separata.
    """
    BASELINES = {
        "172.20.0.10": 0.85,   # Alice — employee fidato
        "172.20.0.11": 0.50,   # Kiosk — device a basso privilegio
        "172.20.0.12": 0.80,   # Bob — employee (potenzialmente compromesso)
    }
    return BASELINES.get(device_ip, SCORING_CONFIG["DEFAULT_BASELINE"])


# =======================================================================
# DAEMON LOOP
# =======================================================================
session_key = None

print("[PDP] Avvio daemon loop. Polling ogni 15 secondi...", flush=True)

while True:
    time.sleep(15)

    # Acquisizione o rinnovo session key
    if not session_key:
        session_key = get_splunk_session_key()
        if not session_key:
            continue

    timestamp = datetime.now().strftime('%H:%M:%S')
    print(f"\n[{timestamp}] [PDP] ═══ Trust Score Engine Cycle ═══", flush=True)

    result = analyze_and_update_trust(session_key)
    if result is None:
        # Session key scaduta → rinnova al prossimo ciclo
        session_key = None
        continue

    print(f"[{timestamp}] [PDP] ═══ Cycle Complete ═══\n", flush=True)
