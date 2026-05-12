# 📋 Riferimento Completo — Progetto Zero Trust Architecture 2025

> Documento generato dall'analisi del PDF **Adv-2025-Projects.pdf** e di **tutto il codice** presente nel repo.
> Ultima revisione: 12 Maggio 2025

---

## 1. Cosa chiede ESATTAMENTE il PDF del Prof. Spalazzi

Il PDF è composto da 9 slide. Ecco il contenuto distillato, senza inventare nulla:

### Requisiti obbligatori

| Requisito | Dettaglio dal PDF |
|---|---|
| **Tema** | Zero Trust Architecture |
| **Gruppo** | 4-5 persone |
| **Tool obbligatori** | **Splunk**, **IPTables**, **Squid**, **Snort** |
| **DBMS** | A scelta (voi avete scelto PostgreSQL 16) |
| **Da sviluppare** | **PDP** (Policy Decision Point) e **PEP** (Policy Enforcement Point) |

### Struttura richiesta (Slide 3)

L'architettura ZTA si divide in:
- **Control Plane** → dove risiedono le decisioni (PDP, SIEM/Splunk, DBMS)
- **Data Plane** → dove passa il traffico reale (Client → Firewall → Proxy → IDS → PEP → Risorsa)

### I due Use Case richiesti (Slide 4-6)

#### Use Case 1: Richiesta di accesso alla risorsa
Il flusso che **deve essere accettato dal PEP**:
```
Client → IPTables → Squid → Snort → PEP → [query al DBMS] → Risorsa (se la policy lo permette)
```

#### Use Case 2: Qualsiasi altro tipo di richiesta
Serve per **raccogliere log** che integrano lo storico analizzato dal PDP:
```
Qualsiasi traffico → IPTables/Squid/Snort generano log → Log arrivano a Splunk
→ PDP interroga Splunk via API → PDP aggiorna policy nel DBMS
```

### Tips & Tricks dal Prof (Slide 7) — parola per parola

1. **IPTables e Squid** possono identificare il **device `d`** basandosi su **IP** e (solo nella stessa subnet) su **MAC address**
2. Quando il traffico è **routato tra reti diverse**, i **MAC address cambiano** → non fidarsi del MAC cross-subnet
3. **Squid** può identificare il device `d` basandosi su **hostname**
4. **IPTables e Squid** possono identificare la **rete `n`** basandosi su **network ranges**
5. **Squid** può identificare la rete `n` basandosi su **top/second-level domains e subdomain**
6. **PEP è un DBMS Client** → il PEP usa le API del DBMS (query SQL)
7. **PDP è un SIEM Client** → il PDP usa le API di Splunk (REST API)

### Draft Plan dal Prof (Slide 8)

1. Define policies
2. Install tools
3. Develop PDP and PEP
4. Test

---

## 2. Risposta alla domanda: "Bob è nel dataset?"

**SÌ, Bob (`172.20.0.12`) è stato iniettato nel dataset.**

Ecco come funziona la catena:

1. **`honeypot.csv`** (48.8 MB, ~451K righe) → è il dataset originale AWS Honeypot di Kaggle con attacchi reali
2. **`bob_inject.csv`** (697 bytes, 10 righe) → contiene 10 righe false con `src_ip = 172.20.0.12` (l'IP di Bob)
3. **`merge_datasets.py`** → script Python che:
   - Legge `honeypot.csv`
   - Legge `bob_inject.csv`
   - Normalizza lo schema di bob_inject allo schema honeypot (converte IP in intero, protocollo numerico→stringa, aggiunge geo-dati finti)
   - Concatena i due dataset
   - Salva come **`merged.csv`** (48.8 MB, ~451K + 10 righe)
4. **`merged.csv`** è il file che va caricato su Splunk (nell'index `honeypot`)

### Nel PDP il match funziona così:

```python
# pdp.py, riga 23
SEARCH_QUERY = 'search index=* (source="honeypot.csv" OR source="merged.csv") | stats count by srcstr | search count > 0'
```

Quando il PDP riceve i risultati da Splunk, cerca se qualche IP sorgente (`srcstr`) match con gli IP della rete interna (`172.20.*`):

```python
# pdp.py, riga 159
if "172.20" in bad_ip or bad_ip == "172.20.0.12":
    update_trust(bad_ip, 0.40)  # Forte detrazione
```

---

## 3. Stato attuale dell'implementazione

### Mappa dei Container (11 servizi nel docker-compose)

| Container | Immagine | IP (data-plane) | IP (control-plane) | Stato codice |
|---|---|---|---|---|
| `zta-dbms` | `postgres:16` | — | auto | ✅ Completo |
| `zta-splunk` | `splunk/splunk:latest` | — | auto | ✅ Completo (serve config manuale) |
| `zta-pdp` | Python custom | — | auto | ✅ Funzionante |
| `zta-resource` | Python (FastAPI) | `172.20.0.100` | — | ✅ Completo |
| `zta-pep` | Python (FastAPI) | `172.20.0.99` | `172.21.0.99` | ⚠️ Parziale (vedi problemi) |
| `zta-ids` | `linton/docker-snort` | `172.20.0.98` | `172.21.0.98` | ⚠️ Regole OK, ma no forwarding log |
| `zta-proxy` | `ubuntu/squid:5.2` | `172.20.0.97` | `172.21.0.97` | ⚠️ Config OK, ma no forwarding log |
| `zta-firewall` | Ubuntu + IPTables | `172.20.0.96` | `172.21.0.96` | ⚠️ API OK, ma no forwarding log |
| `zta-client-alice` | Alpine + curl | `172.20.0.10` | — | ✅ Simulazione OK |
| `zta-client-kiosk` | Alpine + curl | `172.20.0.11` | — | ✅ Simulazione OK |
| `zta-client-bob` | Alpine + curl | `172.20.0.12` | — | ✅ Simulazione OK |

---

### Dettaglio per componente

#### ✅ DBMS (PostgreSQL)
- **Schema**: tabella `policies` (device_ip, device_name, trust_score) + tabella `access_logs`
- **Dati iniziali**: Alice (0.85), Kiosk (0.50), Bob (0.80)
- **Stato**: Completo e funzionante

#### ✅ PDP (Policy Decision Point)
- **Funzionamento**: Loop infinito ogni 15 secondi
  1. Si autentica a Splunk REST API (`/services/auth/login`)
  2. Lancia una search query (`/services/search/jobs`)
  3. Attende il completamento del job
  4. Scarica i risultati JSON
  5. Per ogni IP nel dataset che contiene `172.20`, riduce il trust di 0.40
- **Fallback demo**: se Splunk non ha dati, riduce comunque Bob di 0.25 ogni ciclo
- **Stato**: Funzionante

#### ⚠️ PEP (Policy Enforcement Point)
- **Funzionamento**: FastAPI gateway che intercetta tutte le richieste
  - Trust ≤ 0.0 → BAN (chiama firewall API + 403)
  - `/admin/dump` richiede trust > 0.90
  - `/transfer` richiede trust > 0.70
  - `/balance` richiede trust > 0.40
- **Problemi**:
  1. Non passa le variabili d'ambiente `DB_HOST`, `DB_USER`, `DB_PASS`, `DB_NAME` nel docker-compose
  2. Non scrive nella tabella `access_logs` (la tabella esiste ma non viene usata)
  3. Non invia log a Splunk

#### ⚠️ Firewall (IPTables + API)
- **Funzionamento**: FastAPI su porta 8081 con 2 endpoint:
  - `POST /ban?ip=X` → esegue `iptables -A FORWARD -s X -j DROP`
  - `GET /status` → mostra le regole iptables
- **Problemi**:
  1. Non ha regole IPTables di base pre-configurate (solo ACCEPT di default)
  2. Non manda log a Splunk
  3. Il `start.sh` nella root del progetto è diverso da quello nella cartella `components/firewall/` — il Dockerfile copia quello dentro components

#### ⚠️ Proxy (Squid)
- **Funzionamento**: Squid ascolta sulla porta 3128
  - ACL che blocca `.evil-malware-domain.com` e `.suspicious-site.net`
  - ACL che blocca file `.exe` e `.torrent`
  - Log via syslog (`access_log syslog:local1.info squid`)
- **Problemi**:
  1. I log syslog vanno configurati per arrivare effettivamente a Splunk (serve rsyslog o forwarding esplicito a `splunk:1514/udp`)
  2. Il traffico dei client **non passa effettivamente** attraverso Squid — i client puntano direttamente al PEP

#### ⚠️ IDS (Snort)
- **Funzionamento**: Snort in modalità console (`-A console`) con 2 regole custom:
  - `sid:1000001` → rileva pattern `OR 1=1` (SQL Injection)
  - `sid:1000002` → rileva accesso a `api/v1/admin/dump`
- **Problemi**:
  1. Gli alert **non vengono inviati a Splunk**
  2. L'immagine Docker `linton/docker-snort` potrebbe essere obsoleta
  3. Il traffico non transita realmente da Snort (stessa questione del routing)

#### ✅ API Server (Risorsa protetta)
- 3 endpoint banking: `/balance`, `/transfer`, `/admin/dump`
- Stato: Completo

#### ✅ Client simulati
- **Alice** (`legit`): chiede balance + transfer ogni 15s
- **Kiosk** (`kiosk`): chiede solo balance ogni 5s
- **Bob** (`suspect`): naviga via proxy su domini malevoli + SQL injection su `/admin/dump`
- Stato: Script completi

---

## 4. 🔴 Problemi CRITICI da risolvere

> [!CAUTION]
> Questi sono i problemi reali che impediscono al progetto di funzionare come richiesto dal professore.

### Problema 1: IL TRAFFICO NON TRANSITA NELLA CATENA REALE

Il PDF richiede: `Client → IPTables → Squid → Snort → PEP → Risorsa`

**Cosa succede ora**: I client chiamano direttamente `http://pep/...` (o `http://proxy:3128` per Bob quando usa il proxy). Non c'è un routing forzato che faccia passare TUTTO il traffico attraverso Firewall → Proxy → IDS → PEP in sequenza.

**Cosa serve**: Configurare il routing Docker in modo che:
- I client possano raggiungere SOLO il firewall
- Il firewall faccia NAT/forward verso il proxy
- Il proxy faccia forward verso Snort (IDS)
- Snort faccia forward verso il PEP
- Il PEP faccia forward verso l'API Server

### Problema 2: I LOG NON ARRIVANO A SPLUNK

IPTables, Squid e Snort generano log localmente ma **non li inviano a Splunk** (`splunk:1514/udp`).

**Cosa serve**:
- **Firewall**: configurare `iptables -j LOG` e `rsyslog` per forwardare a Splunk
- **Squid**: il syslog è configurato ma serve un forwarder (rsyslog o simile) dentro il container
- **Snort**: configurare output `alert_syslog` o `unified2` con un forwarder

### Problema 3: PEP manca environment nel docker-compose

Il container `pep` nel `docker-compose.yaml` non ha la sezione `environment` con le credenziali DB. Usa i default hardcoded che coincidono, ma è fragile.

### Problema 4: PEP non logga nel DB

La tabella `access_logs` nel DBMS esiste ma il PEP non ci scrive mai. Ogni decisione (allow/deny) dovrebbe essere registrata per audit trail.

---

## 5. 🟡 Cose da migliorare (non bloccanti)

1. **Dashboard Splunk**: vanno create manualmente dopo il primo avvio (vedi Walkthrough sezione 7)
2. **Trust History**: la tabella `trust_history` prevista nell'`architecture_analysis.md` non è nel `init.sql`
3. **Regole IPTables pre-configurate**: il firewall parte con policy ACCEPT su tutto, sarebbe meglio avere regole base
4. **Doppio check MAC Address**: il prof vuole vedere che sapete gestire la questione MAC — nel firewall si potrebbe aggiungere una regola MAC-based di esempio
5. **PDP fallback troppo aggressivo**: la riga 165-166 degrada Bob di 0.25 ANCHE quando Splunk non ha risultati — questo è un hack per la demo ma il prof potrebbe chiedervi perché

---

## 6. 🗺️ Roadmap: come procedere

### Priorità ALTA (senza queste non funziona la demo)

| # | Task | Sforzo |
|---|---|---|
| 1 | **Risolvere il routing del traffico**: far passare tutto il traffico nella catena `Firewall → Proxy → IDS → PEP → API` | Alto |
| 2 | **Forwarding log a Splunk**: configurare rsyslog/syslog-ng nei container Firewall, Proxy, IDS per mandare a `splunk:1514/udp` | Medio |
| 3 | **Caricare merged.csv su Splunk**: al primo avvio, upload manuale del CSV nell'index `honeypot` (istruzioni nel Walkthrough) | Basso |
| 4 | **Configurare UDP 1514 su Splunk**: abilitare Data Input UDP 1514 (istruzioni nel Walkthrough) | Basso |

### Priorità MEDIA (migliora il voto)

| # | Task | Sforzo |
|---|---|---|
| 5 | Aggiungere `environment` al PEP nel docker-compose | Basso |
| 6 | Far scrivere gli access_logs dal PEP | Basso |
| 7 | Aggiungere tabella `trust_history` al DB | Basso |
| 8 | Aggiungere regole IPTables di base + regola MAC-based nel firewall | Basso |
| 9 | Creare le Dashboard Splunk (Top 10 IP, Timeline, Porte, Paesi) | Medio |

### Priorità BASSA (ciliegina sulla torta)

| # | Task | Sforzo |
|---|---|---|
| 10 | Rimuovere il fallback demo dal PDP (riga 165-166) e farlo funzionare solo via Splunk reale | Basso |
| 11 | Aggiungere una UI/report di riepilogo della demo | Opzionale |
| 12 | Documentare il progetto con diagrammi per la presentazione | Medio |

---

## 7. Riepilogo file del progetto

```
Advanced-Cybersecurity-for-IT-Project/
├── .env.example                    # Template credenziali
├── .env                            # Credenziali personali (gitignored)
├── docker-compose.yaml             # Orchestrazione 11 container
├── Adv-2025-Projects.pdf           # PDF del professore
├── honeypot.csv                    # Dataset originale Kaggle (48.8 MB)
├── bob_inject.csv                  # 10 righe fake con IP di Bob
├── merge_datasets.py               # Script merge honeypot + bob
├── merged.csv                      # Risultato del merge (da caricare su Splunk)
├── start.sh                        # Script avvio firewall (radice, NON usato)
├── README.md                       # Documentazione progetto
├── architecture_analysis.md        # Analisi architetturale dettagliata
├── Walkthrough.md                  # Guida passo-passo per il team
└── components/
    ├── api-server/                 # FastAPI banking API (risorsa protetta)
    │   ├── Dockerfile
    │   ├── main.py
    │   └── requirements.txt
    ├── clients/                    # Simulatore traffico (Alice, Kiosk, Bob)
    │   ├── Dockerfile
    │   └── simulator.sh
    ├── dbms/                       # Schema + dati iniziali PostgreSQL
    │   └── init.sql
    ├── firewall/                   # IPTables + API Flask per ban dinamico
    │   ├── Dockerfile
    │   ├── fw_api.py
    │   ├── requirements.txt
    │   └── start.sh
    ├── ids/                        # Snort IDS con regole SQL injection
    │   ├── Dockerfile
    │   └── local.rules
    ├── pdp/                        # Policy Decision Point (query Splunk REST)
    │   ├── Dockerfile
    │   ├── pdp.py
    │   └── requirements.txt
    ├── pep/                        # Policy Enforcement Point (gateway FastAPI)
    │   ├── Dockerfile
    │   ├── pep.py
    │   └── requirements.txt
    └── proxy/                      # Squid proxy con ACL domini malevoli
        ├── Dockerfile
        └── squid.conf
```
