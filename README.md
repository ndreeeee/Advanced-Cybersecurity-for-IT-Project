# 🛡️ Zero Trust Architecture - Banking API Security

Progetto per il corso di **Advanced Cybersecurity** (2025).
Il progetto implementa una **Zero Trust Architecture (ZTA)** completa sfruttando un'infrastruttura a container (Docker), basata sui requisiti definiti dal Prof. L. Spalazzi.

## 🎯 Obiettivo del Progetto
Costruire un'architettura divisa in **Control Plane** e **Data Plane**, utilizzando i seguenti tool obbligatori:
- **Splunk**: SIEM per la raccolta e l'analisi centralizzata dei log.
- **IPTables**: Packet filter autonomo (Firewall L3/L4).
- **Squid**: Application-level firewall / Proxy (Filtro L7).
- **Snort**: Intrusion Detection/Prevention System (IDS/IPS).
- **PostgreSQL**: DBMS a scelta come Policy Store.
- App custom (Python): Per simulare **PDP** (Policy Decision Point) e **PEP** (Policy Enforcement Point).

---

## 🏗️ Architettura

Per mantenere l'isolamento richiesto, ogni componente "logico" della rete vive in un container isolato. Le comunicazioni sono suddivise su due reti Docker distinte: `data-plane` e `control-plane`.

### Mappa dei Container (9 Totali)

| Container | Ruolo ZTA | Descrizione |
|-----------|-----------|-------------|
| `client-*` | Subject | I client che effettuano richieste HTTP all'API. |
| `firewall` | Firewall L3 | Implementato con **IPTables**. Filtra per IP/Porta. |
| `proxy` | Firewall L7 | Implementato con **Squid**. Blocca traffico verso URL/domini sospetti. |
| `ids` | Deep Packet Ins. | Implementato con **Snort**. Rileva payload anomali (es. SQLi). |
| `pep` | Enforcement | App Python. Valuta il trust in tempo reale e inoltra/blocca il flusso. |
| `api-server`| Resource | App backend vulnerabile (es. Nginx + Python API). |
| `dbms` | Policy Store | **PostgreSQL**. Contiene il Trust Score e le regole. |
| `splunk` | Analytics | SIEM che aggrega i log dai container sul Data Plane. |
| `pdp` | Decision | App Python. Interroga Splunk via API, aggiorna il DBMS dinamicamente. |

---

## 🏦 Caso di Studio: "Core Banking API"

Per dimostrare l'efficacia del motore ZTA, il progetto simula l'ambiente interno di un istituto finanziario in cui gli impiegati usano un'API bancaria. Il trust non è statico ma viene valutato *contemporaneamente* in base al comportamento di rete della singola macchina.

### 1. La Risorsa (API Server)
* 🟢 `/api/v1/balance` - Visione saldi (Richiede Trust > 0.40)
* 🟡 `/api/v1/transfer` - Operazioni dispositive (Richiede Trust > 0.70)
* 🔴 `/api/v1/admin/dump` - Esportazione totale (Richiede Trust > 0.90)

### 2. Le Identità (I Client)
* **`employee-alice`**: Lavora normalmente senza violazioni (Trust stabile: 0.85).
* **`branch-kiosk`**: Terminale filiale limitato, può solo leggere saldi (Trust stabile: 0.50).
* **`employee-bob`**: Dispositivo inizialmente fidato (0.80) che viene compromesso da un malware durante la demo.

### 3. Ruolo Strumenti nel Caso d'Uso
* Durante le operazioni, ogni richiesta passa attraverso `firewall` -> `proxy` -> `ids` -> `pep`.
* **Squid** registra e blocca tentativi di navigazione su siti neri.
* **Snort** analizza se `employee-bob` invia payload malevoli contro l'API (`' OR 1=1--`).
* **Splunk** riceve in tempo reale syslog e alert.
* **PDP** analizza i dati su Splunk e abbassa/azzera il Trust Score.
* **PEP** agisce di conseguenza su DBMS, bloccando prima accessi a layer API, per poi inviare `DROP` rule definitive ad **IPTables** in caso di trust stracciato.

---

## 🎬 Scenari di Dimostrazione (Flusso)

### Fase 1: Funzionamento Regolare (Allow)
**Alice** (Trust=0.85) effettua transazioni su `/transfer`. Tutto il traffico passa pulito negli stream Snort/Squid. PEP autorizza interrogando il DBMS.

### Fase 2: Infezione e Degrado (Restrict)
**Bob** (Trust=0.80) inizia a interrogare domini anomali. **Squid** intercetta e invia il report. **Splunk** indicizza l'anomalia. **PDP** degrada il Trust di Bob a `0.60`. Ora Bob può solo vedere i saldi su `/balance`, ma il PEP gli stacca l'autorizzazione per `/transfer`.

### Fase 3: Isolamento Network Totale (Deny)
Il Malware su Bob prova uno scan e una SQL Injection massiva verso `/admin/dump`. **Snort** fa *trigger* ed invia un Critical Alert a Splunk. Il **PDP** fissa il trust di Bob a `0.00`. Il **PEP** implementa istantaneamente una regola **IPTables** sul livello del Kernel che taglia fisicamente la rete TCP di Bob verso l'infrastruttura.
