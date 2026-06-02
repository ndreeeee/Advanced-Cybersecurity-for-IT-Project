<p align="center">
  <img src="docs/zta_project_banner.png" alt="Zero Trust Architecture 2026 Project Banner" width="900" style="border-radius: 8px;">
</p>

# 🛡️ Zero Trust Architecture (ZTA) 2026
### *Microsegmentazione, Attestazione Hardware, Adaptive Risk Assessment e Ispezione L7 per la protezione di Database Ospedalieri*

<p align="center">
  <a href="https://www.docker.com/"><img src="https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white" alt="Docker"></a>
  <a href="https://www.envoyproxy.io/"><img src="https://img.shields.io/badge/Envoy_Proxy-9D3F9D?style=for-the-badge&logo=envoyproxy&logoColor=white" alt="Envoy"></a>
  <a href="https://www.openpolicyagent.org/"><img src="https://img.shields.io/badge/Open_Policy_Agent-1A2E40?style=for-the-badge&logo=openpolicyagent&logoColor=white" alt="OPA"></a>
  <a href="https://www.splunk.com/"><img src="https://img.shields.io/badge/Splunk_Enterprise-000000?style=for-the-badge&logo=splunk&logoColor=F25B22" alt="Splunk"></a>
  <a href="https://www.mongodb.com/"><img src="https://img.shields.io/badge/MongoDB-47A248?style=for-the-badge&logo=mongodb&logoColor=white" alt="MongoDB"></a>
</p>
<p align="center">
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python"></a>
  <a href="https://www.snort.org/"><img src="https://img.shields.io/badge/Snort_IDS-FF0000?style=for-the-badge&logo=security&logoColor=white" alt="Snort"></a>
  <a href="https://netfilter.org/projects/nftables/"><img src="https://img.shields.io/badge/nftables-FFA500?style=for-the-badge&logo=linux&logoColor=white" alt="nftables"></a>
  <a href="https://www.latex-project.org/"><img src="https://img.shields.io/badge/LaTeX-008080?style=for-the-badge&logo=latex&logoColor=white" alt="LaTeX"></a>
</p>

---

Questo repository contiene il codice sorgente, le configurazioni di rete dockerizzate, i modelli predittivi e la relazione accademica relativi al progetto di **Advanced Cybersecurity** (Anno Accademico 2025/2026). 

L'obiettivo è la realizzazione pratica di un'infrastruttura di rete basata sul paradigma **Zero Trust (ZTA)** per la sicurezza e la microsegmentazione delle API e del database della collezione medica di un portale ospedaliero (San Raffaele). Il sistema applica il principio cardine **"Never Trust, Always Verify"** scartando qualsiasi richiesta di default e sottoponendola a validazione continua a livello di rete, credenziali, postura hardware, impronta digitale software e rischio comportamentale in tempo reale.

---

## 📖 Indice
1. [🔍 Panoramica del Sistema](#-panoramica-del-sistema)
2. [⚙️ Flusso di Verifica Dinamico (Animato)](#%EF%B8%8F-flusso-di-verifica-dinamico-animato)
3. [🌐 Architettura e Microsegmentazione](#-architettura-e-microsegmentazione)
4. [⛓️ Flusso Logico delle Richieste (Sequence)](#%EF%B8%8F-flusso-logico-delle-richieste-sequence)
5. [📊 La Tupla Multidimensionale ZTA (6D)](#-la-tupla-multidimensionale-zta-6d)
6. [🛠️ Simulazione e Validazione dei 5 Scenari](#%EF%B8%8F-simulazione-e-validazione-dei-5-scenari)
7. [🚀 Avvio dell'Infrastruttura](#-avvio-dellinfrastruttura)
8. [👥 Autori e Contesto Accademico](#-autori-e-contesto-accademico)

---

## 🔍 Panoramica del Sistema
Nelle reti tradizionali basate sul perimetro (*"castle-and-moat"*), l'intrusione all'interno della rete locale garantisce accesso illimitato alle risorse interne. Questo progetto neutralizza tale minaccia dividendo le risorse in aree segregate e ponendo all'ingresso un **Policy Enforcement Point (PEP)** rigido gestito da **Envoy Proxy**, coordinato con un **Policy Decision Point (PDP)** rappresentato da **Open Policy Agent (OPA)**.

Ogni singola transazione viene validata controllando:
- **Identità forte**: Certificati mTLS con crittografia asimmetrica.
- **Integrità hardware**: Verifica dell'attestazione hardware del chip **TPM** (Trusted Platform Module).
- **Consistenza Software**: Fingerprinting **JA3** del browser per rilevare bot o manipolazioni di User-Agent.
- **Rischio Comportamentale**: Calcolato in tempo reale con algoritmi di Machine Learning (Gradient Boosting) su **Splunk SIEM**.
- **Analisi Payload L7**: Ispezione profonda dei verbi HTTP e delle query MongoDB per bloccare attacchi injection sul nascere.

---

## ⚙️ Flusso di Verifica Dinamico (Animato)
L'immagine vettoriale interattiva sottostante illustra graficamente il percorso dei pacchetti dati all'interno del nostro sistema ZTA: i tentativi di accesso validati fluiscono in verde fino al Secure Core, mentre i tentativi malevoli o non conformi vengono catturati ed espulsi al gateway con un verdetto di **DENY** immediato.

<p align="center">
  <img src="docs/zta_verification_flow.svg" alt="Dynamic ZTA Verification Flow" width="850">
</p>

---

## 🌐 Architettura e Microsegmentazione
La topologia di rete è strutturata in **quattro zone isolate** definite nel `docker-compose.yaml`. I client non possiedono alcuna via di instradamento diretto alle risorse protette, dovendo transitare obbligatoriamente per il canale cifrato controllato da Envoy.

```mermaid
graph TD
    classDef untrusted fill:#4d2c2c,stroke:#ff6b6b,stroke-width:2px,color:#fff;
    classDef dmz fill:#2c3e50,stroke:#3498db,stroke-width:2px,color:#fff;
    classDef core fill:#1b4d3e,stroke:#2ecc71,stroke-width:2px,color:#fff;
    classDef control fill:#2c2c2c,stroke:#95a5a6,stroke-width:2px,color:#fff;
    classDef pep fill:#d35400,stroke:#e67e22,stroke-width:3px,color:#fff;

    subgraph ReteEsterna["🌐 Rete Esterna (Smart Working)"]
        charlie["💻 Charlie (Remoto)"]:::untrusted
    end

    subgraph ReteInterna["🏢 Rete Interna / DMZ"]
        alice["💻 Alice (Aziendale)"]:::dmz
        bob["💻 Bob (BYOD Personale)"]:::dmz
        fw["🛡️ nftables Firewall"]:::dmz
    end

    subgraph SecureCore["🔒 Secure Core (Backend Network)"]
        pep["🎛️ Envoy Proxy PEP"]:::pep
        api["🐍 Web API (Flask)"]:::core
        db[("🗄️ MongoDB Database")]:::core
    end

    subgraph ControlPlane["⚙️ Piano di Controllo (Trust Zone)"]
        opa["🧠 Open Policy Agent PDP"]:::control
        splunk["📊 Splunk SIEM + MLTK"]:::control
        fluent["📦 Fluent-Bit Shipper"]:::control
        snort["🕵️ Snort NIDS"]:::control
    end

    %% Flussi Dati e Connessioni
    charlie -->|1. mTLS| fw
    alice -->|1. mTLS + TPM| fw
    bob -->|1. mTLS| fw
    
    fw -->|2. DNAT (8443)| pep
    pep <-->|3. gRPC Authz| OPA
    opa <-->|4. HTTP Risk API| splunk
    
    pep -->|5. HTTP Proxy| api
    api -->|6. TCP Driver| db
    
    %% Flussi di Monitoraggio e Telemetria
    fw -.->|Log ulogd2| fluent
    pep -.->|Log Accesso L7| fluent
    api -.->|Log Applicativi| fluent
    db -.->|Log Transazioni| fluent
    snort -.->|Alert Intrusioni| fluent
    fluent -->|HEC HTTPS| splunk
    fw -.->|Packet Mirroring| snort
```

---

## ⛓️ Flusso Logico delle Richieste (Sequence)
Il diagramma di sequenza mostra le fasi sequenziali attraverso le quali si dipana la validazione di una richiesta di accesso alle cartelle cliniche:

```mermaid
sequenceDiagram
    autonumber
    actor Client as Client (Alice/Bob/Charlie)
    participant FW as nftables Firewall
    participant PEP as Envoy Proxy (PEP)
    participant PDP as Open Policy Agent (PDP)
    participant SIEM as Splunk + MLTK (PIP/PAP)
    participant API as Web API
    participant DB as MongoDB

    Client->>FW: 1. Connessione cifrata (mTLS Handshake)
    Note over Client,FW: Estrazione certificato client & verifica OID TPM
    FW->>PEP: 2. Inoltro traffico (DNAT su porta 8443)
    PEP->>PDP: 3. Richiesta autorizzazione gRPC (CheckRequest)
    Note over PEP,PDP: Invio: Utente, TPM, IP, JA3, URL, Payload L7
    PDP->>SIEM: 4. Interrogazione rischio comportamentale
    SIEM-->>PDP: 5. Ritorno Risk Score (ML Predictor)
    
    alt Verdetto: CONSENTITO (Rischio sotto soglia & TPM presente & Rete Interna)
        PDP-->>PEP: 6a. OK (ALLOW)
        PEP->>API: 7. Inoltro chiamata HTTP
        API->>DB: 8. Esecuzione query nel Database
        DB-->>API: 9. Dati clinici dei pazienti
        API-->>PEP: 10. HTTP Response 200 OK
        PEP-->>Client: 11. Visualizzazione Portale Pazienti
    else Verdetto: NEGATO (No TPM / Rete Esterna / Rischio Elevato / Query Injection)
        PDP-->>PEP: 6b. KO (DENY)
        PEP-->>Client: 7. HTTP 403 Forbidden / Connection Reset
    end
```

---

## 📊 La Tupla Multidimensionale ZTA (6D)
Per ogni richiesta, OPA valuta la tupla contestuale dinamica $T = (u, d, s, n, a, r)$:

1. **User ($u$)**: Identità dell'utente autenticata via mTLS (`CN=employee-alice`).
2. **Device ($d$)**: Postura del client. OPA cerca l'OID proprietario `1.3.6.1.4.1.9999.1` iniettato nel certificato tramite attestazione TPM.
3. **Software ($s$)**: Hash del fingerprinting **JA3** calcolato da Envoy per garantire che il browser non sia emulato o compromesso.
4. **Network ($n$)**: Subnet di provenienza (Internal `192.168.1.0/24` vs External `10.0.1.0/24`).
5. **Action ($a$)**: Metodo di accesso applicativo (richieste `GET`/`POST` o query MongoDB `find`/`delete` ispezionate a livello L7).
6. **Resource ($r$)**: Endpoints o risorse target (es: `/api/patients`).

---

## 🛠️ Simulazione e Validazione dei 5 Scenari

Di seguito sono dettagliati i cinque scenari operativi simulati all'interno della rete di test:

| Scenario | Utente | Dispositivo | Rete | Azione / Payload | Esito OPA / Firewall | Logica di Sicurezza |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **1. Accesso Legittimo** | Alice | Sicuro (TPM) | Interna | Ricerca pazienti | **ALLOW** | Risk score Splunk minimo ($\approx 9.96$), OPA autorizza l'accesso al DB. |
| **2. Dispositivo BYOD** | Bob | Personale (No TPM) | Interna | Autenticazione | **DENY** | Mancanza di attestazione TPM. Blocco immediato al login. |
| **3. Accesso da Esterno** | Charlie | Sicuro (TPM) | Esterna | Autenticazione | **DENY** | Blocco preventivo dovuto alla localizzazione di rete non protetta. |
| **4. Bypass di Rete L4** | Charlie | - | Esterna | Connessione diretta DB | **DROP (Firewall)** | `nftables` scarta i pacchetti diretti su porta `8000`. Snort allerta il SIEM. |
| **5. Injection L7** | Alice | Sicuro (TPM) | Interna | `DROP` / `DELETE` | **DENY (Envoy L7)** | Rilevamento payload malevolo a livello L7 tramite `mongo_proxy`. |

---

### 📂 Dettagli Tecnici degli Scenari ed Evidenze Grafiche

<details>
<summary><b>🟢 Scenario 1: Accesso Legittimo di Alice</b></summary>

* **Descrizione**: L'utente Alice si connette dalla workstation ospedaliera interna dotata di chip TPM. 
* **Flusso**: mTLS Handshake OK $\rightarrow$ TPM Check OK $\rightarrow$ Splunk Risk Score OK ($\approx 9.96 \le 50$) $\rightarrow$ Accesso consentito.
* **Risultati**: Alice visualizza correttamente le informazioni cliniche dei pazienti.
* **Evidenze**:
  
  *Schermata del Portale di Login Ospedaliero:*
  ![Login Page](relazione/capitolo4/img/login_page.png)
  
  *Portale Pazienti sbloccato con successo:*
  ![Alice Dashboard](relazione/capitolo4/img/alice_dashboard.png)
  
  *Log di autorizzazione OPA indicizzato in Splunk:*
  ![Splunk Alice Allowed](relazione/capitolo4/img/splunk_alice_allowed.png)

</details>

<details>
<summary><b>🔴 Scenario 2: Dispositivo BYOD Non Autorizzato (Bob)</b></summary>

* **Descrizione**: Bob tenta l'accesso usando credenziali valide ma dal proprio portatile personale (privo del chip TPM aziendale).
* **Flusso**: mTLS Handshake $\rightarrow$ OPA rileva `tpm_present: false` $\rightarrow$ Blocco al login.
* **Risultati**: Bob riceve un errore HTTP 403 Forbidden e non può accedere a nessuna sessione.
* **Logica Chiave**: Nonostante il rischio comportamentale stimato da Splunk sia bassissimo ($\approx 5.5$), l'assenza di TPM agisce come vincolo rigido non compensabile, determinando il verdetto di **DENY**.
* **Evidenze**:
  
  *Schermata di blocco visualizzata da Bob:*
  ![Bob Blocked](relazione/capitolo4/img/bob_blocked.png)
  
  *Log di blocco Splunk (evidenziata la mancanza di TPM):*
  ![Splunk Bob Blocked](relazione/capitolo4/img/splunk_bob_blocked.png)

</details>

<details>
<summary><b>🟡 Scenario 3: Accesso da Rete Esterna (Charlie)</b></summary>

* **Descrizione**: Charlie tenta di collegarsi da casa (rete esterna/Smart Working) usando il suo laptop aziendale sicuro con TPM.
* **Flusso**: mTLS Handshake $\rightarrow$ OPA rileva `network_internal: false` $\rightarrow$ Blocco preventivo.
* **Risultati**: Charlie viene bloccato al portale di login a causa delle politiche di restrizione geografica/IP.
* **Evidenze**:
  
  *Schermata di blocco visualizzata da Charlie:*
  ![Charlie Blocked](relazione/capitolo4/img/charlie_blocked.png)
  
  *Log Splunk (blocco dovuto a network non interna):*
  ![Splunk Charlie Blocked](relazione/capitolo4/img/splunk_charlie_blocked.png)

</details>

<details>
<summary><b>💥 Scenario 4: Tentativo di Bypass di Rete a Livello L4</b></summary>

* **Descrizione**: Un attaccante tenta di bypassare Envoy (PEP) provando a inviare query dirette alla porta interna delle API (`8000`) o del DB (`27017`).
* **Flusso**: Il client Charlie esegue un curl diretto $\rightarrow$ `nftables` intercetta il traffico anomalo $\rightarrow$ Regola `DROP` applicata $\rightarrow$ La sonda Snort NIDS rileva l'attività e allerta il SIEM $\rightarrow$ IP isolato permanentemente in denylist.
* **Comandi di Test**:
  ```bash
  docker exec -it zta-client-charlie curl -v --connect-timeout 3 http://zta-firewall:8000/api/patients
  ```
* **Risultati**: Connessione in timeout immediato. Il traffico anomalo viene scartato silenziosamente.
* **Evidenze**:
  
  *Visualizzazione dei log di blocco nftables indicizzati in tempo reale in Splunk:*
  ![Splunk Logs](relazione/capitolo4/img/splunk_logs.png)

</details>

<details>
<summary><b>🛑 Scenario 5: Ispezione e Blocco di Payload Dannosi L7</b></summary>

* **Descrizione**: Alice (compromessa o malintenzionata) tenta di inviare una query distruttiva (ad es. query di cancellazione MongoDB come `DROP` o `DELETE`) tramite la barra di ricerca.
* **Flusso**: Envoy intercetta la richiesta L7 $\rightarrow$ Il filtro `mongo_proxy` inoltra il payload ad OPA $\rightarrow$ OPA individua le chiavi proibite nel corpo della richiesta $\rightarrow$ Verdetto **DENY L7** $\rightarrow$ MongoDB protetto.
* **Risultati**: L'attacco injection fallisce immediatamente e ad Alice viene mostrato un errore HTTP 403 Forbidden.
* **Evidenze**:
  
  *Schermata di errore injection intercettata a livello applicativo:*
  ![Alice SQL Blocked](relazione/capitolo4/img/alice_sql_blocked.png)
  
  *Log di blocco L7 in Splunk (intercettazione chiamata DELETE/DROP):*
  ![Splunk Alice Blocked](relazione/capitolo4/img/splunk_alice_blocked.png)

</details>

---

## 🚀 Avvio dell'Infrastruttura

### Prerequisiti
- **Docker** e **Docker Compose** installati e funzionanti.
- Almeno 8GB di RAM dedicati a Docker (necessari per Splunk Enterprise e il modulo MLTK).

### Installazione e Orchestrazione
1. Clona la repository locale:
   ```bash
   git clone https://github.com/ndreeeee/Advanced-Cybersecurity-for-IT-Project.git
   cd Advanced-Cybersecurity-for-IT-Project
   ```
2. Compila i moduli Docker e avvia l'intera infrastruttura di container:
   ```bash
   docker-compose up --build -d
   ```
3. Verifica che tutti i servizi siano in esecuzione e sani:
   ```bash
   docker ps
   ```

### Accessi di Test
- **Portale Web (Login)**: `http://localhost:8081` (per simulare i client Alice, Bob, Charlie).
- **Console Splunk Enterprise**: `http://localhost:8000` (User: `admin`, Password configurata in `.env`).
- **Open Policy Agent (Regole API)**: `http://localhost:8181/v1/policies`

---

## 👥 Autori e Contesto Accademico

*Progetto finale di gruppo per il corso di **Advanced Cybersecurity** (Laurea Magistrale in Ingegneria Informatica e dell'Automazione).*
* **Ateneo**: Università Politecnica delle Marche (UNIVPM)
* **Docente**: Prof. Luca Spalazzi

<table align="center">
  <thead>
    <tr>
      <th align="center">Avatar</th>
      <th align="left">Candidato</th>
      <th align="left">Contatti</th>
      <th align="left">Ruoli Principali</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td align="center"><img src="https://github.com/ndreeeee.png" width="50" style="border-radius:50%"></td>
      <td align="left"><b>Andrea Flaiani</b><br>Matr. 1126928</td>
      <td align="left">
        📧 <a href="mailto:s1126928@studenti.univpm.it">s1126928@studenti.univpm.it</a><br>
        🐈 <a href="https://github.com/ndreeeee">@ndreeeee</a>
      </td>
      <td align="left">Ideazione Architettura ZTA, OPA Policies & Regole di rete nftables</td>
    </tr>
    <tr>
      <td align="center"><img src="https://ui-avatars.com/api/?name=Andrea+Altieri&background=0D8ABC&color=fff&rounded=true" width="50"></td>
      <td align="left"><b>Andrea Altieri</b><br>Matr. 1128865</td>
      <td align="left">📧 <a href="mailto:s1128865@studenti.univpm.it">s1128865@studenti.univpm.it</a></td>
      <td align="left">Splunk Enterprise SIEM Setup & Integrazione Algoritmi MLTK</td>
    </tr>
    <tr>
      <td align="center"><img src="https://ui-avatars.com/api/?name=Niccolo+de+Pascali&background=1abc9c&color=fff&rounded=true" width="50"></td>
      <td align="left"><b>Niccolò de Pascali</b><br>Matr. 1123958</td>
      <td align="left">📧 <a href="mailto:s1123958@studenti.univpm.it">s1123958@studenti.univpm.it</a></td>
      <td align="left">Configurazione Envoy PEP L7, Certificati mTLS & Backend API Flask</td>
    </tr>
    <tr>
      <td align="center"><img src="https://ui-avatars.com/api/?name=Matteo+Risolo&background=2ecc71&color=fff&rounded=true" width="50"></td>
      <td align="left"><b>Matteo Risolo</b><br>Matr. 1122743</td>
      <td align="left">📧 <a href="mailto:s1122743@studenti.univpm.it">s1122743@studenti.univpm.it</a></td>
      <td align="left">Configurazione telemetrie Fluent-Bit, Regole Snort IDS & Inoltro Log</td>
    </tr>
    <tr>
      <td align="center"><img src="https://ui-avatars.com/api/?name=Simone+Murazzo&background=9b59b6&color=fff&rounded=true" width="50"></td>
      <td align="left"><b>Simone Murazzo</b><br>Matr. 1113295</td>
      <td align="left">📧 <a href="mailto:s1113295@studenti.univpm.it">s1113295@studenti.univpm.it</a></td>
      <td align="left">Validazione dei 5 Scenari, Stesura Relazione LaTeX & Quality Assurance</td>
    </tr>
  </tbody>
</table>
