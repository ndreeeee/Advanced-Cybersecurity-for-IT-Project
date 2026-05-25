# Documentazione degli Scenari di Simulazione (ZTA 2026)

Questo documento spiega nel dettaglio come testare e dimostrare l'infrastruttura Zero Trust Architecture implementata per il progetto. Le interfacce web sviluppate permettono di visualizzare dinamicamente le reazioni dei componenti di sicurezza (Envoy PEP, OPA PDP, Splunk MLTK e Firewall) in risposta a diverse minacce.

---

## 🟢 Livello 1: Autenticazione e Verifica dell'Identità (Il caso Alice vs Bob)

Il primo livello dimostra l'implementazione del concetto *Device & Identity Verification*. In un sistema tradizionale, chiunque possieda le credenziali (username e password) può accedere al sistema. Nel nostro approccio ZTA, le credenziali sono solo il punto di partenza.

### Come testarlo:
1. **Accesso Legittimo (Alice)**: Collegandosi a `http://localhost:8081` si utilizza il client di Alice. Envoy estrae i campi del certificato mTLS e OPA valuta la presenza dell'OID `1.3.6.1.4.1.9999.1` (simulazione del chip TPM hardware). Dato che Alice usa un PC aziendale sicuro, l'accesso è **concesso**.
2. **Accesso Negato (Bob)**: Collegandosi a `http://localhost:8082` si utilizza il client di Bob. Il suo certificato è sprovvisto dell'estensione TPM. OPA intercetta la richiesta tramite Envoy e restituisce un **DENY** immediato (Errore `403 Forbidden`).

```mermaid
graph LR
    classDef default fill:#f9fcfb,stroke:#a3b1c6,stroke-width:2px,color:#2d3436,rx:12,ry:12;
    classDef client fill:#ffffff,stroke:#2196f3,stroke-width:2px,color:#0d47a1,rx:12,ry:12;
    classDef security fill:#ffffff,stroke:#e53935,stroke-width:2px,color:#b71c1c,rx:12,ry:12;
    classDef core fill:#ffffff,stroke:#8e24aa,stroke-width:2px,color:#4a148c,rx:12,ry:12;
    classDef db fill:#ffffff,stroke:#43a047,stroke-width:2px,color:#1b5e20,rx:12,ry:12;
    classDef fail fill:#ffebee,stroke:#b71c1c,stroke-width:2px,color:#b71c1c,stroke-dasharray: 5 5,rx:12,ry:12;

    subgraph S1 ["Caso 1: Alice (Successo)"]
        Alice["👩‍💻 Alice<br>(PC Aziendale)"]:::client
        PEP_A{"<img src='https://img.shields.io/badge/-Envoy-D24185?style=flat&logo=envoyproxy&logoColor=white' />"}:::security
        OPA_A["<img src='https://img.shields.io/badge/-OPA-0E223D?style=flat&logo=openpolicyagent&logoColor=white' />"]:::core
        DB_A[("<img src='https://img.shields.io/badge/-MongoDB-47A248?style=flat&logo=mongodb&logoColor=white' />")]:::db
        
        Alice == "1. TLS + TPM" ==> PEP_A
        PEP_A -- "2. Check" --> OPA_A
        OPA_A -- "3. ALLOW" --> PEP_A
        PEP_A == "4. Accesso" ==> DB_A
    end

    subgraph S2 ["Caso 2: Bob (Bloccato)"]
        Bob["👨‍💻 Bob<br>(PC Privato)"]:::client
        PEP_B{"<img src='https://img.shields.io/badge/-Envoy-D24185?style=flat&logo=envoyproxy&logoColor=white' />"}:::security
        OPA_B["<img src='https://img.shields.io/badge/-OPA-0E223D?style=flat&logo=openpolicyagent&logoColor=white' />"]:::core
        Block_B(("❌ DENY<br>No TPM")):::fail
        
        Bob -. "1. TLS (No TPM)" .-> PEP_B
        PEP_B -. "2. Check" .-> OPA_B
        OPA_B ===> Block_B
    end
```

---

## 🔴 Livello 2: Rilevamento Anomalie e Insider Threat (Il Modello ML)

Il secondo livello dimostra la *Continuous Authentication*. Anche se un utente ha un dispositivo fidato, le sue azioni continuano ad essere monitorate per prevenire minacce interne (Insider Threat).

### Come testarlo:
1. Accedere alla dashboard tramite il client di Alice (`localhost:8081`).
2. **Simulazione Attacco SQLi**: Inserire nella barra di ricerca `DROP TABLE patients;` o `DELETE FROM records`.
3. **Cosa succede**: Splunk MLTK rileva l'anomalia comportamentale (una richiesta distruttiva da parte di un medico). Il **Trust Score** schizza oltre 50. OPA riceve questo score e blocca la richiesta sul nascere.

```mermaid
graph LR
    classDef default fill:#f9fcfb,stroke:#a3b1c6,stroke-width:2px,color:#2d3436,rx:12,ry:12;
    classDef client fill:#ffffff,stroke:#2196f3,stroke-width:2px,color:#0d47a1,rx:12,ry:12;
    classDef security fill:#ffffff,stroke:#e53935,stroke-width:2px,color:#b71c1c,rx:12,ry:12;
    classDef core fill:#ffffff,stroke:#8e24aa,stroke-width:2px,color:#4a148c,rx:12,ry:12;
    classDef fail fill:#ffebee,stroke:#b71c1c,stroke-width:2px,color:#b71c1c,stroke-dasharray: 5 5,rx:12,ry:12;

    Alice["👩‍💻 Alice<br>(Azione Anomala)"]:::client
    PEP{"<img src='https://img.shields.io/badge/-Envoy-D24185?style=flat&logo=envoyproxy&logoColor=white' />"}:::security
    OPA["<img src='https://img.shields.io/badge/-OPA-0E223D?style=flat&logo=openpolicyagent&logoColor=white' />"]:::core
    Splunk["<img src='https://img.shields.io/badge/-Splunk_MLTK-000000?style=flat&logo=splunk&logoColor=white' />"]:::core
    Block(("❌ DENY<br>Risk > 50")):::fail

    Alice == "1. DROP TABLE" ==> PEP
    PEP -- "2. Check gRPC" --> OPA
    OPA -- "3. Richiesta ML" --> Splunk
    Splunk -. "4. Score: 97" .-> OPA
    OPA ===> Block
```

---

## 🏴‍☠️ Livello 3: Movimento Laterale e Bypass del Firewall (L3/L4)

L'ultimo livello dimostra la robustezza dei confini di micro-segmentazione. Un attaccante che ha compromesso un container potrebbe tentare di aggirare il proxy ZTA (Envoy) e colpire direttamente le API di backend.

### Come testarlo:
1. Accedere alla dashboard di Alice.
2. Premere `Ctrl + Shift + D` per aprire la **Console di Debug (Terminale Hacker)** nascosta.
3. Inserire il comando `curl http://backend-api:8000/api/patients`.
4. **Cosa succede**: Stai dicendo al container del client di scavalcare Envoy. Tuttavia, il Firewall L3/L4 (nftables) scarta (DROP) qualsiasi connessione al backend che non provenga esclusivamente dall'IP di Envoy.

```mermaid
graph LR
    classDef default fill:#f9fcfb,stroke:#a3b1c6,stroke-width:2px,color:#2d3436,rx:12,ry:12;
    classDef hacker fill:#ffffff,stroke:#000000,stroke-width:2px,color:#000000,rx:12,ry:12;
    classDef security fill:#ffffff,stroke:#e53935,stroke-width:2px,color:#b71c1c,rx:12,ry:12;
    classDef db fill:#ffffff,stroke:#43a047,stroke-width:2px,color:#1b5e20,rx:12,ry:12;
    classDef fail fill:#ffebee,stroke:#b71c1c,stroke-width:2px,color:#b71c1c,stroke-dasharray: 5 5,rx:12,ry:12;

    Hacker["🥷 Attaccante<br>(Bypass Envoy)"]:::hacker
    FW["🔥 NFTables<br>Firewall L3"]:::security
    DB[("<img src='https://img.shields.io/badge/-Backend_API-3776AB?style=flat&logo=python&logoColor=white' />")]:::db
    Block(("❌ DROP<br>IP non Autorizzato")):::fail
    Snort(("🐷 Snort<br>Alert")):::security

    Hacker == "1. Connessione Diretta" ==> FW
    FW ===> Block
    FW -. "2. Segnala Intrusione" .-> Snort
```

---

## 🌐 Livello 4: Accesso Condizionato Adattivo (Adaptive Risk)

Il quarto livello espande il concetto di "Non fidarti mai" includendo il **contesto ambientale** dell'utente. La ZTA valuta dinamicamente la tolleranza al rischio.

### Come testarlo:
1. **Accesso Ospedale**: `http://localhost:8081` (Alice). OPA vede che l'IP è interno e tollera un `risk_score <= 50`.
2. **Accesso Esterno (Smart Working)**: Vai su `http://localhost:8083` (Charlie). OPA rileva l'IP esterno e **abbassa drasticamente la tolleranza al rischio (<= 10)**.
3. **Perché Charlie viene bloccato?** Charlie usa un dispositivo aziendale con un livello di rischio "normale" (es. 15). Se fosse in ospedale entrerebbe, ma dall'esterno la ZTA esige una salute del dispositivo impeccabile.

```mermaid
graph LR
    classDef default fill:#f9fcfb,stroke:#a3b1c6,stroke-width:2px,color:#2d3436,rx:12,ry:12;
    classDef client fill:#ffffff,stroke:#2196f3,stroke-width:2px,color:#0d47a1,rx:12,ry:12;
    classDef security fill:#ffffff,stroke:#e53935,stroke-width:2px,color:#b71c1c,rx:12,ry:12;
    classDef core fill:#ffffff,stroke:#8e24aa,stroke-width:2px,color:#4a148c,rx:12,ry:12;
    classDef fail fill:#ffebee,stroke:#b71c1c,stroke-width:2px,color:#b71c1c,stroke-dasharray: 5 5,rx:12,ry:12;

    Charlie["💻 Charlie<br>(Smart Working)"]:::client
    PEP{"<img src='https://img.shields.io/badge/-Envoy-D24185?style=flat&logo=envoyproxy&logoColor=white' />"}:::security
    OPA["<img src='https://img.shields.io/badge/-OPA-0E223D?style=flat&logo=openpolicyagent&logoColor=white' />"]:::core
    Splunk["<img src='https://img.shields.io/badge/-Splunk_MLTK-000000?style=flat&logo=splunk&logoColor=white' />"]:::core
    Block(("❌ DENY<br>15 > Soglia 10")):::fail

    Charlie == "1. Accesso Esterno" ==> PEP
    PEP -- "2. Check IP Context" --> OPA
    OPA -- "3. Valuta ML" --> Splunk
    Splunk -. "4. Score: 15" .-> OPA
    OPA ===> Block
```
