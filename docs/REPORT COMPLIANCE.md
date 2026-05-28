# Report di Conformità e Diagnosi: Progetto Zero Trust Architecture 2026

Questo report presenta un'analisi comparativa dettagliata tra i requisiti architetturali e operativi espressi nel documento di progetto (`Adv-2026-Project.pdf`) e l'implementazione attuale presente nel workspace locale.

---

## Fase 1: Estrazione dei Requisiti (Mappatura dei Componenti)

Dal documento PDF sono emersi i seguenti requisiti fondamentali e ruoli tecnologici:
1. **Envoy (PEP)**: Agisce come Policy Enforcement Point (PEP). Deve gestire l'autenticazione mTLS (Step 1), estrarre metadati (identità utente, software, device, network) e intercettare il traffico a livello applicativo (L7). Per MongoDB, deve usare `envoy.filters.network.mongo_proxy` per estrarre collezione e comandi.
2. **OPA (PDP)**: Agisce come Policy Decision Point (PDP). Riceve i metadati estratti da Envoy tramite gRPC.
3. **Splunk (SIEM)**: Riceve i dati da OPA e utilizza modelli di Machine Learning per calcolare il `rischio` dinamico in base alle dimensioni (User, Device, Software, Network, Action, Resource).
4. **Filtro L7 Firewall (Lua)**: Il diagramma (Slide 3, Step 9) richiede esplicitamente l'uso di `envoy.filters.http.lua` come firewall di Livello 7 per ispezionare il payload delle query autorizzate e bloccare eventuali payload dannosi prima di raggiungere il database.
5. **Estrazione Identità (Zero Trust 6D)**:
   - *Device*: Identificato tramite hardware (TPM OID nel certificato).
   - *Software*: Identificato tramite fingerprint JA3. In assenza di hardware, il sistema deve fare affidamento esclusivo sul fingerprint software.
6. **Network & Sicurezza**: Utilizzo di NFTables per firewall di rete e Snort come NIDS (Logs diretti verso Splunk).

---

## Fase 3: Analisi di Conformità e Diagnosi

### ✅ Componenti Conformi (Allineati al PDF)
- **Stack Tecnologico Primario**: Tutti i container richiesti (Envoy, OPA, Splunk, NFTables, Snort, MongoDB) sono regolarmente configurati nel `docker-compose.yaml` (Es. `nftables-firewall`, `mongodb-resource`, `envoy-pep`, `opa-pdp`, ecc.).
- **Estrazione delle Identità (mTLS e OID)**: Envoy è correttamente configurato con `tls_inspector` per il JA3. Le regole OPA in `rules.rego` estraggono fedelmente il `user` dal CN, il `device` validando il TPM tramite l'OID `[1, 3, 6, 1, 4, 1, 9999, 1]`, e il `software` tramite JA3/Header, in linea con le "Tips and Tricks" del PDF.
- **Flusso gRPC Envoy-OPA**: Il `mongo_proxy` emette correttamente i `dynamic_metadata` che vengono passati ad OPA tramite il filtro `ext_authz`.
- **Rischio Dinamico (Splunk ML)**: L'architettura prevede la corretta interrogazione del rischio basata sulle 6 dimensioni e OPA applica l'enforcement basato su soglie (es. `<= 50` con TPM, `<= 30` senza TPM).

### ⚠️ Discrepanze o Mancanze Rilevate
1. **Posizionamento e Uso del Filtro Lua (`envoy.filters.http.lua`)**:
   - *Requisito PDF*: Richiede l'uso di `envoy.filters.http.lua` direttamente sul traffico di database per fare L7 Firewall inspection (Slide 3, Step 9).
   - *Implementazione Locale*: Envoy *non può* usare un filtro HTTP (`http.lua`) in una catena di rete pura (TCP) come quella usata per MongoDB. L'attuale workspace aggira questo limite usando le regole native in OPA (`rules.rego`: `l7_dpi_block`) per fare Deep Packet Inspection sulla query MongoDB, e usa il filtro `http.lua` *solo* per l'accesso API (porta 8443 in `envoy.yaml`). Questa discrepanza rappresenta un ostacolo architetturale qualora il PDF intenda l'uso forzato del filtro Lua sul DB.
2. **Connessione OPA -> Splunk per il Rischio**:
   - *Requisito PDF*: Il diagramma (Slide 6) mostra OPA che comunica e riceve il rischio direttamente dal SIEM (Splunk).
   - *Implementazione Locale*: In `rules.rego` OPA interroga l'endpoint proxy `http://zta-web-api:8000/api/ml/predict`. L'uso di un proxy intermedio (la Web API in Python) per tradurre le query a Splunk non è strettamente "diretto" come indicato nei diagrammi, sebbene funzionale.

---

## 🛠️ Azioni Correttive Consigliate

Dal momento che non possiamo bypassare i limiti tecnici nativi di Envoy (un filtro `http.lua` non può processare payload binari MongoDB TCP), suggerisco le seguenti azioni per sanare o mitigare le non-conformità:

1. **Gestione del L7 Firewall Lua**:
   - **Opzione A (Mantenimento dell'Approccio in Rego - Consigliato)**: Lasciare l'implementazione del Deep Packet Inspection (DPI) per MongoDB all'interno di `rules.rego`. Questa è l'unica implementazione tecnicamente valida per il protocollo MongoDB.
   - **Opzione B (Allineamento Forzato)**: Modificare il flusso in modo che Envoy forzi il traffico DB attraverso un bridge HTTP in grado di invocare il Lua script, anche se questo stravolgerebbe le prestazioni e l'architettura. Suggerisco l'Opzione A.

2. **Dialogo Diretto OPA-Splunk**:
   - **Azione**: Riscrivere la funzione `http.send` in `rules.rego` in modo che chiami direttamente le API REST di Splunk (`https://zta-splunk:8089/services/search/jobs/export`) bypassando la Web-API in Python. Per farlo, occorre codificare in Base64 l'header `Authorization: Basic` e tradurre la manipolazione della stringa SPL in Rego puro.

**Attendo un feedback**: Procedo ad applicare la modifica su `rules.rego` per la chiamata diretta a Splunk, e confermi che il filtro Lua debba rimanere sulla parte HTTP delegando il DPI MongoDB ad OPA?
