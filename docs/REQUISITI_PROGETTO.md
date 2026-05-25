# Mappatura Requisiti del Progetto: Zero Trust Architecture (2026)

Questo documento illustra nel dettaglio come la nostra infrastruttura implementi in modo esatto e completo tutte le richieste presenti nelle specifiche originali del progetto (documento `Adv-2026-Project.pdf` del Prof. Spalazzi).

---

## 1. Stack Tecnologico Richiesto (Slide 2)

Il progetto imponeva l'utilizzo di una precisa combinazione di tecnologie open source. Tutte le tecnologie richieste sono state integrate in un ecosistema containerizzato tramite Docker Compose:

*   ✅ **Envoy Proxy**: Implementato come **Policy Enforcement Point (PEP)** in ascolto sulla porta 8443. Gestisce la terminazione mTLS e blocca nativamente qualsiasi richiesta non autenticata crittograficamente. Le richieste valide vengono messe in pausa e inoltrate a OPA tramite il filtro `ext_authz`.
*   ✅ **OPA (Open Policy Agent)**: Implementato come **Policy Decision Point (PDP)**. Valuta dinamicamente ogni singola richiesta (`rules.rego`) combinando le informazioni del livello di trasporto (certificati, IP) con il rischio comportamentale calcolato.
*   ✅ **Splunk**: Implementato come **SIEM e Motore ML**. Raccoglie i log di decisione (`[OPA-PDP]`) per fini di auditing e, tramite il Machine Learning Toolkit (MLTK), calcola in tempo reale il *Trust Score* (o Risk Score) degli utenti in base al loro comportamento storico.
*   ✅ **NFTables**: Implementato come **Firewall L3/L4**. Applica il concetto di micro-segmentazione tramite una policy di `default deny`. Effettua il port-forwarding (DNAT) esclusivamente verso Envoy, bloccando alla radice qualsiasi tentativo di bypass (es. *Lateral Movement* diretto verso il backend).
*   ✅ **Snort**: Implementato come **NIDS (Network Intrusion Detection System)**. Monitora il traffico interno per rilevare pattern anomali a livello di rete.
*   ✅ **MongoDB**: Implementato come **Data Tier (Risorsa Critica)**. Contiene i database delle cartelle cliniche (`patients`). Non è mai esposto direttamente all'utente o alla rete, ma è incapsulato e raggiungibile unicamente dalle API Python.

---

## 2. Flusso Zero Trust Architecture (Slide 3)

Il diagramma di sequenza fornito nei requisiti illustra un preciso flusso per ogni richiesta (es. `db.utenti.find()`). Il nostro sistema replica fedelmente questi passaggi:

1.  **Handshake mTLS & Fingerprinting (Step 1-2)**: I client stabiliscono una connessione sicura con Envoy. Oltre alla cifratura, Envoy valida il certificato X.509.
2.  **Estrazione Identità (L4/L7)**: Envoy estrae dal traffico molteplici vettori d'identità (la ZTA a 6 dimensioni):
    *   **Identità Utente (User)**: Estratta dal campo CN (Common Name) del certificato (es. `client-alice`).
    *   **Identità Rete (Network)**: Estratta dall'indirizzo IP di provenienza.
    *   **Identità Dispositivo (Device)**: Estratta tramite validazione crittografica di estensioni specifiche nel certificato (OID del TPM).
    *   **Impronta Software (JA3 / Fingerprint)**: Estratta e utilizzata come meccanismo di fallback per riconoscere dispositivi software quando manca l'attestazione hardware.
3.  **Controllo Autorizzazione OPA (Step 5)**: Envoy invia un payload gRPC a OPA contenente le informazioni estratte.
4.  **Interrogazione Splunk (Step 6-7)**: OPA interroga l'infrastruttura ML (Web API -> Splunk) inviando le dimensioni comportamentali dell'utente per richiedere il ricalcolo del rischio.
5.  **Risposta OPA (Step 8)**: OPA confronta il Risk Score restituito da Splunk con le soglie massime consentite (es. rischio > 50 = DENY).
6.  **Enforcement (Step 9-18)**: Envoy riceve l'esito da OPA:
    *   Se **ALLOW**: la richiesta prosegue verso il backend API e MongoDB (L7 proxy).
    *   Se **DENY**: la richiesta viene troncata istantaneamente restituendo un `403 Forbidden`.
7.  **Log SIEM (Step 13/15)**: OPA genera un log strutturato (JSON) con tutti i dettagli della decisione presa, incluso il Trust Score calcolato. Fluent Bit raccoglie questo log e lo immagazzina nell'indice `main` di Splunk per fini di auditing e visualizzazione.

---

## 3. L'Identità del Dispositivo e Hardware Attestation (Slide 8)

Un requisito critico (*Tips and Tricks*) menzionato nelle slide riguarda la gestione dell'identità del dispositivo fisico, che può essere ottenuta in modo affidabile solo se è presente un chip crittografico dedicato (es. Intel TPM o Apple Secure Enclave).

La nostra implementazione gestisce esplicitamente questo paradigma tramite due scenari simulati:
*   **Alice (Presenza di Hardware Dedicato)**: Il certificato X.509 di Alice include un'estensione OID custom (`1.3.6.1.4.1.9999.1`) che rappresenta la firma crittografica del TPM. OPA riconosce l'OID e promuove il dispositivo allo stato di *"Workstation Ospedaliera Sicura"*. Questo garantisce ad Alice l'accesso a dati critici e alza la sua tolleranza al rischio comportamentale.
*   **Bob (Assenza di Hardware Dedicato)**: Il certificato di Bob, seppur crittograficamente valido ai fini dell'autenticazione utente (mTLS ha successo), non possiede il binding al TPM. In assenza di hardware fidato, OPA de-classa il dispositivo a *"Sconosciuto"* (basandosi solo sul fingerprint software JA3). A causa di ciò, le policy dinamiche gli negheranno a priori l'accesso alle cartelle sensibili.

---

## 4. Valore Aggiunto: Dashboard e Simulazione Interattiva

Oltre all'implementazione silente dei proxy e delle regole, il progetto include un **Client Frontend interattivo (Dashboard Ospedaliera)**. Questo fornisce un metodo eccellente per dimostrare in tempo reale e visivamente le funzionalità dell'architettura al momento della presentazione:

*   **Attacchi Comportamentali (SQL Injection)**: La barra di ricerca del client permette di scatenare volontariamente comportamenti anomali (es. cercando `DROP TABLE`). Questo innescherà istantaneamente il blocco dell'accesso da parte del Machine Learning (Splunk), mostrando l'efficacia del *Trust Score dinamico*.
*   **Attacchi di Rete (Lateral Movement)**: La console hacker nascosta integrata nella dashboard (`Ctrl + Shift + D`) permette di simulare un tentativo di by-pass di Envoy. La console mostrerà come il firewall NFTables intercetta e distrugge il pacchetto a livello di rete (Livello 3/4), prima ancora che raggiunga l'applicazione.
