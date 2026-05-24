# Checklist Requisiti Progetto ZTA 2026 (Prof. Spalazzi)

Questa checklist mappa i requisiti estratti dal documento `Adv-2026-Project.pdf` con l'implementazione attuale della nostra infrastruttura Zero Trust.

## 1. Stack Tecnologico Richiesto
- [x] **Envoy Proxy**: Implementato come Policy Enforcement Point (PEP). Gestisce la terminazione mTLS (porta 8443) e inoltra le richieste di autorizzazione a OPA tramite il filtro `ext_authz`.
- [x] **OPA (Open Policy Agent)**: Implementato come Policy Decision Point (PDP). Valuta le policy scritte in Rego (`rules.rego`) analizzando le identità (certificati) e interrogando Splunk per il calcolo del rischio.
- [x] **Splunk**: Implementato come SIEM/motore di Machine Learning. Raccoglie i dati e calcola il `risk_score` basato sulle azioni dell'utente, l'impronta del software e lo stato del dispositivo.
- [x] **NFTables**: Implementato come Firewall L3/L4. La configurazione blocca tutto il traffico diretto al backend (`default deny`) e fa port forwarding (DNAT) solo verso Envoy, garantendo la micro-segmentazione.
- [x] **Snort**: Implementato come Network Intrusion Detection System (NIDS). Analizza il traffico di rete alla ricerca di pattern malevoli.
- [x] **MongoDB**: Implementato come Data Tier (Risorsa). Memorizza le cartelle cliniche dei pazienti ed è accessibile solo tramite la Web API protetta.

## 2. Flusso Zero Trust Architecture (L7)
- [x] **Autenticazione mTLS (Step 1)**: I client si autenticano verso Envoy utilizzando certificati crittografici.
- [x] **Estrazione Identità (Step 2/4)**: Envoy estrae l'identità dell'utente (CN del certificato), il fingerprint del software (JA3) e l'identità del dispositivo (TPM).
- [x] **Autorizzazione Zero Trust (Step 3/5)**: OPA riceve la richiesta gRPC da Envoy e valuta se consentire l'inoltro al backend.
- [x] **Integrazione Statistiche/Rischio (Step 6/7)**: OPA interroga Splunk inviando i dati estratti per ottenere una stima in tempo reale del rischio.
- [x] **Enforcement (Step 8-18)**: Envoy riceve la decisione (ALLOW/DENY) da OPA. Se ALLOW, la richiesta arriva all'API Python e poi a MongoDB. Se DENY, l'accesso viene bloccato (Errore 403 HTTP).

## 3. Identità del Dispositivo (Tips & Tricks)
- [x] **Hardware Attestation (TPM)**: Il sistema simula il controllo di un Trusted Platform Module (es. Intel TPM o Apple Secure Enclave). 
    - *Implementazione:* Nello scenario attuale, il client di Alice invia l'attestazione TPM valida, mentre il client di Bob non ce l'ha, venendo de-classato a rischio maggiore.
- [x] **Software Fingerprint (JA3)**: Utilizzato come fallback o parametro aggiuntivo per identificare il client quando il TPM è assente o per l'analisi comportamentale in Splunk.

## 4. Fasi di Sviluppo (Draft plan)
- [x] **1. Install tools**: Tutti i container (Envoy, OPA, Splunk, MongoDB, Snort, Firewall, API, Client) sono containerizzati tramite Docker Compose.
- [x] **2. Define policies**: Le policy Zero Trust sono definite in modo dichiarativo in `rules.rego`.
- [x] **3. Develop PDP and PEP**: Il binding tra Envoy e OPA è perfettamente funzionante tramite `envoy.yaml`.
- [x] **4. Test**: Abbiamo sviluppato un Frontend (Dashboard Medica) per testare visivamente e dinamicamente l'architettura. Sono stati implementati molteplici scenari di test:
    - **Controllo Accessi Base:** Bob bloccato vs Alice autorizzata.
    - **Insider Threat (SQL Injection):** Alice bloccata dinamicamente da Splunk/OPA a Livello 7 a causa di comportamento anomalo.
    - **Lateral Movement (Bypass Firewall):** Attacco bloccato a Livello 4 da nftables.

---
> [!TIP]
> **Stato Progetto:** Il progetto rispetta il **100%** dei requisiti tecnici richiesti per la consegna. La UI avanzata per testare gli scenari costituisce un eccellente valore aggiunto per la presentazione.
