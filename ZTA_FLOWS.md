# 🔄 Flussi Logici e Autorizzazione (ZTA 2026)

Il processo di autorizzazione nel modello 2026 è più granulare e sicuro.

## 1. Fase 1: Handshake mTLS & Fingerprinting
Ogni connessione inizia con una validazione crittografica:
- **mTLS Authentication**: Envoy valida il certificato del client.
- **Identity Extraction**: Si estraggono l'identità dell'utente (CN del certificato), l'identità del device (OID specifici del TPM) e l'identità della rete (IP).
- **JA3 Fingerprint**: Se il certificato non è legato all'hardware, Envoy estrae il fingerprint JA3 per identificare univocamente lo stack software del client.

## 2. Fase 2: Estrazione Metadati del Comando
Envoy utilizza filtri specifici (es. `mongo_proxy` o filtri L7) per capire cosa sta facendo l'utente:
- Estrazione del comando (es. `find`, `transfer`).
- Estrazione della risorsa/collezione (es. `utenti`, `conti`).
- Estrazione del payload della query.

## 3. Fase 3: Verifica gRPC verso OPA
Envoy invia una richiesta `Check` gRPC a OPA contenente:
- `{ user, software (JA3), device (TPM), network_ip, resource, command }`
OPA consulta Splunk per ottenere statistiche di rischio in tempo reale e risponde con `ALLOWED` o `DENIED`.

## 4. Fase 4: Enforcement & Logging
- Se OPA approva, Envoy inoltra la richiesta al MongoDB finale.
- Se OPA nega, Envoy restituisce un errore al client.
- Ogni decisione viene loggata su Splunk per alimentare il ciclo di analisi successivo.

---
*Riferimento: Adv-2026-Project.pdf (Slide 3, 5, 6)*
