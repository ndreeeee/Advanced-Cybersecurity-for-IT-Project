# 📝 TODO List: Cosa manca per completare ZTA 2026

Basato sull'analisi dettagliata del PDF del Prof. Spalazzi (Slide 3-9).

## 1. Gestione Identità (Identity Engine)
Il PDF pone un'enfasi fortissima sull'identità hardware (TPM) e software (JA3).
- [ ] **Esecuzione PKI**: Lanciare `generate_identities.py` per creare i certificati con OID custom (Slide 8).
- [ ] **Fingerprinting JA3**: Configurare Envoy affinché estragga l'hash JA3 del client e lo passi a OPA come parametro di valutazione (Slide 3, Punto 2).

## 2. Policy Enforcement Point (Envoy PEP)
Envoy deve agire come un firewall intelligente per il database.
- [ ] **BSON Metadata Extraction**: Verificare che il filtro `mongo_proxy` stia correttamente estraendo i comandi (es. `find`) e le collezioni (es. `patients`) per passarli a OPA (Slide 3, Punto 4).
- [ ] **L7 Firewall (Lua)**: Scrivere la logica in `lua_script.lua` per ispezionare il payload della query e bloccare richieste sospette (es. tentativi di dump massivo o filtri non autorizzati) (Slide 3, Punto 9).

## 3. Policy Decision Point (OPA PDP)
OPA non deve solo guardare le regole statiche, ma deve interrogare il SIEM.
- [ ] **Integrazione OPA-Splunk**: Implementare la logica (tramite `http.send` in Rego o un sidecar) affinché OPA possa chiedere a Splunk: *"Qual è la statistica di rischio per questo utente/device/comando?"* (Slide 3, Punto 6).

## 4. Sensori di Rete (Firewall & IDS)
- [ ] **Regole NFTables**: Definire il file di configurazione per `nftables-firewall` che sostituisca definitivamente IPTables (Slide 6).
- [ ] **Firma Snort per MongoDB**: Aggiornare `local.rules` con pattern specifici per il protocollo MongoDB (es. rilevamento di tentativi di bypass autenticazione o attacchi al protocollo binario).

## 5. Simulatore Client (Test End-to-End)
Il simulatore attuale è obsoleto (usa `curl` per chiamate web).
- [ ] **Migrazione al protocollo Mongo**: Aggiornare `simulator.sh` (o creare uno script Python) affinché i client (Alice e Bob) si connettano ad Envoy usando un **Client MongoDB**.
- [ ] **mTLS Enforcement**: Configurare i client affinché presentino i rispettivi certificati (`alice.crt`, `bob.crt`) durante la connessione, altrimenti Envoy li bloccherà al punto 1 della slide 3.

## 6. Trust Score Engine (PDP Python)
- [x] **OPA ↔ Splunk ↔ MongoDB**: `trust_engine.py` + `rules.rego` + servizio `trust-engine` in compose. `pdp.py` è solo stub legacy; policy store su `hospital_db.identities`.

---
> [!IMPORTANT]
> Il punto più critico e innovativo richiesto dal prof quest'anno è il **punto 6 della Slide 3**: OPA che interroga Splunk per decidere l'autorizzazione. Questa è la vera integrazione SIEM-PDP.
