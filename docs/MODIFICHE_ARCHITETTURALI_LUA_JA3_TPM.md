# Revisione Architetturale: Envoy Lua, TPM e JA3 Fallback

Questo documento descrive le modifiche apportate per allineare l'implementazione pratica del progetto "Zero Trust Architecture 2026" con i requisiti formali definiti nelle specifiche architetturali (PDF). 

Sono state risolte due criticità principali: il posizionamento errato del firewall L7 (Lua) e l'applicazione rigida delle policy hardware (TPM) che inibiva l'uso del fallback software (JA3).

---

## 1. Rimozione dello Script Lua (DPI L7) e Ricollocamento in OPA

### Il Problema Originale
Il diagramma di progetto prevedeva un filtro "Deep Packet Inspection" al Livello 7 tramite uno script Lua (`envoy.filters.http.lua`) per analizzare il payload delle query al database e bloccare operazioni distruttive (es. `db.utenti.find({ eta: 30 })` o `dropDatabase`).
Tuttavia, nell'implementazione originale, questo script era posizionato nel listener HTTP delle Web API, rendendolo **inutile per le connessioni TCP native dirette a MongoDB** sulla porta 27017 (poiché Envoy non supporta script Lua nativi sul traffico BSON di Mongo). Il blocco delle query malevole era perciò solo "simulato" dal backend Python.

### La Soluzione Adottata
- **Rimozione:** Lo script fittizio `lua_script.lua` è stato eliminato dal progetto ed rimosso dal file `envoy.yaml`.
- **Integrazione in OPA (PDP):** La logica di Deep Packet Inspection è stata trasferita in **OPA** (`rules.rego`). Envoy utilizza ora nativamente il modulo `envoy.filters.network.mongo_proxy` per estrarre la collezione, l'operazione e il payload della query BSON, e li trasmette ad OPA sotto forma di metadati (`input.attributes.metadataContext`).
- **Policy Aggiornata:** In `rules.rego` è stata creata la variabile `l7_dpi_block` che intercetta i payload malevoli (es. `dropdatabase`) e risponde con un "DENY" immediato. Questo rappresenta una DPI reale sul traffico nativo del database.

---

## 2. Risoluzione della Policy TPM e Fallback su JA3

### Il Problema Originale
Le slide del progetto specificavano chiaramente: *"When the certificate is not tied to the hardware (does not contain a hardware attestation) use only the software fingerprint (JA3)"*. 
L'implementazione originale ignorava questo requisito: la policy OPA in `rules.rego` imponeva in modo stringente il check booleano `is_tpm` per concedere un "ALLOW", **bloccando in modo incondizionato chiunque fosse sprovvisto del chip hardware** (es. il client Bob), vanificando lo scopo del calcolo del JA3.

### La Soluzione Adottata
- Le regole in `rules.rego` sono state riscritte implementando una **Tolleranza Dinamica al Rischio**.
- È stato introdotto il vero **Fallback su JA3**:
  1. Se il certificato **possiede l'OID del TPM**: L'identità hardware è verificata e garantita. OPA tollera un rischio più elastico generato da Splunk (es. `<= 50` da rete interna).
  2. Se il certificato **NON possiede l'OID del TPM** (come per il client Bob): L'identità hardware è assente, si estrae solo la "software identity" tramite **JA3**. Essendo questo meno affidabile, OPA permette comunque l'accesso, ma abbassa drasticamente la soglia di rischio consentita (es. `<= 30`).
  3. L'accesso da reti esterne (es. client Charlie) senza TPM viene invece bloccato a prescindere, innalzando il rigore Zero Trust sulle connessioni remote.

Queste modifiche hanno reso l'infrastruttura coerente con lo stato dell'arte e fedele al 100% alle specifiche progettuali fornite, rimpiazzando meccanismi simulati con un vero enforcement Zero Trust e DPI a livello di database.
