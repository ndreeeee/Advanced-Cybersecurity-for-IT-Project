# Checklist Implementazione — Zero Trust Architecture 2026

---

## 1. Envoy (Policy Enforcement Point)

- [x] Listener MongoDB sulla porta 27017
- [x] Listener HTTP sulla porta 8443
- [x] mTLS obbligatorio su entrambi i listener (`require_client_certificate: true`)
- [x] TLS Inspector con fingerprinting JA3 abilitato
- [x] Filtro `mongo_proxy` con emissione di metadati dinamici (operazione + collezione)
- [x] Filtro `ext_authz` L4 (gRPC verso OPA) per il traffico MongoDB
- [x] Filtro `header_mutation` per iniettare l'hash JA3 negli header HTTP
- [x] Filtro `lua` come firewall L7 (blocco `/api/patients/sensitive` e `DELETE`)
- [x] Filtro `ext_authz` L7 (gRPC verso OPA) per il traffico HTTP
- [x] Filtro `router` per l'instradamento finale verso i backend
- [x] Certificato client inviato a OPA (`include_peer_certificate: true`)
- [x] Access log JSON strutturati con le 6 dimensioni ZTA (user, JA3, device, IP, risorsa, authz)
- [x] Cluster MongoDB, Web API e OPA definiti correttamente
- [x] Comunicazione gRPC (HTTP/2) verso OPA

---

## 2. OPA (Policy Decision Point)

- [x] Deny-by-default (`default allow := false`)
- [x] Riconoscimento automatico del tipo di traffico (HTTP vs MongoDB)
- [x] Estrazione dell'identità utente dal campo `principal` del certificato mTLS
- [x] Estrazione del fingerprint JA3 dai metadati del TLS Inspector
- [x] Fallback JA3 via header `x-client-fingerprint` per il traffico HTTP
- [x] Verifica del TPM tramite parsing X.509 e controllo OID `1.3.6.1.4.1.9999.1`
- [x] Estrazione dell'IP sorgente (con supporto `X-Forwarded-For`)
- [x] Estrazione della risorsa (path HTTP o collezione MongoDB)
- [x] Estrazione del comando (metodo HTTP o operazione MongoDB)
- [x] Deep Packet Inspection: blocco query con `sensitive_notes`, `dropdatabase`, `deleteall`
- [x] Integrazione con Splunk MLTK via `http.send` verso il Web API proxy
- [x] Soglie di rischio adattive:
  - [x] Rete interna + TPM: rischio ≤ 50
  - [x] Rete interna + solo JA3: rischio ≤ 30
  - [x] Rete esterna + TPM: rischio ≤ 10
  - [x] Rete esterna + no TPM: accesso sempre negato
- [x] Logging JSON strutturato con tutte le dimensioni (ALLOW e DENY)
- [x] Plugin `envoy_ext_authz_grpc` sulla porta 9191

---

## 3. NFTables (Firewall L3/L4)

- [x] IP forwarding abilitato (`net.ipv4.ip_forward=1`)
- [x] Risoluzione dinamica dell'IP di Envoy all'avvio
- [x] Port forwarding DNAT verso Envoy (porta 8443)
- [x] Masquerade (SNAT) per il traffico di ritorno
- [x] Log + DROP del traffico diretto alla porta 8000 (bypass Envoy)
- [x] Set `denylist` per ban dinamici con regole di DROP attive
- [x] Management API con endpoint `/ban` e `/status`
- [x] Logging su file per Fluent Bit (`/var/log/nftables/firewall.log`)
- [x] `CAP_NET_ADMIN` abilitato nel Docker Compose

---

## 4. Snort (NIDS)

- [x] Condivisione dello stack di rete di Envoy (`network_mode: service:envoy-pep`)
- [x] Regola per rilevamento scansioni di rete (SYN scan, threshold 20 pacchetti in 10s)
- [x] Regola per tentativo di accesso diretto a MongoDB (porta 27017)
- [x] Output log su volume condiviso con Fluent Bit (`/var/log/snort/`)

---

## 5. MongoDB (Database Risorsa)

- [x] 10 pazienti con dati clinici realistici e note sensibili
- [x] Collezione `identities` con trust score per Alice e Bob
- [x] Collezione `trust_history` con indice temporale
- [x] Utente di servizio `zta_service_user` con ruolo `readWrite`
- [x] Isolamento nella rete `backend-net` (non raggiungibile direttamente dai client)

---

## 6. Splunk (SIEM + Machine Learning)

- [x] HTTP Event Collector (HEC) abilitato con token
- [x] Dataset di training `simulated_traffic.csv` montato come lookup table (10.000 record)
- [x] Modello `trust_model` (RandomForestRegressor sulle 6 dimensioni ZTA)
- [x] Ricezione log da tutti i 5 componenti via Fluent Bit
- [x] Web API proxy `/api/ml/predict` per le richieste di OPA
- [x] Mapping centralizzato dei valori ZTA → etichette del dataset di training

---

## 7. PKI e Certificati

- [x] Root CA proprietaria (`ZTA Hospital Trust Root CA`)
- [x] Certificato Envoy (server)
- [x] Certificato Alice con estensione TPM OID (`1.3.6.1.4.1.9999.1`)
- [x] Certificato Bob senza estensione TPM (solo software/JA3)
- [x] Certificato Charlie con TPM (client esterno)
- [x] SPIFFE ID nei SAN di tutti i certificati (`spiffe://zta.hospital/ns/default/sa/client-{name}`)
- [x] File `.pem` combinati (cert + key) per pymongo

---

## 8. Segregazione di Rete

- [x] `frontend-net` (10.0.1.0/24) — Alice, Bob, Firewall
- [x] `backend-net` — MongoDB, Web API, Envoy
- [x] `control-plane-net` — OPA, Splunk, Fluent Bit
- [x] `external-net` (192.168.100.0/24) — Charlie
- [x] Client confinati nelle rispettive zone di rete
- [x] Envoy è l'unico nodo che attraversa tutte le reti

---

## 9. Pipeline di Logging (Fluent Bit)

- [x] Raccolta log da Snort (`/var/log/snort/alert_json.txt`)
- [x] Raccolta log da MongoDB (`/var/log/mongodb/mongod.log`)
- [x] Raccolta log da Envoy (`/var/log/envoy/access.log`)
- [x] Raccolta log da OPA (`/var/log/opa/decision.log`)
- [x] Raccolta log da NFTables (`/var/log/nftables/firewall.log`)
- [x] Filtro grep per estrarre solo i log `[OPA-PDP]`
- [x] Parser regex per il payload JSON di OPA
- [x] Iniezione del campo `host` per ogni sorgente
- [x] Output unico verso Splunk HEC (porta 8088, TLS)

---

## 10. Client di Test

- [x] Alice (porta 8081) — client legittimo, rete interna, certificato con TPM
- [x] Bob (porta 8082) — client sospetto, rete interna, certificato senza TPM
- [x] Charlie (porta 8083) — client esterno, rete untrusted, certificato con TPM
- [x] Interfaccia web con pagina di login e dashboard
- [x] Richieste mTLS verso Envoy tramite il Firewall
- [x] Simulazione bypass (richiesta diretta alla porta 8000)
- [x] Header `X-Forwarded-For` con IP reale del container
