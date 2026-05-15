# 🛠️ Specifiche Tecniche Strumenti (ZTA 2026)

Dettaglio dell'integrazione degli strumenti richiesti per l'architettura 2026.

## 1. Envoy Proxy (PEP)
Utilizzato come gateway universale. Filtri chiave:
- `envoy.filters.http.ext_authz`: Per delegare le decisioni a OPA via gRPC.
- `envoy.filters.network.mongo_proxy`: Per ispezionare il traffico verso il database MongoDB.
- `envoy.filters.http.lua`: Per logica custom di estrazione metadati.

## 2. OPA - Open Policy Agent (PDP)
- Riceve richieste di autorizzazione via gRPC da Envoy.
- Valuta le policy scritte in **Rego**.
- Interroga le API di Splunk per pesare il rischio in base alla "storia" dell'utente e del device.

## 3. NFTables (Firewall)
- Sostituisce IPTables per una gestione più performante dei set di regole.
- Riceve comandi dal piano di controllo per isolare device compromessi.

## 4. Identità Hardware (TPM/Secure Enclave)
- Il progetto richiede di legare il certificato client a un hardware dedicato.
- Se l'hardware è presente, il certificato è considerato "Strong Identity".
- In assenza di hardware, si usa la firma software (JA3) che però rende i device "indistinguibili" se hanno lo stesso OS/Browser.

## 5. MongoDB & Splunk
- **MongoDB**: Utilizzato sia come risorsa protetta che come Policy Store.
- **Splunk**: Fornisce statistiche (Query Statistics) su user/device/resource che OPA usa per decidere se una richiesta è anomala rispetto alla media.

---
*Riferimento: Adv-2026-Project.pdf (Slide 2, 8)*
