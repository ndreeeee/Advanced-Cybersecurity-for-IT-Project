# Documentazione degli Scenari di Simulazione (ZTA 2026)

Questo documento spiega nel dettaglio come testare e dimostrare l'infrastruttura Zero Trust Architecture implementata per il progetto. Le interfacce web sviluppate permettono di visualizzare dinamicamente le reazioni dei componenti di sicurezza (Envoy PEP, OPA PDP, Splunk MLTK e Firewall) in risposta a diverse minacce.

---

## 🟢 Livello 1: Autenticazione e Verifica dell'Identità (Il caso Alice vs Bob)

Il primo livello dimostra l'implementazione del concetto *Device & Identity Verification*. In un sistema tradizionale, chiunque possieda le credenziali (username e password) può accedere al sistema. Nel nostro approccio ZTA, le credenziali sono solo il punto di partenza.

### Come testarlo:
1. **Accesso Legittimo (Alice)**: Collegandosi a `http://localhost:8081` si utilizza il client di Alice. Cliccando su "Accedi al Portale", il sistema effettua l'handshake mTLS usando il certificato di Alice. Envoy estrae i campi del certificato e OPA valuta la presenza dell'OID `1.3.6.1.4.1.9999.1` (simulazione del chip TPM hardware). Dato che Alice usa un PC aziendale sicuro, l'accesso è **concesso** e può visualizzare i pazienti e le cartelle cliniche.
2. **Accesso Negato (Bob)**: Collegandosi a `http://localhost:8082` si utilizza il client di Bob. Sebbene anche lui "conosca" la password e invii una richiesta formalmente corretta, il suo certificato è sprovvisto dell'estensione TPM (simulando un dispositivo personale non autorizzato, BYOD non sicuro). OPA intercetta la richiesta tramite Envoy e restituisce un **DENY** immediato. L'interfaccia mostrerà nativamente l'errore `403 Forbidden - Access Denied`.

---

## 🔴 Livello 2: Rilevamento Anomalie e Insider Threat (Il Modello ML)

Il secondo livello dimostra la *Continuous Authentication* e il *Trust Score dinamico*. Anche se un utente (Alice) ha un dispositivo fidato, le sue azioni continuano ad essere monitorate per prevenire minacce interne (Insider Threat).

### Come testarlo:
1. Accedere alla dashboard tramite il client di Alice (`localhost:8081`).
2. Nella barra di ricerca in alto a destra, inserire una query normale (es. `Mario`): la ricerca non sortirà effetti negativi sul punteggio di fiducia.
3. **Simulazione Attacco SQLi**: Inserire nella barra di ricerca un payload malevolo (es. `DROP TABLE patients;` o includere la parola `DELETE`). L'applicazione invierà una richiesta sospetta al backend. 
4. **Cosa succede dietro le quinte**: Splunk MLTK (simulato nel nostro web-api) rileva l'anomalia comportamentale (una richiesta distruttiva su una risorsa API da parte di un medico). Il **Trust Score** della richiesta schizza a valori altissimi (rischio > 50). OPA riceve questo score e, nonostante il certificato di Alice e il suo TPM siano validi, blocca la richiesta sul nascere, restituendo un errore ZTA a schermo.

---

## 🏴‍☠️ Livello 3: Movimento Laterale e Bypass del Firewall di Rete (L3/L4)

L'ultimo livello dimostra la robustezza dei confini di micro-segmentazione. Un attaccante che ha compromesso un container (es. il client) potrebbe tentare di aggirare il proxy ZTA (Envoy) e colpire direttamente le API di backend (MongoDB o Web-API).

### Come testarlo:
1. Accedere alla dashboard di Alice.
2. Premere la combinazione segreta `Ctrl + Shift + D` per aprire la **Console di Debug (Terminale Hacker)** nascosta nell'interfaccia.
3. Inserire il comando `curl http://backend-api:8000/api/patients` e premere Invio.
4. **Cosa succede dietro le quinte**: Stai dicendo al container del client di scavalcare Envoy e fare una richiesta HTTP diretta al backend. Tuttavia, il traffico passa attraverso la rete gestita dal Firewall L3/L4 (nftables). Il firewall è istruito per droppare qualsiasi connessione al backend che non provenga esclusivamente dall'IP del container Envoy. La richiesta va in timeout o viene scartata (DROP), e il terminale mostrerà un `[ERRORE DI RETE]`.

---

Questi scenari dimostrano i pilastri della Zero Trust: **non fidarsi di nulla (né rete, né credenziali, né dispositivo) e verificare continuamente ogni singola transazione.**
