# Riassunto: Progetto "Zero Trust Architecture" 2026

**Autore slide:** Prof. Luca Spalazzi (Dipartimento di Ingegneria dell'Informazione, Università Politecnica delle Marche).

---

## 1. Obiettivo e Tecnologie
Il progetto richiede l'implementazione di un'architettura **Zero Trust (ZTA)** per la protezione di un database.
- **Gruppi:** 4-5 persone.
- **Tecnologie Obbligatorie:** Envoy (PEP), OPA (PDP), Splunk (SIEM), NFTables (Firewall di Rete L3/L4), Snort (NIDS).
- **Database (Risorsa):** MongoDB (o in alternativa ProxySQL + MySQL).

---

## 2. Le 6 Dimensioni della Zero Trust (Tupla ZTA)
Ogni singola richiesta effettuata dal client viene scomposta in 6 identità fondamentali, che formeranno la tupla passata a OPA e Splunk:
1. **u (User Identity):** Identità dell'utente (es. `mario.rossi`), estratta solitamente dal Common Name (CN) del certificato.
2. **s (Software Identity):** Fingerprint del client/OS. Il PDF suggerisce esplicitamente di usare l'hash **JA3** scambiato durante l'handshake TLS.
3. **d (Device Identity):** Identità del dispositivo fisico. *Vedi Sezione "Tips and Tricks".*
4. **n (Network Identity):** Indirizzo IP sorgente della rete.
5. **a (Action):** Operazione effettuata sul database (es. `find()`).
6. **r (Resource):** Risorsa interrogata nel database (es. la collection `utenti`).

---

## 3. Flusso dell'Architettura (Sequence & Deployment Diagram)
Il PDF chiarisce molto bene, attraverso diagrammi UML e disegni alla lavagna, l'esatto flusso che ogni pacchetto deve compiere.

1. **Connessione Iniziale (Livello Rete):** Il traffico passa per il firewall L3/L4 (NFTables) e viene analizzato dal NIDS (Snort). Entrambi inviano costantemente i loro log a Splunk.
2. **Handshake e Parsing (Envoy - PEP):** 
   - Il Client effettua un handshake **mTLS** con Envoy.
   - Envoy funge da terminatore TLS e L7 Proxy. Estrae l'identità crittografica dal certificato (User, Device) e il JA3 (Software).
   - Envoy analizza il payload BSON di MongoDB ed estrae Comando e Risorsa.
3. **Controllo Autorizzativo (OPA e Splunk - PDP):**
   - Envoy congela la richiesta e fa una chiamata gRPC a OPA passando la tupla `(u, s, d, n, a, r)`.
   - **OPA (il motore decisionale) interroga direttamente Splunk (SIEM)** passandogli la tupla.
   - **Splunk funge da calcolatore del rischio:** riceve la tupla, consulta le statistiche/modelli, calcola un livello di **"rischio"** e lo restituisce in modo sincrono a OPA.
   - OPA controlla se il rischio rientra nei parametri stabiliti (`rischio <= soglie`).
4. **Decisione Finale:**
   - OPA restituisce `ALLOW` o `DENY` a Envoy.
   - Se `ALLOW`, Envoy inoltra la query a MongoDB.
   - Envoy invia un log JSON a Splunk contenente la decisione presa e i parametri della richiesta.

---

## 4. Tips and Tricks: Gestione delle Identità
Il professore fornisce suggerimenti specifici per le identità **Software (s)** e **Device (d)**:
- L'identità del dispositivo (`d`) può essere ottenuta **solo** se si utilizza hardware dedicato integrato nel processore (es. **TPM** su Windows 11 o **Secure Enclave** su Apple Silicon). In questo caso, il certificato utente viene "legato" all'hardware tramite l'OID nel certificato.
- Se l'hardware TPM non è presente, l'identità del dispositivo non può essere verificata con certezza.
- In assenza di hardware, ci si deve affidare al fingerprint del software (**JA3**) lasciato dal client.
- **Attenzione:** Se due dispositivi diversi usano esattamente lo stesso client (es. Firefox) e lo stesso sistema operativo, avranno lo stesso JA3 e risulteranno *indistinguibili*.

---

## 5. Draft Plan suggerito
1. Installazione dei tool.
2. Definizione delle policy.
3. Sviluppo di PDP (OPA) e PEP (Envoy).
4. Fase di Test.
