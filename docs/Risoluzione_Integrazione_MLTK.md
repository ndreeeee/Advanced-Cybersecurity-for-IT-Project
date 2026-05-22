# Risoluzione Problemi e Nuove Funzionalità: Integrazione Splunk MLTK

Questo documento riassume le problematiche affrontate e risolte durante l'integrazione finale tra OPA (Open Policy Agent), il proxy Web API e il Machine Learning Toolkit (MLTK) di Splunk per l'architettura Zero Trust.

## Problemi Risolti (Troubleshooting)

### 1. Modello MLTK Privato (Visibilità "trust_model")
- **Sintomo:** Le query via API ricevevano l'errore `Error in 'apply' command: model 'trust_model' does not exist`. OPA riceveva `500 Internal Server Error` dal proxy e applicava la policy di sicurezza predefinita (`risk = 100`, Accesso Negato).
- **Causa:** Il comando `fit` di Splunk salva i modelli `.mlmodel` in `/opt/splunk/etc/users/admin/search/lookups/` con permessi *Private*. L'API, agendo tramite chiamate remote in background, non riusciva a leggerlo.
- **Soluzione:** È stato modificato il permesso del file `__mlspl_trust_model.mlmodel` da *Private* a **Global** tramite l'interfaccia web di Splunk (Settings > Lookups), rendendolo visibile a tutti i ruoli. Questa istruzione è stata anche aggiunta alla documentazione `Configurazione_Splunk_MLTK.md`.

### 2. Disallineamento del nome della Variabile Predetta
- **Sintomo:** L'API proxy continuava a restituire `500` anche se il modello veniva trovato.
- **Causa:** L'algoritmo di regressione dello Splunk MLTK, quando riceve il comando `apply trust_model`, salva il punteggio di rischio nella colonna predefinita `predicted(rischio)`. Tuttavia, il codice in Python (`main.py`) e la query generata da OPA (`rules.rego`) cercavano il valore nella colonna finale `rischio` (che risultava vuota a causa dell'uso di `| makeresults`).
- **Soluzione:** È stata modificata la query SPL generata dinamicamente da OPA in `rules.rego` includendo il comando `| rename "predicted(rischio)" as rischio | table rischio`. In questo modo l'output restituito da Splunk ha esattamente lo stesso formato atteso dall'API Python.

### 3. Categorie Sconosciute in fase di Inferenza (Vocabolario MLTK)
- **Sintomo:** Il modello loggava nei messaggi SPL l'errore `Error in 'apply' command: No valid fields to fit or apply model to.` quando veniva valutata una richiesta in tempo reale.
- **Causa:** Il dataset utilizzato per il training (`simulated_traffic.csv`) conteneva stringhe formattate in modo specifico (es. `user="alice.medico"`, `software="chrome_115"`). Al contrario, il contesto live di Envoy/OPA inviava dati grezzi e stringhe formattate diversamente (es. `user="alice"`, `software="86dab2109182b6bbaa644647d7db2997"` hash JA3). Il modello `RandomForestRegressor` dello Splunk MLTK va in errore critico (FATAL) se riceve categorie mai viste in fase di *fit*, in quanto non può convertirle internamente.
- **Soluzione:** È stato introdotto un meccanismo di **Data Mapping** trasparente all'interno del proxy Web-API (`components/api/main.py`). La stringa SPL in arrivo da OPA viene intercettata, e i valori real-time vengono sostituiti al volo con i loro corrispettivi "sicuri" visti durante il training dal modello. 
  - *Esempio:* L'hash client-fingerprint o JA3 di Alice viene mappato su `chrome_115`.
  - *Esempio:* `user="alice"` viene mappato su `user="alice.medico"`.

---

## Nuove Funzionalità Aggiunte

1. **Proxy ML (Web-API) Riscritto:**
   - La Web-API è stata ripulita dalle vecchie implementazioni "mock" e convertita in un vero e proprio proxy Zero-Trust.
   - Comunica nativamente via API REST Splunk (`/services/search/jobs/export`), passa le credenziali, cattura il risultato e lo formatta come JSON pulito per OPA.
   - Implementa logging avanzato: ogni stringa SPL inviata viene loggata, permettendo di verificare istantaneamente se OPA sta costruendo correttamente il contesto 6D.

2. **Dinamicità delle 6 Dimensioni (ZTA 6D) in OPA:**
   - Il modulo `rules.rego` costruisce in tempo reale una query SPL `| makeresults | eval user="...", ...` iniettando tutti gli attributi HTTP.
   - L'accesso al database non è più concesso ciecamente: OPA aspetta che Splunk sputi fuori la percentuale (risk score). Se il punteggio di rischio <= 50, OPA accetta la richiesta, altrimenti attiva il Default DENY.

## Stato Finale
L'architettura **Envoy -> OPA -> WebAPI -> Splunk MLTK** comunica ora in modo robusto, inibendo automaticamente l'accesso ai client se il rischio inferito in base a comportamenti (Rete, Dispositivo TPM, Certificati) devia dallo standard (Zero Trust Adattivo).
