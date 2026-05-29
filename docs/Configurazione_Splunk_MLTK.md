# Configurazione Iniziale di Splunk MLTK per Zero Trust

Questa guida descrive i passaggi da eseguire **una tantum** (ora che abbiamo configurato i volumi persistenti su Docker) per preparare l'ambiente di Machine Learning in Splunk.

## 1. Installazione degli Add-on

Il motore di Machine Learning richiede due pacchetti ufficiali.

**Download (da splunkbase.splunk.com):**
1. Scarica **Python for Scientific Computing**. Assicurati di selezionare la versione per **Linux 64-bit**.
2. Scarica **Splunk Machine Learning Toolkit (MLTK)** (oppure il nuovo *Splunk AI Toolkit*). Scegli sempre Linux se richiesto.

**Procedura di caricamento:**
1. Accedi all'interfaccia web di Splunk (`http://localhost:8000`) usando le credenziali `admin` / `<TUA_PASSWORD>` (definita nel file `.env`).
2. Nella barra laterale di sinistra (vicino alla scritta "Apps"), clicca sull'icona a forma di **ingranaggio** (Manage Apps).
3. In alto a destra, clicca su **Install app from file**.
4. Carica il primo file (`.spl` o `.tgz`) e premi *Upload*.
5. Ripeti il processo per il secondo file.
6. *Nota: Se Splunk ti chiede di riavviare il sistema tramite un prompt giallo in alto, clicca su "Restart Now".*

---

## 2. Verifica del Dataset
Grazie al volume Docker che abbiamo configurato, il file `simulated_traffic.csv` è già mappato internamente a Splunk come Lookup Table.
Per verificare che venga letto correttamente, vai in **Search & Reporting** ed esegui:
```spl
| inputlookup simulated_traffic.csv
```
Dovresti visualizzare la tabella con i 10.000 record di traffico simulato contenenti **13 colonne**:
- **6 Dimensioni ZTA:** `user`, `software`, `device`, `network`, `action`, `resource`
- **6 Feature Comportamentali:** `failed_logins`, `hour_of_day`, `is_night`, `session_freq`, `sensitivity_level`, `days_inactive`
- **Target:** `rischio` (calcolato deterministicamente tramite somma pesata dei fattori di rischio)

---

## 3. Addestramento del Trust Model (La Query)
Ora bisogna "insegnare" a Splunk come valutare il rischio basandosi sulle 6 dimensioni ZTA del progetto **più** le 6 feature comportamentali aggiuntive per la *Continuous Evaluation*.

Esegui questa query esatta:
```spl
| inputlookup simulated_traffic.csv
| fit GradientBoostingRegressor "rischio" from user, software, device, network, action, resource, failed_logins, hour_of_day, is_night, session_freq, sensitivity_level, days_inactive into trust_model
```

**Cosa fa questa query:**
- Addestra un algoritmo *Gradient Boosting* a prevedere il valore della colonna "rischio" utilizzando 12 feature (6 identitarie + 6 comportamentali).
- Il *GradientBoostingRegressor* è stato scelto al posto del *RandomForestRegressor* perché gestisce in modo superiore le interazioni tra feature categoriche (es. user, device) e numeriche continue (es. `failed_logins`, `session_freq`), catturando pattern complessi come "utente interno + 3 login falliti + orario notturno → rischio altissimo".
- Salva in automatico il modello matematico all'interno di Splunk chiamandolo `trust_model`.
- Aggiunge una colonna a schermo `predicted(rischio)` per permetterti di valutare subito la precisione delle predizioni.

**Le 6 feature comportamentali e il loro significato:**

| Feature | Tipo | Significato ZTA |
|---|---|---|
| `failed_logins` | int (0-10) | Tentativi di autenticazione falliti nelle ultime 24h |
| `hour_of_day` | int (0-23) | Ora della richiesta |
| `is_night` | bool (0/1) | Accesso in orario notturno (22:00-06:00) |
| `session_freq` | int (1-50) | Sessioni dell'utente nell'ultima ora |
| `sensitivity_level` | int (1-3) | Sensibilità della risorsa (1=bassa, 3=alta) |
| `days_inactive` | int (0-365) | Giorni dall'ultima autenticazione riuscita |

Da questo esatto momento, il motore ML è attivo e pronto a ricevere le richieste in tempo reale da OPA!

> **Nota:** Le feature comportamentali vengono calcolate e iniettate in tempo reale dal proxy Web-API (`main.py`) prima di inoltrare la query a Splunk. OPA e `rules.rego` restano invariati e continuano a inviare le 6 dimensioni ZTA originali.

---

## 4. Condivisione Globale del Modello (FONDAMENTALE)
I modelli generati tramite il comando `fit` vengono salvati di default come privati per l'utente che ha eseguito la query (solitamente `admin`), all'interno dell'app (es. `Search`). Poiché il proxy dell'API comunica via background, **se il modello rimane privato l'API restituirà un errore**.

Per rendere il modello visibile all'API:
1. Dal menu in alto su Splunk, clicca su **Settings** (Impostazioni) > **Lookups**.
2. Clicca su **Lookup table files**.
3. Cerca il file `__mlspl_trust_model.mlmodel`.
4. Sotto la colonna *Sharing*, clicca su **Permissions**.
5. Modifica il permesso per Object should appear in: scegliendo **Global** anziché *Keep private*.
6. Assicurati che il ruolo `admin` o `Everyone` abbia permessi di Read (lettura).
7. Clicca su **Save**.

Questo garantirà che le chiamate esterne (tramite Python / Web API) possano applicare il modello (comando `apply`) senza incorrere in restrizioni di visibilità.
