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
Dovresti visualizzare la tabella con i 10.000 record di traffico simulato.

---

## 3. Addestramento del Trust Model (La Query)
Ora bisogna "insegnare" a Splunk come valutare il rischio basandosi sulle 6 dimensioni del progetto Zero Trust.

Esegui questa query esatta:
```spl
| inputlookup simulated_traffic.csv
| fit RandomForestRegressor "rischio" from user, software, device, network, action, resource into trust_model
```

**Cosa fa questa query:**
- Addestra un algoritmo *RandomForest* a prevedere il valore della colonna "rischio".
- Salva in automatico il modello matematico all'interno di Splunk chiamandolo `trust_model`.
- Aggiunge una colonna a schermo `predicted(rischio)` per permetterti di valutare subito la precisione delle predizioni.

Da questo esatto momento, il motore ML è attivo e pronto a ricevere le richieste in tempo reale da OPA!

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
