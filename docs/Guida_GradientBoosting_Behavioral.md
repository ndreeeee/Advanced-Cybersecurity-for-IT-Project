# Guida al Modello di Trust Score Avanzato (Gradient Boosting con Feature Comportamentali)

Questo documento fornisce una guida completa alla configurazione, al funzionamento teorico e alla verifica del modello di **Trust Score** aggiornato per il progetto Zero Trust Architecture (ZTA). Il modello è passato da un approccio statico basato su identità (Random Forest con 6 dimensioni) a una **valutazione dinamica e continua del comportamento** utilizzando l'algoritmo **Gradient Boosting Regressor** e **12 feature complessive**.

---

## 1. Configurazione di Splunk da Zero (Guida Passo-Passo)

Per rendere il modello operativo all'interno di Splunk, consentendo al proxy Web-API (`main.py`) di interrogarlo in tempo reale, segui questa procedura dettagliata.

### A. Prerequisiti (Installazione App su Splunk)
Il motore di Machine Learning richiede due pacchetti ufficiali gratuiti, scaricabili da [Splunkbase](https://splunkbase.splunk.com/):
1. **Python for Scientific Computing** (Assicurati di scaricare la versione per **Linux 64-bit**, coerente con il container Docker di Splunk).
2. **Splunk Machine Learning Toolkit (MLTK)**.

**Procedura di caricamento:**
1. Accedi all'interfaccia di Splunk (`http://localhost:8000`) come `admin`.
2. Fai clic sull'icona a forma di **ingranaggio** (Manage Apps) accanto alla scritta "Apps" nella barra laterale sinistra.
3. Seleziona **Install app from file** in alto a destra.
4. Carica prima il file di Python for Scientific Computing e poi il file di MLTK.
5. **Riavvia Splunk** quando ti viene richiesto dal banner giallo in alto.

### B. Caricamento del Dataset
Grazie alla configurazione del volume condiviso in Docker, il file `simulated_traffic.csv` generato dal nostro script Python è già mappato all'interno di Splunk come Lookup Table.
Per verificare che venga letto correttamente, vai su **Search & Reporting** ed esegui:
```spl
| inputlookup simulated_traffic.csv
```
Dovresti visualizzare una tabella di 10.000 record con 13 colonne (12 feature + 1 target `rischio`).

### C. Addestramento del Modello (Training)
Esegui la seguente query SPL per addestrare l'algoritmo **Gradient Boosting** a prevedere il rischio basandosi sulle 12 dimensioni:
```spl
| inputlookup simulated_traffic.csv
| fit GradientBoostingRegressor "rischio" from user, software, device, network, action, resource, failed_logins, hour_of_day, is_night, session_freq, sensitivity_level, days_inactive into trust_model
```
*Nota: Al completamento della query, Splunk salverà il modello addestrato all'interno del proprio database con il nome `trust_model` e mostrerà a schermo una colonna aggiuntiva `predicted(rischio)` per misurarne le performance.*

### D. Condivisione Globale del Modello (FONDAMENTALE)
Per impostazione predefinita, Splunk salva il modello come privato dell'utente `admin`. Per consentire al proxy Web-API (che effettua le chiamate via API REST in background) di interrogarlo tramite il comando `apply`, devi renderlo pubblico:
1. Dal menu principale di Splunk, vai su **Settings** (Impostazioni) > **Lookups**.
2. Fai clic su **Lookup table files**.
3. Trova nella lista il file del modello, identificato come `__mlspl_trust_model.mlmodel`.
4. Sotto la colonna *Sharing*, fai clic su **Permissions**.
5. Cambia lo stato dell'oggetto selezionando **Global** (invece di *Keep private*).
6. Assicurati che l'utente `admin` o `Everyone` abbia permessi di **Read** (Lettura).
7. Fai clic su **Save**.

### E. Query di Verifica Rapida (Simulazione del Proxy)
Per verificare che il modello calcoli correttamente il rischio differenziando i comportamenti legittimi da quelli anomali direttamente in Splunk, puoi eseguire questi due test:

#### Test Scenario A: Utente Legittimo (Basso Rischio)
Simula Alice che accede alla risorsa di pomeriggio, da un dispositivo aziendale sicuro e senza login falliti alle spalle:
```spl
| makeresults 
| eval user="alice.medico", software="chrome_115", device="tpm_enclave_88", network="10.0.0.15", action="find", resource="pazienti", failed_logins=0, hour_of_day=14, is_night=0, session_freq=3, sensitivity_level=2, days_inactive=0 
| apply trust_model 
| rename "predicted(rischio)" as rischio 
| table user, failed_logins, is_night, rischio
```
*Output atteso: Rischio molto basso (es. <25).*

#### Test Scenario B: Attacco/Anomalia (Alto Rischio)
Simula Mario che tenta un'azione di drop su un database di configurazione critico, nel cuore della notte, tramite curl (senza TPM) e dopo 5 tentativi di login falliti nelle ultime 24 ore:
```spl
| makeresults 
| eval user="mario.rossi", software="curl", device="missing_tpm", network="1.2.3.4", action="drop", resource="config_db", failed_logins=5, hour_of_day=3, is_night=1, session_freq=25, sensitivity_level=3, days_inactive=10 
| apply trust_model 
| rename "predicted(rischio)" as rischio 
| table user, failed_logins, is_night, rischio
```
*Output atteso: Rischio estremamente alto (es. >75).*

---

## 2. RandomForest vs. Gradient Boosting: Il Confronto

Perché siamo passati da un'architettura basata su **Random Forest** a una basata su **Gradient Boosting**? Di seguito sono analizzate le differenze e i motivi ingegneristici della scelta.

| Parametro di Confronto | RandomForestRegressor | GradientBoostingRegressor |
|---|---|---|
| **Metodo di Addestramento** | **Parallelo (Bagging)**: Crea molti alberi decisionali in parallelo in modo indipendente; la predizione finale è la semplice media aritmetica di tutti gli alberi. | **Sequenziale (Boosting)**: Costruisce un albero alla volta. Ogni nuovo albero viene addestrato specificamente per correggere gli errori di stima (i residui) fatti dall'albero precedente. |
| **Ottimizzazione dell'Errore** | Cerca di ridurre la varianza complessiva del modello mediando alberi complessi (rischia l'underfitting su pattern molto specifici). | Minimizza direttamente una funzione di perdita (Loss Function) calcolando il gradiente dell'errore ad ogni step (incredibilmente preciso). |
| **Sensibilità alle Anomalie** | Tende a "smussare" le anomalie o i picchi improvvisi di rischio a causa della media complessiva della foresta. | Molto sensibile alle anomalie comportamentali. Se un comportamento devia dalla norma, il boosting penalizza pesantemente lo score. |
| **Interazione tra Feature** | Tratta le feature in modo isolato nelle diramazioni casuali degli alberi. | Eccelle nel catturare relazioni non lineari e complesse tra variabili categoriche (es. `user`) e numeriche (es. `failed_logins`, `is_night`). |

### Perché Gradient Boosting è superiore nel nostro progetto ZTA?
In un modello di valutazione continua del rischio, le variabili non agiscono da sole. Un utente che fallisce 5 login di giorno dall'ufficio ha un profilo di rischio moderato; lo stesso utente che fallisce 5 login alle 3 di notte da un IP non aziendale rappresenta una minaccia critica. 

Mentre il **Random Forest** fatica a catturare questa interazione non lineare (poiché calcola la media di alberi generati casualmente), il **Gradient Boosting** focalizza i propri alberi successivi proprio sulla correzione degli errori commessi su questi casi limite, identificando con estrema precisione le minacce complesse (pattern multi-dimensionali).

---

## 3. Logica del Rischio e Feature Comportamentali

### Perché 12 Feature invece delle 6 originali?
L'architettura Zero Trust originale basata su OPA si affidava unicamente a **6 feature identitarie** (chi sei, che software usi, da dove ti colleghi, che azione compi, su quale risorsa). Questa è una **valutazione statica del contesto di autenticazione**.

L'aggiunta di **6 feature comportamentali** abilita la **valutazione dinamica e continua**. Il sistema non si limita più a verificare "le credenziali al momento dell'ingresso", ma monitora la sessione dell'utente nel tempo.

### Tabella Completa delle Feature

| Categoria | Feature | Tipo | Descrizione e Ruolo ZTA |
|---|---|---|---|
| **Identità (ZTA)** | `user` | Categorico | Identificativo univoco del soggetto. |
| **Identità (ZTA)** | `software` | Categorico | User-Agent o hash dell'applicazione utilizzata (es. browser vs script). |
| **Identità (ZTA)** | `device` | Categorico | Stato del dispositivo (TPM verificato, sconosciuto, ecc.). |
| **Identità (ZTA)** | `network` | Categorico | Rete o subnet di provenienza (IP interno vs IP pubblico). |
| **Identità (ZTA)** | `action` | Categorico | Operazione richiesta (find, drop, delete, update). |
| **Identità (ZTA)** | `resource` | Categorico | Asset a cui si richiede l'accesso (pazienti, cartelle cliniche, config). |
| **Comportamento (Nuovo)** | `failed_logins` | Numerico (int) | Numero di tentativi di accesso falliti (o richieste bloccate da OPA) nelle ultime 24h. |
| **Comportamento (Nuovo)** | `hour_of_day` | Numerico (int) | Fascia oraria della richiesta (0-23). |
| **Comportamento (Nuovo)** | `is_night` | Booleano (0/1) | Flag per accessi in orario notturno (22:00 - 06:00). |
| **Comportamento (Nuovo)** | `session_freq` | Numerico (int) | Frequenza delle richieste effettuate nell'ultima ora (indicatore di scripting automatico). |
| **Comportamento (Nuovo)** | `sensitivity_level`| Numerico (int) | Grado di criticità della risorsa richiesta (1=basso, 3=alto). |
| **Comportamento (Nuovo)** | `days_inactive` | Numerico (int) | Numero di giorni trascorsi dall'ultimo login andato a buon fine. |

---

### La "Formula" del Rischio (Ground Truth del Generatore di Traffico)
Il modello di regressione impara a prevedere lo score addestrandosi su un dataset generato artificialmente. La formula matematica di base che definisce il rischio reale (da `0` a `100`) risponde a una logica di **penalità a punteggio cumulativo**:

$$\text{Rischio} = \text{Base} + \Delta\text{Hardware} + \Delta\text{Rete} + \Delta\text{Login} + \Delta\text{Orario} + \Delta\text{Frequenza} + \Delta\text{Sensibilità} + \Delta\text{Inattività} + \Delta\text{Azione} + \Delta\text{Software} + \epsilon$$

Dove le singole penalità sono calcolate come segue:

1. **Stato del Dispositivo ($\Delta\text{Hardware}$):**
   * Se il dispositivo non possiede un TPM hardware verificato (`missing_tpm` o `unknown`): **$+20$**
2. **Posizione di Rete ($\Delta\text{Rete}$):**
   * Se la connessione proviene da un indirizzo IP non appartenente alla rete aziendale interna: **$+15$**
3. **Storico Sicurezza ($\Delta\text{Login}$):**
   * Accumulo per ogni tentativo fallito registrato nelle 24 ore: **$+8 \times \text{failed\_logins}$** (fino a un massimo di **$+40$**).
4. **Fattore Temporale ($\Delta\text{Orario}$):**
   * Se l'accesso avviene in orario notturno (`is_night` = 1): **$+10$**
5. **Velocità Operativa ($\Delta\text{Frequenza}$):**
   * Se la frequenza di sessione nell'ultima ora supera i 20 accessi (potenziale attacco automatizzato): **$+5$**
6. **Criticità Risorsa ($\Delta\text{Sensibilità}$):**
   * Valutazione basata sul livello di sensibilità (da 1 a 3): **$+10 \times (\text{sensitivity\_level} - 1)$** (quindi $+0$ per liv. 1, $+20$ per liv. 3).
7. **Stato Inattività ($\Delta\text{Inattività}$):**
   * Penalizzazione per utenti dormienti: **$+5$** per ogni 30 giorni di inattività accumulati.
8. **Pericolosità Operazione ($\Delta\text{Azione}$):**
   * Se l'azione comporta la cancellazione o rimozione di dati (`delete`, `drop`): **$+15$**
9. **Firma Software ($\Delta\text{Software}$):**
   * Se viene utilizzato software non standard/sospetto (es. `curl`, `nmap`): **$+5$**
10. **Fattore Rumore ($\epsilon$):**
    * Fluttuazione casuale definita da una distribuzione gaussiana: **$\pm 3$ punti** (evita l'overfitting del modello su regole eccessivamente rigide).

---

### Come funziona la Regressione
A differenza dei modelli di **classificazione** (che restituiscono solo risposte binarie come `0 = Sicuro` o `1 = Pericolo`), il nostro modello implementa una **regressione**. 

* **Output continuo:** Restituisce un punteggio numerico continuo (es. `18.4`, `52.1`, `89.7`).
* **Integrazione ZTA flessibile:** Questo punteggio viene inoltrato al motore di policy OPA. OPA può quindi implementare regole flessibili e dinamiche, come ad esempio:
  * $\text{Risk Score} \le 30 \rightarrow$ Accesso consentito senza restrizioni.
  * $30 < \text{Risk Score} \le 50 \rightarrow$ Accesso consentito ma con limitazioni (es. sola lettura) o richiesta di Multi-Factor Authentication (MFA).
  * $\text{Risk Score} > 50 \rightarrow$ Accesso negato (DENY) e blocco della sessione.

In questo modo, la sicurezza non è più un sistema rigido "dentro o fuori", ma si adatta fluidamente alla postura di sicurezza e al comportamento dell'utente in tempo reale.
