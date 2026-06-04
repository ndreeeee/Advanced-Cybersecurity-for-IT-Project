# Dashboard Splunk: Analisi Comportamentale e Anomalie ZTA

Questa guida descrive come configurare e implementare una dashboard Splunk avanzata per l'**analisi comportamentale**, l'**ispezione JA3** e il **clustering delle anomalie** tramite Splunk MLTK.

---

## 🚀 Come Creare la Dashboard in Splunk

Esistono due metodi per creare la dashboard e importare il codice XML. Se riscontri difficoltà a trovare il pulsante di modifica, il **Metodo A** (tramite query) è il più rapido e sicuro.

### Metodo A: Creazione da una Ricerca (Consigliato)
1. Apri la console web di Splunk (`http://localhost:8000`) ed effettua il login.
2. Vai su **Search & Reporting** e digita nella barra di ricerca la seguente query: `host="zta-opa"`
3. Esegui la ricerca. In alto a destra (sopra il grafico temporale/risultati), clicca su **Save As** (Salva come) e seleziona **Dashboard Panel** (Pannello dashboard).
4. Nella finestra popup, configura come segue:
   - **Dashboard**: Seleziona **New** (Nuovo).
   - **Dashboard Title**: `ZTA - Analisi Comportamentale e Anomalie`
   - **Dashboard XML Definition**: Seleziona **Classic Dashboards** (Simple XML). *Attenzione: Non scegliere Dashboard Studio, poiché il codice XML Simple XML non è compatibile.*
   - **Panel Title**: Inserisci un titolo provvisorio, ad esempio `Richieste Totali`.
5. Clicca su **Save** (Salva) e successivamente su **View Dashboard** (Visualizza dashboard).
6. Ora che ti trovi all'interno della dashboard, vedrai finalmente il pulsante **Edit** (Modifica) in alto a destra.
7. Clicca su **Edit** (Modifica) e poi, nella barra superiore, seleziona la voce **Source** (Sorgente).
8. Sostituisci l'intero codice autogenerato con il codice XML fornito di seguito e clicca su **Save** (Salva).

### Metodo B: Creazione dalla sezione Dashboards
1. Dal menu in alto di Splunk, vai sulla voce **Dashboards** e clicca sul pulsante **Create New Dashboard** in alto a destra.
2. Inserisci come titolo `ZTA - Analisi Comportamentale e Anomalie`.
3. Seleziona **Classic Dashboards** (Simple XML) e clicca su **Create**.
4. Una volta aperta la dashboard vuota, clicca su **Edit** in alto a destra, seleziona la modalità **Source** (Sorgente) e sostituisci il codice XML.
   *(Nota: Se non vedi il pulsante Edit, assicurati di aver aperto la dashboard cliccando sul suo nome dall'elenco, e di non trovarti ancora nella pagina riassuntiva di tutte le dashboard).*

---

## 📄 Codice XML della Dashboard (Simple XML)

Copia ed incolla questo codice nella scheda **Source** di Splunk:

```xml
<dashboard version="1.1" theme="dark">
  <label>ZTA - Analisi Comportamentale e Anomalie</label>
  <description>Monitoraggio in tempo reale del rischio utente, JA3 fingerprinting e clustering di anomalie</description>
  
  <!-- SELETTORE TEMPORALE GLOBALE (Time Picker) -->
  <fieldset submitButton="false">
    <input type="time" token="time_filter" searchWhenChanged="true">
      <label>Intervallo Temporale</label>
      <default>
        <earliest>0</earliest>
        <latest></latest>
      </default>
    </input>
  </fieldset>
  
  <!-- ROW 1: METRIC CARD DI LIVELLO ALTO -->
  <row>
    <panel>
      <single>
        <title>Richieste Totali</title>
        <search>
          <query>Decision=* | stats count</query>
          <earliest>$time_filter.earliest$</earliest>
          <latest>$time_filter.latest$</latest>
        </search>
        <option name="drilldown">none</option>
        <option name="refresh.display">progressbar</option>
      </single>
    </panel>
    <panel>
      <single>
        <title>Tasso di Blocco (Deny %)</title>
        <search>
          <query>Decision=* | stats count(eval(Decision="DENY")) as Deny, count as Total | eval percentage=round((Deny/Total)*100, 2) | fields percentage</query>
          <earliest>$time_filter.earliest$</earliest>
          <latest>$time_filter.latest$</latest>
        </search>
        <option name="drilldown">none</option>
        <option name="numberPrecision">0.00</option>
        <option name="unit">%</option>
      </single>
    </panel>
    <panel>
      <single>
        <title>Rischio Medio Registrato</title>
        <search>
          <query>Decision=* | stats avg(risk_score) as avg_risk | eval avg_risk=round(avg_risk, 1)</query>
          <earliest>$time_filter.earliest$</earliest>
          <latest>$time_filter.latest$</latest>
        </search>
        <option name="drilldown">none</option>
        <option name="rangeColors">["0x53a051","0xf8be34","0xdc4e41"]</option>
        <option name="rangeValues">[20,50]</option>
        <option name="useColors">1</option>
      </single>
    </panel>
  </row>
 
  <!-- ROW 2: ANOMALIE TEMPORALI E IMPERSONIFICAZIONE JA3 -->
  <row>
    <panel>
      <chart>
        <title>Distribuzione degli Accessi per Ora (Rilevamento Notturno)</title>
        <search>
          <query>Decision=*
| eval hour=strftime(_time, "%H")
| chart count by hour, user</query>
          <earliest>$time_filter.earliest$</earliest>
          <latest>$time_filter.latest$</latest>
        </search>
        <option name="charting.chart">column</option>
        <option name="charting.chart.stackMode">stacked</option>
        <option name="charting.legend.placement">right</option>
      </chart>
    </panel>
    <panel>
      <chart>
        <title>Correlazione Utenti vs Impronte Software (JA3)</title>
        <search>
          <query>Decision=*
| chart count by user, software</query>
          <earliest>$time_filter.earliest$</earliest>
          <latest>$time_filter.latest$</latest>
        </search>
        <option name="charting.chart">bar</option>
        <option name="charting.legend.placement">right</option>
      </chart>
    </panel>
  </row>
 
  <!-- ROW 3: ML CLUSTERING K-MEANS & ANDAMENTO DEL RISCHIO -->
  <row>
    <panel>
      <table>
        <title>Clustering delle Sessioni Utente (Outlier Detection - K-Means)</title>
        <search>
          <query>Decision=*
| stats count as FrequenzaMax, avg(risk_score) as RischioMedio by user
| join type=left user [ search Decision=DENY | stats count as LoginFalliti by user ]
| fillnull value=0 LoginFalliti
| fit KMeans k=3 RischioMedio FrequenzaMax LoginFalliti
| rename cluster as ClusterID
| eval Descrizione=case(ClusterID==0, "Profilo B: Alto Rischio (Bloccato / Sospetto)", ClusterID==1, "Profilo A: Frequenza Elevata (Scraping)", ClusterID==2, "Profilo C: Basso Rischio (Attività Ordinaria)")
| table user, RischioMedio, FrequenzaMax, LoginFalliti, ClusterID, Descrizione</query>
          <earliest>$time_filter.earliest$</earliest>
          <latest>$time_filter.latest$</latest>
        </search>
        <option name="count">10</option>
        <option name="drilldown">none</option>
      </table>
    </panel>
    <panel>
      <chart>
        <title>Andamento del Rischio Dinamico vs Soglia OPA Adattiva</title>
        <search>
          <query>Decision=*
| eval limit=if(network_internal="true", 50, 8)
| timechart span=5m max(risk_score) as "Rischio Calcolato" max(limit) as "Soglia OPA" by user</query>
          <earliest>$time_filter.earliest$</earliest>
          <latest>$time_filter.latest$</latest>
        </search>
        <option name="charting.chart">line</option>
        <option name="charting.legend.placement">bottom</option>
      </chart>
    </panel>
  </row>
</dashboard>
```

---

## 🔍 Descrizione dei Pannelli e delle Query

### 1. Distribuzione degli Accessi per Ora
*   **Query**: Estrae l'ora (`%H`) dal timestamp dei log OPA e aggrega il numero di chiamate effettuate da ciascun utente.
*   **Analisi di Sicurezza**: Permette di visualizzare picchi di attività anomala durante la notte (ad es. dalle 22:00 alle 06:00). Se l'utente *Alice* (che normalmente opera di giorno) mostra un picco alle 03:00 del mattino, la dashboard lo evidenzia graficamente come una colonna isolata.

### 2. Correlazione Utenti vs Impronte Software (JA3)
*   **Query**: Mette in relazione i singoli utenti con gli hash JA3 censiti da Envoy.
*   **Analisi di Sicurezza**: Rileva attacchi di *browser impersonation* o *credential sharing*. Se per l'utente *Alice* appaiono due barre corrispondenti a due hash JA3 diversi nello stesso intervallo temporale, significa che l'account è utilizzato da due browser diversi (o da uno script automatizzato che simula l'User-Agent ma ha un handshake SSL differente).

### 3. Clustering delle Sessioni (K-Means)
*   **Query**: Calcola dinamicamente la frequenza delle sessioni (richieste totali), il rischio medio e i tentativi falliti (DENY) per ogni utente, ed esegue il clustering **K-Means** via Splunk MLTK.
*   **Analisi di Sicurezza**: Raggruppa i profili in tre categorie comportamentali (i cui ID di cluster possono variare dinamicamente a seconda dell'inizializzazione dell'algoritmo):
    *   **Profilo A (Frequenza Elevata / Scraping)**: Caratterizzato da un altissimo volume di richieste e basso/medio rischio (Alice).
    *   **Profilo B (Alto Rischio / Sospetto)**: Caratterizzato da elevati punteggi di rischio medio e/o blocchi frequenti (Bob e Alice-Device2).
    *   **Profilo C (Basso Rischio / Attività Ordinaria)**: Comportamento regolare a basso rischio e bassa frequenza di chiamate (Charlie).

### 4. Rischio Dinamico vs Soglia OPA
*   **Query**: Confronta il `risk_score` calcolato in tempo reale dal modello predittivo con il limite impostato in OPA (50 se interno, 8 se esterno).
*   **Analisi di Sicurezza**: Mostra l'efficacia delle **soglie adattive**. Quando l'utente si sposta all'esterno (Charlie), la soglia si abbassa a 8, rendendo visivamente chiaro come anche piccole oscillazioni del rischio portino al blocco immediato della connessione.
