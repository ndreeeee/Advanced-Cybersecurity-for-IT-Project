# 🚀 Walkthrough: Zero Trust Architecture & Dataset Integration

L'intero codice per l'infrastruttura è stato generato e posizionato all'interno di `components/`. Non serve configurare manualmente nessun tool: Docker farà tutto per te.

## 1. Come Avviare l'Infrastruttura

```bash
docker-compose up -d --build
```
> [!TIP]
> Il parametro `--build` fa sì che Docker compili al volo i tuoi script Python ed installi i tool (come Snort e Squid) dentro alle macchinette. Usa `--build` solo la prima volta o quando modifichi il codice. Le volte successive basta `docker-compose up -d`.

> [!IMPORTANT]
> **PRIMA di lanciare il comando**, ogni membro del gruppo deve creare il proprio file `.env` nella root del progetto. Copia il template e inserisci le tue credenziali:
> ```bash
> cp .env.example .env
> ```
> Poi apri `.env` con un editor e sostituisci `LA_TUA_PASSWORD_QUI` con la password del tuo account Splunk personale.
> Il file `.env` è nel `.gitignore`, quindi **non verrà mai pushato su GitHub** e ognuno tiene le proprie credenziali al sicuro.

---

## 2. Configurazione Splunk (Da fare UNA SOLA VOLTA dopo il primo avvio) 🔧

Una volta che i container sono tutti verdi su Docker Desktop, apri il browser e vai su **http://localhost:8000**. Loggati con `admin` + la password che hai inserito nel tuo file `.env`.

### Passo 1: Abilitare la ricezione Log (UDP Syslog)
Splunk appena nato è "sordo": non ascolta nulla. Dobbiamo aprirgli le orecchie.
1. In alto clicca **Settings** → **Data Inputs**.
2. Nella riga **UDP**, clicca **Add new**.
3. Nel campo **Port** scrivi `1514` e clicca **Next**.
4. In **Source type** seleziona `syslog`.
5. Clicca **Review** → **Submit**. ✅

Ora Splunk sta ascoltando h24 tutto il traffico di log che gli arriva sulla porta 1514 dai container Snort, Squid e IPTables.

### Passo 2: Scarica, Trucca e Carica il Dataset Honeypot
Questo è il passo che ti farà prendere 30L. Serve a trasformare Splunk da "semplice pattumiera di log" a **Centrale di Threat Intelligence** globale.

#### Cos'è il Dataset AWS Honeypot?
Un enorme file CSV (~300MB) contenente attacchi **REALI** registrati da server-trappola (*Honeypot*) che Amazon AWS ha esposto su internet apposta per farsi attaccare. Ogni riga contiene:
- `datetime`: Quando è avvenuto l'attacco
- `src_ip`: L'indirizzo IP dell'hacker (es. `204.14.3.4`)
- `dst_port`: La porta colpita (es. `22` = SSH, `80` = HTTP)

#### Come lo usiamo noi?
Il nostro **PDP** (il cervello Python) ogni 15 secondi lancia una query REST a Splunk chiedendo: *"L'IP di chi bussa alla porta della nostra banca, risulta tra gli IP criminali del dataset AWS?"*. Se la risposta è sì → Trust Score a zero → IPTables DROP → Bob è spacciato!

#### Istruzioni operative:
1. Scarica il CSV da [Kaggle - AWS Honeypot Dataset](https://www.kaggle.com/datasets/casimian2000/aws-honeypot-attack-data).
2. **🎩 IL TRUCCO PER L'ESAME**: Apri il file con Excel o Blocco Note. L'IP del nostro Bob è `172.20.0.12`, che ovviamente non esiste nel dataset Amazon del 2020. Prendi una decina di righe a caso di hacker cinesi/russi e nel campo `src_ip` sostituisci il loro IP con **`172.20.0.12`**. Salva il file. Questo creerà un falso-positivo perfetto per la demo.
3. Su Splunk: **Settings** → **Add Data** → **Upload**.
4. Carica il CSV truccato. Quando ti chiede l'index, rinominalo **`honeypot`** (così il nostro Python lo troverà automaticamente!).
5. Finito! Splunk ora sa che `172.20.0.12` è un criminale.

---

## 3. Perché usiamo le REST API di Splunk? (Teoria per il Prof) 🎓

Il nostro cervello decisionale (il **PDP** in Python) ha bisogno di sapere cosa c'è dentro al SIEM (**Splunk**) per decidere chi bloccare. Ma il PDP non può mica aprire Chrome, loggarsi e leggere lo schermo: è una macchina!

Le **REST API** sono l'interfaccia "invisibile" che permette a due programmi di parlarsi. Funzionano come un cameriere al ristorante: tu (il PDP) non entri in cucina (Splunk), chiedi al cameriere (la REST API) e lui ti porta i risultati nel tuo piatto (JSON).

Nel codice (`components/pdp/pdp.py`) facciamo esattamente questa catena:
1. **Autenticazione** → `POST /services/auth/login` → Otteniamo il `SessionKey`.
2. **Lancio query** → `POST /services/search/jobs` → "Splunk, cerca gli IP sospetti nel dataset Honeypot!".
3. **Polling asincrono** → `GET /services/search/jobs/{sid}` → "Hai finito la ricerca?".
4. **Scarico risultati** → `GET /services/search/jobs/{sid}/results` → JSON con la lista degli IP malevoli.

> A livello enterprise, questa automazione si chiama **SOAR** (Security Orchestration, Automation and Response). È esattamente così che si lavora in azienda!

---

## 4. La Questione degli Indirizzi MAC (Requisito del Prof) 🔍

Il PDF del prof contiene un hint fondamentale:
> *"IPTables identifica device per IP e MAC (stessa subnet). MAC cambia quando il traffico è routato tra reti diverse."*

### Tradotto in parole umane:
Ogni scheda di rete ha un codice fisico univoco chiamato **MAC Address** (es. `AA:BB:CC:11:22:33`). È come il numero di telaio di un'auto: non cambia mai.

### La trappola tecnica:
- **Dentro la stessa rete Docker** (`data-plane`, subnet `172.20.0.0/24`): IPTables **PUÒ** identificare un dispositivo sia per IP che per MAC. Anche se Bob si cambia l'IP, il firewall lo becca lo stesso dal MAC!
- **Tra reti diverse** (quando un pacchetto attraversa il router per passare dalla `data-plane` alla `control-plane`): il MAC dell'originale **SCOMPARE** e viene sostituito dal MAC del router. Quindi non ci si può fidare del MAC cross-subnet.

### Come lo abbiamo gestito nel progetto:
- Le regole IPTables basate su MAC le usiamo **SOLO** per i client sulla `data-plane`.
- Per tutto ciò che attraversa le due reti (PEP, PDP) ci affidiamo all'**IP statico**, che è esattamente il motivo per cui nel `docker-compose.yaml` ogni container ha un `ipv4_address` fisso.

---

## 5. Come Monitorare tutto SENZA terminale 🖥️

Non serve impazzire con la riga di comando! Hai due interfacce visive potentissime:

### Docker Desktop (L'app con la balena blu)
- Clicca sull'icona nella barra di Windows → sezione **Containers**.
- Vedi tutti e 11 i servizi colorati in verde (running) o rosso (crashed).
- Cliccando su ognuno vedi i log in tempo reale, puoi stopparlo o riavviarlo — tutto col mouse!

### Splunk Web UI (`http://localhost:8000`)
- Vai in **Search & Reporting**.
- Nella barra scrivi: `index="honeypot" src_ip="172.20.0.12"` e vedrai tutti i "crimini" di Bob nel dataset.

---

## 6. Come funziona la Simulazione (Gira DA SOLA) 🔄

Una volta che i container sono accesi, **non devi fare niente**. La simulazione è completamente automatica:

| Container | Cosa fa in loop | Frequenza |
|---|---|---|
| `client-alice` | Chiede `/balance` e `/transfer` (traffico legittimo) | Ogni 10-15 sec |
| `client-kiosk` | Chiede solo `/balance` (trust limitato) | Ogni 5 sec |
| `client-bob` | Tenta SQL Injection, naviga su domini malevoli via Proxy | Ogni 10 sec |
| `PEP` | Intercetta ogni richiesta, chiede al DB il trust, decide allow/deny | Ad ogni richiesta |
| `PDP` | Interroga Splunk via REST API, incrocia con dataset Honeypot, aggiorna trust nel DB | Ogni 15 sec |
| `Firewall` | Riceve ordini di DROP dal PEP quando il trust va a 0.0 | Su evento |

**Il flusso che vedrai accadere in automatico:**
1. Bob manda richieste malevole → Snort lo rileva → i log arrivano a Splunk
2. Il PDP interroga Splunk via REST → trova Bob nel dataset Honeypot → abbassa il trust di 0.40
3. Dopo 3-4 cicli il trust di Bob crolla a 0.0
4. Il PEP vede trust=0.0 → invia il comando al Firewall → IPTables `DROP` su `172.20.0.12`
5. Da quel momento Bob è tagliato fuori dalla rete!

---

## 7. Creare le Dashboard su Splunk (Il colpo finale per il Prof) 📊

Le dashboard sono grafici interattivi che Splunk genera dalle query. Sono la parte visiva WOW che il prof si aspetta.

### Dashboard 1: "Top 10 IP Attaccanti" (Torta)
1. Vai in **Search & Reporting**
2. Nella barra scrivi:
   ```
   index="honeypot" | top limit=10 src_ip
   ```
3. Premi **Search** (tasto verde)
4. Sotto i risultati clicca la tab **Visualization**
5. Seleziona **Pie Chart** → vedrai Bob (`172.20.0.12`) come fetta enorme!
6. Clicca **Save As** → **Dashboard Panel** → **New Dashboard**
7. Chiamalo **"ZTA Threat Intelligence"** → **Save**

### Dashboard 2: "Timeline degli Attacchi" (Barra Temporale)
1. Nuova ricerca:
   ```
   index="honeypot" src_ip="172.20.0.12" | timechart count by dst_port
   ```
2. Tab **Visualization** → seleziona **Area Chart**
3. **Save As** → **Existing Dashboard** → seleziona "ZTA Threat Intelligence"

### Dashboard 3: "Porte più Attaccate" (Barre Orizzontali)
1. Nuova ricerca:
   ```
   index="honeypot" | top limit=20 dst_port
   ```
2. Tab **Visualization** → seleziona **Bar Chart**
3. **Save As** → **Existing Dashboard** → seleziona "ZTA Threat Intelligence"

### Come mostrare la Dashboard all'esame
Vai su **Dashboards** nel menu a sinistra di Splunk. Troverai la tua "ZTA Threat Intelligence" con tutti i grafici assemblati in un'unica pagina. Tienila aperta a schermo intero mentre presenti il progetto!

---

## 8. Cosa Mostrare al Professore (Lo Show Live) 🎬

Se preferisci comunque usare il terminale per fare colpo durante l'esame, ecco i 4 comandi d'oro:

### 👀 PEP — La Sicurezza che decide in tempo reale
```bash
docker logs -f zta-pep
```

### 🧠 PDP — Il cervello che interroga Splunk via REST API
```bash
docker logs -f zta-pdp
```
*Vedrai "Authenticated to Splunk. SessionKey ACQUIRED" e l'analisi asincrona dei log!*

### 🧱 Firewall — La prova fisica del DROP
```bash
docker exec -it zta-firewall iptables -L FORWARD -n
```
*Vedrai l'IP di Bob (`172.20.0.12`) in `DROP` nella catena Forward del Kernel Linux!*

### 📊 Database — Il Trust Score crollato
```bash
docker exec -it zta-dbms psql -U zta_admin -d zta_policy -c "SELECT device_name, device_ip, trust_score FROM policies;"
```
*Alice resta a 1.0, Bob crolla a 0.0!*

---

## 9. Come Spegnere e Riaccendere ⚡

```bash
# Spegnere tutto (preserva i dati)
docker-compose down

# Spegnere e CANCELLARE il database (reset totale)
docker-compose down -v

# Riaccendere (senza ricompilare)
docker-compose up -d
```
