# Simulazione di Anomalia Temporale e Account Dormiente (Scenario 8)

Questa guida descrive come configurare, eseguire e validare la simulazione delle **anomalie temporali** e dell'**account dormiente** (corrispondente allo Scenario 8 della tesi).

---

## 📖 Panoramica della Simulazione

L'obiettivo è dimostrare la capacità della ZTA di calcolare un rischio comportamentale adattivo e bloccare accessi anomali basati su:
1.  **Accesso in orario notturno** (`is_night = 1`, `hour_of_day = 3`): Accessi eseguiti al di fuori dell'orario lavorativo standard.
2.  **Inattività prolungata dell'account** (`days_inactive = 90`): Riattivazione improvvisa di un account dormiente.
3.  **Picco di tentativi falliti** (`failed_logins = 4`): Possibile attacco di tipo brute force.

---

## 🛠️ Implementazione (Il Barbatrucco)

Per evitare la creazione complessa di nuovi certificati mTLS e container aggiuntivi, viene utilizzato il trucco della **propagazione del parametro di query**. La simulazione viene attivata appendendo `?simulate=dormant_night` a qualsiasi endpoint HTTP esposto da Envoy.

### 1. Modifica al Backend delle Web API (`main.py`)

Il file [main.py](file:///c:/Users/andre/Documents/GitHub/Advanced-Cybersecurity-for-IT-Project/components/api/main.py) intercetta il parametro di query, sovrascrive i dati temporali e pulisce la query in modo che Splunk riceva parametri corretti per il modello MLTK.

#### Codice Modificato in `enrich_spl_with_behavioral_features`
```python
def enrich_spl_with_behavioral_features(query: str, simulate_dormant_night: bool = False) -> str:
    user = extract_user_from_spl(query)
    resource = extract_resource_from_spl(query)
    record_session(user)

    # Se la simulazione è attiva, forziamo i parametri delle anomalie temporali
    if simulate_dormant_night:
        hour_of_day = 3         # Ore 03:00 del mattino
        is_night = 1            # Flag notte attivo
        days_inactive = 90      # Account rimasto dormiente per 90 giorni
        failed_logins = 4       # 4 login falliti nelle 24h per simulare brute force
    else:
        now = datetime.now()
        hour_of_day = now.hour
        is_night = 1 if (hour_of_day >= 22 or hour_of_day < 6) else 0
        days_inactive = 0
        failed_logins = get_failed_logins(user)

    session_freq = get_session_freq(user)
    sensitivity_level = get_sensitivity_level(resource)

    behavioral_features = (
        f', failed_logins={failed_logins}'
        f', hour_of_day={hour_of_day}'
        f', is_night={is_night}'
        f', session_freq={session_freq}'
        f', sensitivity_level={sensitivity_level}'
        f', days_inactive={days_inactive}'
    )
    return query.replace('| apply ', f'{behavioral_features} | apply ')
```

---

## 🚀 Come Eseguire i Test

Lanciare i seguenti comandi direttamente dal terminale della macchina host (o da dentro i container client) per simulare l'attacco.

### Test 1: Accesso di Charlie (Rete Esterna, TPM) con Anomalia Temporale
Charlie si collega da rete esterna, ha un certificato valido con TPM ma richiede l'accesso alle 3 di notte dopo 90 giorni di inattività.

```bash
docker exec -it zta-client-charlie curl -k -v "https://zta-firewall:8443/api/patients?simulate=dormant_night"
```

*   **Esito OPA**: **DENY**.
*   **Logica**: Il rischio calcolato sale a $\approx 50$ (a causa dell'inattività, dell'orario notturno e dei login falliti simulati). Poiché Charlie opera da rete esterna, OPA applica la soglia di rischio restrittiva `splunk_risk_score <= 8`. Il valore 50 supera abbondantemente la soglia e la richiesta viene bloccata.

### Test 2: Accesso di Alice (Rete Interna, TPM) con Anomalia Temporale
Alice si collega dalla rete ospedaliera protetta interna, ma il suo account viene usato alle 3 di notte con brute force.

```bash
docker exec -it zta-client-alice curl -k -v "https://zta-firewall:8443/api/patients?simulate=dormant_night"
```

*   **Esito OPA**: **DENY**.
*   **Logica**: Il rischio calcolato sale a $\approx 67$ (inattività + orario notturno + 4 login falliti + livello di sensibilità della risorsa). Nonostante Alice si trovi sulla rete interna (dove la soglia di tolleranza è 50), il punteggio di rischio di 67 supera la barriera di sicurezza del PDP, determinando un blocco preventivo.

---

## 📊 Verifica nei Log di Splunk

Una volta eseguito il test, è possibile cercare l'evento in Splunk eseguendo la seguente ricerca per monitorare i dati arricchiti:

```sql
index=* sourcetype="opa:decisions" Decision="DENY"
| table user, network_ip, risk_score, is_night, days_inactive, failed_logins
```
Le colonne mostreranno chiaramente il picco del `risk_score` correlato con i valori `is_night=1` e `days_inactive=90`.
