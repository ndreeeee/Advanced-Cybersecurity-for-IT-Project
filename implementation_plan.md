# Trust Score Engine ML — UNSW-NB15 + Splunk Integration

## Contesto

Il trust engine attuale ([trust_engine.py](file:///c:/Users/andre/Documents/GitHub/Advanced-Cybersecurity-for-IT-Project/components/pdp/trust_engine.py)) calcola il trust score con **formule statiche** (`P(attacco) = 1 - e^(-λ·count)`). Vogliamo sostituirlo con un modello ML allenato su un **dataset reale**: **UNSW-NB15**.

## Dataset: UNSW-NB15

**Fonte**: Australian Centre for Cyber Security (ACCS), UNSW Canberra
**Paper**: Moustafa & Slay, 2015 — *"UNSW-NB15: a comprehensive data set for network intrusion detection systems"*
**Licenza**: Uso accademico libero (con citazione)

| Proprietà | Valore |
|-----------|--------|
| Record totali | 2,540,044 |
| Training set | 175,341 record |
| Testing set | 82,332 record |
| Feature | 49 (+ label + attack_cat) |
| Tipi di attacco | 9: Fuzzers, Analysis, Backdoors, DoS, Exploits, Generic, Reconnaissance, Shellcode, Worms |
| Formato | CSV |

### Feature principali del dataset (mappate al nostro contesto ZTA)

| Feature UNSW-NB15 | Tipo | Mapping ZTA |
|-------------------|------|-------------|
| `dur` | float | Durata connessione → indicatore sessione |
| `proto` | cat | Protocollo (tcp/udp) → tipo traffico |
| `service` | cat | Servizio (-/http/ftp/dns) → risorsa acceduta |
| `state` | cat | Stato connessione → pattern accesso |
| `sbytes` / `dbytes` | int | Byte src→dst / dst→src → volume traffico |
| `sttl` / `dttl` | int | TTL src/dst → fingerprinting rete |
| `sloss` / `dloss` | int | Pacchetti persi → qualità connessione |
| `sinpkt` / `dinpkt` | float | Inter-packet time → pattern temporale |
| `sjit` / `djit` | float | Jitter → stabilità connessione |
| `tcprtt` | float | TCP round-trip time → latenza |
| `ct_srv_src` | int | Connessioni stesso servizio/src → frequenza |
| `ct_dst_ltm` | int | Connessioni stessa dst ultime 100 → density |
| `ct_src_ltm` | int | Connessioni stessa src ultime 100 → density |
| `attack_cat` | cat | Categoria attacco → tipo anomalia |
| `label` | binary | 0=normale, 1=attacco → target ML |

> [!NOTE]
> Il dataset non ha direttamente un "trust score", ma il modello ML **apprende a distinguere traffico normale da attacchi** e trasforma la probabilità di attacco in un trust score inverso: `trust = 1 - P(attack)`.

## User Review Required

> [!IMPORTANT]
> **Download del dataset**: il dataset va scaricato da Kaggle (~150MB zip). Lo script `download_dataset.py` lo scarica automaticamente. Serve un account Kaggle? Oppure possiamo includere un subset ridotto (~10K record) direttamente nel repo per la demo?

> [!WARNING]
> **Dimensione Docker**: scikit-learn + pandas + numpy aggiungono ~200MB all'immagine Docker del trust-engine. Accettabile per un progetto accademico.

## Proposed Changes

### Struttura file nuovi

```
components/pdp/
├── ml/
│   ├── __init__.py              # Package init
│   ├── download_dataset.py      # Scarica UNSW-NB15 da Kaggle/mirror
│   ├── preprocess.py            # Pulizia + feature engineering
│   ├── train_model.py           # Training pipeline (CLI)
│   ├── ml_model.py              # Classe TrustMLModel (inference)
│   ├── feature_config.py        # Mapping feature UNSW → ZTA
│   └── models/                  # Modelli salvati (.joblib)
│       └── .gitkeep
├── trust_engine.py              # MODIFICATO: usa ml_model
├── requirements.txt             # MODIFICATO: +scikit-learn,pandas,numpy
├── Dockerfile.trust-engine      # MODIFICATO: copia ml/
└── ...
```

---

### 1. Download e Preprocessing

#### [NEW] [download_dataset.py](file:///c:/Users/andre/Documents/GitHub/Advanced-Cybersecurity-for-IT-Project/components/pdp/ml/download_dataset.py)

Script che:
- Scarica `UNSW_NB15_training-set.csv` e `UNSW_NB15_testing-set.csv` da un mirror GitHub pubblico
- Fallback: istruzioni per download manuale da Kaggle
- Salva in `ml/data/`

#### [NEW] [preprocess.py](file:///c:/Users/andre/Documents/GitHub/Advanced-Cybersecurity-for-IT-Project/components/pdp/ml/preprocess.py)

Preprocessing pipeline:
1. **Pulizia**: rimozione duplicati, gestione NaN/Inf, drop colonne costanti
2. **Feature selection**: selezione delle 20 feature più rilevanti per il trust scoring (basate su importanza e correlazione con la label)
3. **Encoding**: LabelEncoding per feature categoriche (`proto`, `service`, `state`, `attack_cat`)
4. **Scaling**: StandardScaler per feature numeriche
5. **Feature engineering aggiuntive**:
   - `bytes_ratio = sbytes / (sbytes + dbytes + 1)` — simmetria traffico
   - `packet_rate = (spkts + dpkts) / (dur + 0.001)` — densità pacchetti
   - `connection_density = ct_srv_src + ct_dst_ltm` — frequenza connessioni (analogo alla density Splunk)
6. **Output**: dataset pulito pronto per il training

#### [NEW] [feature_config.py](file:///c:/Users/andre/Documents/GitHub/Advanced-Cybersecurity-for-IT-Project/components/pdp/ml/feature_config.py)

Configurazione centralizzata:
- Lista feature selezionate dal dataset UNSW
- Mapping feature UNSW → metriche SIEM Splunk per l'inference runtime
- Parametri scaler, encoder (serializzati con il modello)

---

### 2. Pipeline ML

#### [NEW] [train_model.py](file:///c:/Users/andre/Documents/GitHub/Advanced-Cybersecurity-for-IT-Project/components/pdp/ml/train_model.py)

Script CLI per il training:

```python
# Uso:
# python -m ml.train_model --data ml/data/ --output ml/models/

# Pipeline:
# 1. Carica dataset preprocessato
# 2. Allena Isolation Forest (anomaly detection unsupervised)
# 3. Allena Gradient Boosting (classificazione attack/normal)
# 4. Valuta metriche (accuracy, precision, recall, F1, confusion matrix)
# 5. Salva modelli + scaler + encoder in ml/models/
```

**Isolation Forest** (Stadio 1):
- Contamination auto-calibrata dal dataset (~13% attacchi)
- Produce `anomaly_score ∈ [-1, 1]`
- Parametri: `n_estimators=200, max_samples='auto'`

**Gradient Boosting Classifier** (Stadio 2):
- Target binario: `label` (0=normal, 1=attack)
- Feature: le 20 selezionate + anomaly_score dello stadio 1
- Produce `P(attack) ∈ [0, 1]` → `trust_score = 1 - P(attack)`
- Parametri: `n_estimators=300, max_depth=6, learning_rate=0.1`

#### [NEW] [ml_model.py](file:///c:/Users/andre/Documents/GitHub/Advanced-Cybersecurity-for-IT-Project/components/pdp/ml/ml_model.py)

Classe `TrustMLModel` per inference runtime:

```python
class TrustMLModel:
    """Modello ML per trust scoring in produzione."""
    
    def predict(self, siem_metrics: dict) -> TrustPrediction:
        """
        Input (da Splunk via trust_engine):
          - deny_count, allow_count, total_events, max_z_score
          - network_ip, user, hour_of_day
          
        Mapping SIEM → UNSW features:
          - total_events      → ct_srv_src (connection count)
          - deny_count         → sloss (packet loss proxy)  
          - max_z_score        → sjit (jitter/anomalia)
          - deny_ratio         → bytes_ratio (simmetria)
          - events_per_hour    → packet_rate (densità)
          
        Output:
          TrustPrediction(
            trust_score=0.82,     # [0,1] - da P(attack) del GB
            risk_score=18.0,      # [0,100] - calibrato
            anomaly_score=-0.3,   # [-1,1] - da Isolation Forest
            is_anomaly=False,
            confidence=0.91,
            attack_type="Normal"  # o categoria UNSW
          )
        """
```

---

### 3. Integrazione Trust Engine

#### [MODIFY] [trust_engine.py](file:///c:/Users/andre/Documents/GitHub/Advanced-Cybersecurity-for-IT-Project/components/pdp/trust_engine.py)

Modifiche chiave:

```diff
+ from ml.ml_model import TrustMLModel, TrustPrediction
+ 
+ ML_MODEL_PATH = os.getenv("ML_MODEL_PATH", "/app/ml/models/trust_model.joblib")
+ ML_ENABLED = os.getenv("ML_ENABLED", "true").lower() == "true"
+ 
+ # Modello ML globale (caricato allo startup)
+ _ml_model: TrustMLModel | None = None

  # --- Startup ---
  def startup():
      seed_cache_from_mongo()
+     # Carica modello ML
+     global _ml_model
+     if ML_ENABLED:
+         _ml_model = TrustMLModel()
+         _ml_model.load_model(ML_MODEL_PATH)
      threading.Thread(target=background_poller, daemon=True).start()

  # --- Nel poll loop, sostituisce le formule statiche ---
  def poll_splunk_and_update():
      ...
      for doc in identities:
          ...
-         # Vecchio calcolo statico
-         delta, reason = compute_trust_delta(metrics)
-         new_trust = max(0.0, min(1.0, baseline + delta))
+         # Nuovo calcolo ML
+         if _ml_model and ML_ENABLED:
+             prediction = _ml_model.predict(metrics)
+             new_trust = prediction.trust_score
+             reason = f"ML: {prediction.attack_type} (conf={prediction.confidence:.2f})"
+         else:
+             # Fallback a formule statiche
+             delta, reason = compute_trust_delta(metrics)
+             new_trust = max(0.0, min(1.0, baseline + delta))

  # --- build_context aggiornato con campi ML ---
  def build_context_for_principal(doc, metrics):
      ...
+     if _ml_model and ML_ENABLED:
+         pred = _ml_model.predict(metrics or {})
+         ctx["ml_anomaly_score"] = pred.anomaly_score
+         ctx["ml_trust_class"] = pred.attack_type
+         ctx["ml_confidence"] = pred.confidence
      return ctx

+ # --- Nuovo endpoint: stato modello ML ---
+ @app.get("/v1/ml/status")
+ def ml_status():
+     if not _ml_model:
+         return {"enabled": False}
+     return _ml_model.get_status()
```

> [!NOTE]
> **Fallback**: se `ML_ENABLED=false` o il modello non è caricato, si usano le vecchie formule statiche. Zero downtime.

---

### 4. Configurazione Docker

#### [MODIFY] [requirements.txt](file:///c:/Users/andre/Documents/GitHub/Advanced-Cybersecurity-for-IT-Project/components/pdp/requirements.txt)

```diff
 httpx==0.27.2
 pymongo==4.8.0
 fastapi==0.115.0
 uvicorn==0.30.6
+scikit-learn==1.5.2
+pandas==2.2.3
+numpy==1.26.4
+joblib==1.4.2
```

#### [MODIFY] [Dockerfile.trust-engine](file:///c:/Users/andre/Documents/GitHub/Advanced-Cybersecurity-for-IT-Project/components/pdp/Dockerfile.trust-engine)

```diff
 FROM python:3.11-slim
 WORKDIR /app
 COPY requirements.txt .
 RUN pip install --no-cache-dir -r requirements.txt
 COPY trust_engine.py .
+COPY ml/ ./ml/
 EXPOSE 8182
 CMD ["python", "trust_engine.py"]
```

#### [MODIFY] [docker-compose.yaml](file:///c:/Users/andre/Documents/GitHub/Advanced-Cybersecurity-for-IT-Project/docker-compose.yaml)

```diff
     environment:
       MONGO_URI: mongodb://mongodb-resource:27017/hospital_db
       SPLUNK_HOST: https://splunk-siem:8089
       SPLUNK_USER: admin
       SPLUNK_PASS: ${SPLUNK_PASSWORD}
       FIREWALL_URL: http://nftables-firewall
       TRUST_POLL_SECONDS: "15"
+      ML_ENABLED: "true"
+      ML_MODEL_PATH: "/app/ml/models/trust_model.joblib"
+      ML_ANOMALY_THRESHOLD: "0.65"
```

---

### 5. Aggiornamento OPA

#### [MODIFY] [rules.rego](file:///c:/Users/andre/Documents/GitHub/Advanced-Cybersecurity-for-IT-Project/components/pdp/rules.rego)

```rego
# Nuova regola: il modello ML ha rilevato anomalia
ml_anomaly_detected if {
    siem.ml_anomaly_score > 0.65
}

# Regola aggiornata
is_authorized if {
    input.attributes.source.principal == alice_identity
    is_tpm
    trust_ok
    risk_ok
    not ml_anomaly_detected
}
```

---

## Riepilogo File

| Azione | File | Descrizione |
|--------|------|-------------|
| **NEW** | `ml/__init__.py` | Package init |
| **NEW** | `ml/download_dataset.py` | Download UNSW-NB15 |
| **NEW** | `ml/preprocess.py` | Pulizia e feature engineering |
| **NEW** | `ml/feature_config.py` | Config feature mapping |
| **NEW** | `ml/train_model.py` | Training pipeline CLI |
| **NEW** | `ml/ml_model.py` | Classe inference runtime |
| **NEW** | `ml/models/.gitkeep` | Directory modelli |
| **MODIFY** | `trust_engine.py` | Integrazione ML |
| **MODIFY** | `requirements.txt` | Dipendenze ML |
| **MODIFY** | `Dockerfile.trust-engine` | Copia modulo ML |
| **MODIFY** | `docker-compose.yaml` | Env vars ML |
| **MODIFY** | `rules.rego` | Regola ML anomaly |

## Verification Plan

### Automated Tests

1. **Training su UNSW-NB15**:
   ```bash
   cd components/pdp
   python -m ml.download_dataset
   python -m ml.train_model --data ml/data/ --output ml/models/
   ```
   Output atteso: Accuracy > 85%, modello salvato

2. **Test inference**:
   ```bash
   python -c "
   from ml.ml_model import TrustMLModel
   m = TrustMLModel()
   m.load_model('ml/models/trust_model.joblib')
   # Sessione normale
   print(m.predict({'deny_count': 0, 'allow_count': 10, 'total_events': 10, 'max_z_score': 0.5}))
   # Sessione sospetta  
   print(m.predict({'deny_count': 15, 'allow_count': 2, 'total_events': 17, 'max_z_score': 4.0}))
   "
   ```

3. **Docker build**:
   ```bash
   docker compose build trust-engine
   ```

### Manual Verification

- `GET /v1/context?user=alice` → campi ML presenti
- `GET /v1/ml/status` → accuracy, feature importances, tipo modello
- Simulare attacco Bob → trust score cala dinamicamente via ML
