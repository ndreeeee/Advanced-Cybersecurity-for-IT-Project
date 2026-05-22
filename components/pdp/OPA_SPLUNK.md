# OPA ↔ Splunk ↔ MongoDB (Trust Engine)

## Architettura (workflow.md + Adv-2026)

```text
Log (OPA, Envoy, Snort…) → Fluent Bit → Splunk (HEC)
                              ↑
                    Trust Engine (ogni 15s)
                    · SPL density / frequenza
                    · P(attacco) = 1 - e^(-λ·count)
                    · aggiorna MongoDB identities
                              ↑
                    GET /v1/context
                              ↑
              OPA ext_authz (ogni richiesta Envoy)
```

**Nota:** non si usa PostgreSQL. Il policy store è **MongoDB** (`hospital_db.identities`).

## Servizi

| Container | Ruolo |
|-----------|--------|
| `zta-trust-engine` | SIEM client Splunk REST + API per OPA |
| `zta-opa` | PDP Rego + plugin `envoy_ext_authz_grpc` :9191 |
| `zta-splunk` | SIEM |
| `zta-mongodb` | Policy store + dati pazienti |

## Verifica rapida

```bash
docker compose up -d --build trust-engine opa-pdp
curl -s "http://localhost:8182/health"   # se esponi 8182, altrimenti:
docker exec zta-trust-engine wget -qO- http://127.0.0.1:8182/v1/context?user=alice
```

Dopo click su Alice (8081), in Splunk:

```spl
index=main earliest=-15m "[OPA-PDP]"
```

## Variabili

| Env | Default |
|-----|---------|
| `TRUST_LAMBDA` | 0.005 |
| `TRUST_Z_THRESHOLD` | 2.0 |
| `TRUST_RISK_DENY_THRESHOLD` | 50 |
| `TRUST_MIN_ACCESS` | 0.40 |
