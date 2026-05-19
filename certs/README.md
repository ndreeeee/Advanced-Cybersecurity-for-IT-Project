# 🔐 ZTA Identity Management (PKI)

Questa cartella contiene l'infrastruttura di identità crittografica per il progetto Zero Trust 2026.

## 📂 Contenuto della cartella

| File | Tipo | Descrizione |
|------|------|-------------|
| `ca.crt` | **Root CA** | Il certificato dell'Autorità Ospedaliera. Usato da Envoy per validare i client. |
| `ca.key` | **CA Private Key** | La chiave segreta della CA. **Non condividere!** |
| `alice.crt` | **Client Cert** | Identità di Alice. Contiene l'estensione **TPM (OID 1.3.6.1.4.1.9999.1)**. |
| `bob.crt` | **Client Cert** | Identità di Bob. Certificato standard (Software-only). |
| `envoy.crt` | **Server Cert** | Identità del proxy Envoy (PEP). |
| `generate_identities.py` | **Tool** | Script Python per rigenerare tutti i certificati. |

## 🚀 Come rigenerare i certificati

Se i certificati scadono o se vuoi resettare l'ambiente, esegui:

```bash
python generate_identities.py
```

*Nota: Richiede la libreria `cryptography` (`pip install cryptography`).*

## ⚙️ Come funziona lo script `generate_identities.py`

Lo script automatizza la creazione di una **PKI (Public Key Infrastructure)** privata per il progetto. Ecco i passaggi logici:

1.  **Inizializzazione Root CA**: Genera una coppia di chiavi RSA a 2048 bit e un certificato auto-firmato che funge da "Fiducia Totale" del sistema.
2.  **Generazione Identità (Alice & Bob)**:
    *   Crea una chiave privata univoca per ogni utente.
    *   Prepara una richiesta di certificato con il **Common Name** (es. `employee-alice`).
    *   **Iniezione TPM (Solo Alice)**: Durante la firma, lo script inserisce nel certificato di Alice l'estensione X.509 `UnrecognizedExtension` con OID `1.3.6.1.4.1.9999.1`. Questo simula un'attestazione hardware riuscita.
3.  **Firma**: Tutti i certificati vengono firmati digitalmente usando la chiave privata della Root CA, garantendo l'integrità e l'autenticità.

## 🛡️ Simulazione Hardware TPM
Il certificato di Alice simula un dispositivo aziendale "blindato" tramite l'aggiunta di un'estensione X.509 personalizzata. OPA utilizzerà questa informazione per decidere se Alice può accedere ai dati sensibili (`sensitive_notes`) o se deve essere limitata.
