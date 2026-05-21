package envoy.authz
import rego.v1

# ================================================================
# POLICY ZTA 2026 - DOMINIO OSPEDALIERO (Hospital DB)
# ================================================================

# Regola base: Zero Trust (Deny by default)
default allow := false

# ================================================================
# 1. RICONOSCIMENTO DEL TIPO DI TRAFFICO (HTTP o MongoDB)
# ================================================================
default is_http := false
is_http := true if {
    input.attributes.request.http.method != ""
}

default is_mongo := false
is_mongo := true if {
    input.attributes.metadataContext.filterMetadata["envoy.filters.network.mongo_proxy"]
}

# ================================================================
# 2. ESTRAZIONE DELLE 6 DIMENSIONI (ZTA 6D)
# ================================================================

# A. UTENTE (Estrae "alice", "medico-rossi", ecc. dal certificato)
default user := "Sconosciuto"
user := regex.replace(regex.replace(input.attributes.source.principal, "^.*/", ""), "^client-", "")

# B. SOFTWARE / JA3 (Legge dal TLS Inspector o dall'header iniettato)
default software := "Sconosciuto"
software := input.attributes.metadataContext.filterMetadata["envoy.filters.listener.tls_inspector"]["ja3"] if {
    input.attributes.metadataContext.filterMetadata["envoy.filters.listener.tls_inspector"]["ja3"] != ""
}
software := input.attributes.request.http.headers["x-client-fingerprint"] if {
    is_http
    not input.attributes.metadataContext.filterMetadata["envoy.filters.listener.tls_inspector"]["ja3"]
    input.attributes.request.http.headers["x-client-fingerprint"] != ""
}

# C. DISPOSITIVO E TPM (Controllo Hardware Attestation)
default is_tpm := false
is_tpm := true if {
    cert_raw := input.attributes.source.certificate
    cert_pem := urlquery.decode(cert_raw)
    certs := crypto.x509.parse_certificates(cert_pem)
    count(certs) > 0
    some ext in certs[0].Extensions
    ext.Id == [1, 3, 6, 1, 4, 1, 9999, 1]
}
default device := "Dispositivo non censito (No TPM)"
device := "Workstation Ospedaliera Sicura (TPM Validato)" if { is_tpm }

# D. RETE (Indirizzo IP)
default network_ip := "0.0.0.0"
network_ip := input.attributes.source.address.socketAddress.address

# E. RISORSA (Se HTTP legge il path, se Mongo cerca la collezione)
default resource := "Risorsa Non Definita"
resource := input.attributes.request.http.path if { is_http }
# Se è traffico Mongo, i metadati dinamici ci diranno quale collezione sta venendo interrogata
resource := "MongoDB / pazienti" if { 
    is_mongo 
    # Fallback sicuro nel caso il metadato esatto cambi
}

# F. COMANDO (Se HTTP legge GET/POST, se Mongo legge find/insert)
default command := "Operazione Non Definita"
command := input.attributes.request.http.method if { is_http }
command := "Query Database" if { is_mongo }


# ================================================================
# 3. MOTORE DECISIONALE CON SPLUNK MOCK E LOGGING
# ================================================================

allow := true if {
    # 1. Chiede il livello di rischio a Splunk
    risk_score := get_risk_from_splunk(network_ip, software)
    
    # 2. CONDIZIONE DI ACCESSO: Rischio accettabile (< 50)
    risk_score < 50
    
    # 3. Log di successo nella console di OPA
    print("[OPA-PDP] 🟢 ACCESSO CONSENTITO | Rischio:", risk_score, "| Utente:", user, "| DB/API:", command, "su", resource)
} else := false if {
    # Se il rischio è troppo alto (>= 50), scatta il blocco ZTA
    risk_score := get_risk_from_splunk(network_ip, software)
    print("[OPA-PDP] 🔴 ACCESSO BLOCCATO (ZERO TRUST) | Rischio:", risk_score, "| Utente:", user, "| JA3 Sospetto:", software)
}

# --- MOCK SPLUNK PER LA FASE DI SVILUPPO ---
get_risk_from_splunk(ip, ja3) := risk if {
    # Fingiamo che questo IP sia un medico autorizzato a basso rischio
    ip == "127.0.0.1"
    risk := 10
}
default get_risk_from_splunk(_, _) := 90 # Tutti gli altri vengono bloccati (es. 90)