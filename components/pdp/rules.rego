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

# A. UTENTE
default user := "Sconosciuto"
user := regex.replace(regex.replace(input.attributes.source.principal, "^.*/", ""), "^client-", "")

# B. SOFTWARE / JA3
default software := "Sconosciuto"
software := input.attributes.metadataContext.filterMetadata["envoy.filters.listener.tls_inspector"]["ja3"] if {
    input.attributes.metadataContext.filterMetadata["envoy.filters.listener.tls_inspector"]["ja3"] != ""
}
software := input.attributes.request.http.headers["x-client-fingerprint"] if {
    is_http
    not input.attributes.metadataContext.filterMetadata["envoy.filters.listener.tls_inspector"]["ja3"]
    input.attributes.request.http.headers["x-client-fingerprint"] != ""
}

# C. DISPOSITIVO E TPM
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

# D. RETE
default network_ip := "0.0.0.0"
network_ip := input.attributes.source.address.socketAddress.address

# E. RISORSA
default resource := "Risorsa Non Definita"
resource := input.attributes.request.http.path if { is_http }
resource := "MongoDB / pazienti" if { is_mongo }

# F. COMANDO
default command := "Operazione Non Definita"
command := input.attributes.request.http.method if { is_http }
command := "Query Database" if { is_mongo }


# ================================================================
# 3. MOTORE DECISIONALE CON SPLUNK MOCK E LOGGING JSON
# ================================================================

allow := true if {
    # 1. Chiede il livello di rischio a Splunk passando IP, JA3 e Utente
    risk_score := get_risk_from_splunk(network_ip, software, user)
    
    # 2. CONDIZIONI DI ACCESSO
    risk_score < 50
    is_tpm
    
    # 3. Log di SUCCESSO strutturato in JSON per Splunk
    print("[OPA-PDP]", json.marshal({
        "Decision": "ALLOW",
        "risk_score": risk_score,
        "user": user,
        "software": software,
        "device": device,
        "network_ip": network_ip,
        "resource": resource,
        "command": command
    }))
} else := false if {
    # Calcola il rischio anche se l'accesso fallisce (per capire perché è fallito)
    risk_score := get_risk_from_splunk(network_ip, software, user)
    
    # Log di BLOCCO strutturato in JSON per Splunk
    print("[OPA-PDP]", json.marshal({
        "Decision": "DENY",
        "risk_score": risk_score,
        "tpm_present": is_tpm,
        "user": user,
        "software": software,
        "device": device,
        "network_ip": network_ip,
        "resource": resource,
        "command": command
    }))
}

# --- MOCK SPLUNK PER LA FASE DI SVILUPPO ---
get_risk_from_splunk(ip, ja3, current_user) := risk if {
    current_user == "alice"
    risk := 10
}
get_risk_from_splunk(ip, ja3, current_user) := risk if {
    current_user == "bob"
    risk := 10
}
default get_risk_from_splunk(_, _, _) := 90