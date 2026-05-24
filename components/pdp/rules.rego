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
network_ip := input.attributes.request.http.headers["x-forwarded-for"] if {
    is_http
    input.attributes.request.http.headers["x-forwarded-for"]
} else := input.attributes.source.address.socketAddress.address

# E. RISORSA
default resource := "Risorsa Non Definita"
resource := input.attributes.request.http.path if { is_http }
resource := "MongoDB / pazienti" if { is_mongo }

# F. COMANDO
default command := "Operazione Non Definita"
command := input.attributes.request.http.method if { is_http }
command := "Query Database" if { is_mongo }


# ================================================================
# 3. MOTORE DECISIONALE CON SIEM ML E LOGGING JSON
# ================================================================

# Valore di default in caso Splunk non risponda o fallisca
default splunk_risk_score := 100

splunk_risk_score := risk if {
    # Costruiamo la query SPL interpolando le 6 dimensioni (ZTA 6D)
    query := sprintf("| makeresults | eval user=\"%s\", software=\"%s\", device=\"%s\", network=\"%s\", action=\"%s\", resource=\"%s\" | apply trust_model | rename \"predicted(rischio)\" as rischio | table rischio", [user, software, device, network_ip, command, resource])
    
    # Chiamata sincrona a Web-API che fa da proxy per Splunk MLTK
    resp := http.send({
        "method": "POST",
        "url": "http://zta-web-api:8000/api/ml/predict",
        "headers": {
            "Content-Type": "application/json"
        },
        "body": {
            "query": query
        },
        "raise_error": false,
        "timeout": "35s"
    })
    
    resp.status_code == 200
    
    # Parsing della risposta (Il proxy restituisce {"rischio": 15.34})
    risk := to_number(resp.body.rischio)
}

# Contesto di rete: la richiesta DEVE provenire dalla rete interna ospedaliera
default is_internal_network := false
is_internal_network := true if {
    net.cidr_contains("10.0.1.0/24", network_ip)
}

# La regola di autorizzazione adattiva:
# - Se la rete è INTERNA, tolleranza rischio <= 50
# - Se la rete è ESTERNA, tolleranza rischio <= 10
risk_ok := true if {
    is_internal_network
    splunk_risk_score <= 50
} else := true if {
    not is_internal_network
    splunk_risk_score <= 10
} else := false

allow := true if {
    # CONDIZIONI DI ACCESSO
    risk_ok
    is_tpm
    
    # 3. Log di SUCCESSO strutturato in JSON per Splunk
    print("[OPA-PDP]", json.marshal({
        "Decision": "ALLOW",
        "risk_score": splunk_risk_score,
        "user": user,
        "software": software,
        "device": device,
        "network_ip": network_ip,
        "network_internal": is_internal_network,
        "resource": resource,
        "command": command
    }))
} else := false if {
    # Log di BLOCCO strutturato in JSON per Splunk
    print("[OPA-PDP]", json.marshal({
        "Decision": "DENY",
        "risk_score": splunk_risk_score,
        "tpm_present": is_tpm,
        "risk_ok": risk_ok,
        "network_internal": is_internal_network,
        "user": user,
        "software": software,
        "device": device,
        "network_ip": network_ip,
        "resource": resource,
        "command": command
    }))
}