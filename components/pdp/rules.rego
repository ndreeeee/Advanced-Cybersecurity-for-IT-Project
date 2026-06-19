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

# Rilevamento connessioni TCP dirette al database (OP_MSG / pymongo moderno)
# Quando il mongo_proxy non riesce a decodificare il protocollo OP_MSG (opcode 2013),
# non genera metadati. In questo caso, se la richiesta non è HTTP ma ha un certificato
# client valido, la classifichiamo come tentativo di accesso diretto al database.
default is_direct_db := false
is_direct_db := true if {
    not is_http
    not is_mongo
    input.attributes.source.certificate != ""
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
resource := input.attributes.metadataContext.filterMetadata["envoy.filters.network.mongo_proxy"]["collection"] if {
    is_mongo
    input.attributes.metadataContext.filterMetadata["envoy.filters.network.mongo_proxy"]["collection"]
} else := "MongoDB (Collezione sconosciuta)" if { is_mongo }
resource := "patients" if { is_direct_db }

# F. COMANDO E QUERY (DPI)
default command := "Operazione Non Definita"
command := input.attributes.request.http.method if { is_http }
command := input.attributes.metadataContext.filterMetadata["envoy.filters.network.mongo_proxy"]["operation"] if {
    is_mongo
    input.attributes.metadataContext.filterMetadata["envoy.filters.network.mongo_proxy"]["operation"]
} else := "Comando MongoDB sconosciuto" if { is_mongo }
command := "Accesso Diretto MongoDB (OP_MSG)" if { is_direct_db }

# Estrazione Query per L7 DPI (se presente)
default db_query := ""
db_query := input.attributes.metadataContext.filterMetadata["envoy.filters.network.mongo_proxy"]["query"] if {
    is_mongo
}


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

# L7 DPI: Regole di blocco esplicite su traffico HTTP e MongoDB
default l7_dpi_block := false

# --- LIVELLO 1: Protezione dell'endpoint HTTP delle Cartelle Cliniche ---
l7_dpi_block := true if {
    is_http
    resource == "/api/patients/sensitive"
    not is_internal_network  # Blocca Charlie (Rete Esterna)
} else := true if {
    is_http
    resource == "/api/patients/sensitive"
    not is_tpm               # Blocca Bob (Senza TPM)
} 

# --- LIVELLO 2: Protezione profonda su comandi nativi MongoDB ---
else := true if {
    is_mongo
    contains(lower(db_query), "dropdatabase")
} else := true if {
    is_mongo
    contains(lower(db_query), "deleteall")
}

# La regola di autorizzazione adattiva (Risk-Based & JA3 Fallback)
# - Se la rete è INTERNA:
#   - Con TPM: tolleranza rischio <= 38 (Alice: massima fiducia)
#   - Senza TPM (solo JA3): tolleranza rischio <= 26 (Bob: fiducia limitata)
# - Se la rete è ESTERNA:
#   - Con TPM: tolleranza rischio <= 26 (Charlie in smart working: fiducia limitata)
#   - Senza TPM: accesso sempre negato (Gestito implicitamente)

risk_ok := true if {
    is_internal_network
    is_tpm
    splunk_risk_score <= 38
} else := true if {
    is_internal_network
    not is_tpm
    software != "Sconosciuto"
    splunk_risk_score <= 26
} else := true if {
    not is_internal_network
    is_tpm
    splunk_risk_score <= 26
} else := false

# Definizione delle richieste di autenticazione/login (HTTP o MongoDB)
is_auth_request := true if {
    resource == "/api/auth"
} else := true if {
    command == "authenticate"
} else := false

# Protezione e Requisiti di Sicurezza per il Login:
# 1. Blocca preventivamente le richieste di autenticazione senza un'impronta JA3 valida (Anti-Bot).
# 2. Impone l'obbligo tassativo del modulo TPM per QUALSIASI tentativo di login. 
#    I vecchi macchinari senza TPM mantengono l'operatività sulle API di base (se il rischio è <= 26), 
#    ma non possono richiedere nuovi token di autenticazione.
is_auth_blocked := true if {
    is_auth_request
    software == "Sconosciuto"
} else := true if {
    is_auth_request
    not is_tpm               # <--- BLOCCO TASSATIVO LOGIN SENZA TPM
} else := false

allow := true if {
    # CONDIZIONI DI ACCESSO
    risk_ok
    not l7_dpi_block
    not is_auth_blocked
    
    # 3. Log di SUCCESSO strutturato in JSON per Splunk
    print("[OPA-PDP]", json.marshal({
        "Decision": "ALLOW",
        "risk_score": splunk_risk_score,
        "tpm_present": is_tpm,
        "l7_dpi_block": l7_dpi_block,
        "user": user,
        "software": software,
        "device": device,
        "network_ip": network_ip,
        "network_internal": is_internal_network,
        "resource": resource,
        "command": command,
        "query": db_query
    }))
} else := false if {
    # Log di BLOCCO strutturato in JSON per Splunk
    print("[OPA-PDP]", json.marshal({
        "Decision": "DENY",
        "risk_score": splunk_risk_score,
        "tpm_present": is_tpm,
        "risk_ok": risk_ok,
        "l7_dpi_block": l7_dpi_block,
        "network_internal": is_internal_network,
        "user": user,
        "software": software,
        "device": device,
        "network_ip": network_ip,
        "resource": resource,
        "command": command
    }))
}