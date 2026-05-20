package envoy.authz

import rego.v1

# ================================================================
# POLICY ZTA - Zero Trust Authorization Engine
# Flusso: Envoy estrae la SPIFFE ID dalla SAN del certificato mTLS
# e la passa come source.principal nella richiesta ext_authz gRPC
# ================================================================

# Di default, tutto è BLOCCATO (deny-all)
default allow := false

# Identità SPIFFE valide (estratte dalla SAN del certificato mTLS)
alice_identity := "spiffe://zta.hospital/ns/default/sa/client-alice"
bob_identity   := "spiffe://zta.hospital/ns/default/sa/client-bob"

# ----------------------------------------------------------------
# ESTRAZIONE DELLE 6 DIMENSIONI DEL CONTESTO (ZTA 6D)
# ----------------------------------------------------------------

# 1. UTENTE (user)
default user := "Sconosciuto"
user := regex.replace(regex.replace(input.attributes.source.principal, "^.*/", ""), "^client-", "")

# 2. CLIENT SOFTWARE (software)
default software := "Python mTLS Client"

# Ottieni il JA3 fingerprint da metadataContext (popolato da ext_authz tramite tls_inspector)
software := input.attributes.metadataContext.filterMetadata["envoy.filters.listener.tls_inspector"]["ja3"] if {
    input.attributes.metadataContext.filterMetadata["envoy.filters.listener.tls_inspector"]["ja3"] != ""
}

# Se non c'è nei metadati, prova a prenderlo dall'header x-client-fingerprint
software := input.attributes.request.http.headers["x-client-fingerprint"] if {
    not input.attributes.metadataContext.filterMetadata["envoy.filters.listener.tls_inspector"]["ja3"]
    input.attributes.request.http.headers["x-client-fingerprint"] != ""
}

# Verifica dinamica se il certificato è legato all'hardware (contiene OID TPM: 1.3.6.1.4.1.9999.1)
default is_tpm := false
is_tpm := true if {
    cert_raw := input.attributes.source.certificate
    cert_pem := urlquery.decode(cert_raw)
    certs := crypto.x509.parse_certificates(cert_pem)
    count(certs) > 0
    some ext in certs[0].Extensions
    ext.Id == [1, 3, 6, 1, 4, 1, 9999, 1]
}

# 3. DISPOSITIVO & TPM (device)
default device := "Personal Laptop (Software Only - No TPM)"
device := "Workstation TPM (OID 1.3.6.1.4 - Hardware Attested)" if {
    is_tpm
}

# 4. INDIRIZZO RETE (network_ip)
default network_ip := "0.0.0.0"
network_ip := input.attributes.source.address.socketAddress.address

# 5. RISORSA / COLLEZIONE (resource)
default resource := "utenti"
resource := "pazienti" if {
    contains(input.attributes.request.http.path, "patients")
}

# 6. OPERAZIONE / COMANDO (command)
default command := "connect()"
command := "find()" if {
    input.attributes.request.http.method == "GET"
}
command := "delete()" if {
    input.attributes.request.http.method == "DELETE"
}

# ----------------------------------------------------------------
# VALUTAZIONE PRINCIPALE: Consenti l'accesso e registra il log 6D
# ----------------------------------------------------------------
allow := true if {
    input.attributes.source.principal == alice_identity
    is_tpm
    print("[OPA-PDP]", json.marshal({
        "Log": "Access Allowed",
        "user": user,
        "software": software,
        "device": device,
        "network_ip": network_ip,
        "resource": resource,
        "command": command
    }))
} else := false if {
    # Se l'accesso è negato, stampiamo il log con "Access Denied"
    print("[OPA-PDP]", json.marshal({
        "Log": "Access Denied",
        "user": user,
        "software": software,
        "device": device,
        "network_ip": network_ip,
        "resource": resource,
        "command": command
    }))
}
