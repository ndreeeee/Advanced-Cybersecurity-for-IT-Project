package envoy.authz

import rego.v1

# Di default, tutto è bloccato
default allow := false

# Alice è "legit" e ha accesso tramite identità SPIFFE verificata via mTLS
allow if {
    input.attributes.source.principal == "spiffe://zta.hospital/ns/default/sa/client-alice"
}

# Messaggio di log per motivi di audit (visibile nei log di OPA)
log_decision if {
    allow
    print("[OPA-PDP] Accesso AUTORIZZATO per Alice (Identità SPIFFE valida)")
}

log_decision if {
    not allow
    print("[OPA-PDP] Accesso NEGATO: Identità non valida o non autorizzata")
}
