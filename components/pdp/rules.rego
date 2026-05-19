package envoy.authz

import rego.v1

# ================================================================
# POLICY ZTA - Zero Trust Authorization Engine
# Flusso: Envoy estrae la SPIFFE ID dalla SAN del certificato mTLS
# e la passa come source.principal nella richiesta ext_authz gRPC
# ================================================================

# Di default, tutto è BLOCCATO (deny-all)
default allow := false

# ----------------------------------------------------------------
# Identità SPIFFE valide (estratte dalla SAN del certificato mTLS)
# ----------------------------------------------------------------
alice_identity := "spiffe://zta.hospital/ns/default/sa/client-alice"
bob_identity   := "spiffe://zta.hospital/ns/default/sa/client-bob"

# ----------------------------------------------------------------
# REGOLA 1: Alice (Medico con certificato hardware TPM) → ACCESSO COMPLETO
# Il certificato di Alice ha un'estensione OID custom (TPM attestation)
# che viene verificata lato PKI prima dell'emissione.
# ----------------------------------------------------------------
allow if {
    input.attributes.source.principal == alice_identity
    print("[OPA-PDP] ACCESSO AUTORIZZATO: Alice - identità SPIFFE valida, TPM attestato")
}

# ----------------------------------------------------------------
# REGOLA 2: Bob (Solo software, nessun TPM) → ACCESSO NEGATO
# Anche se il certificato è firmato dalla CA, la policy ZTA
# richiede attestazione hardware per accedere ai dati clinici.
# ----------------------------------------------------------------
deny_reason["certificato_senza_tpm"] if {
    input.attributes.source.principal == bob_identity
    print("[OPA-PDP] ACCESSO NEGATO: Bob - certificato software-only, nessun TPM attestato")
}

# ----------------------------------------------------------------
# REGOLA 3: Qualsiasi identità sconosciuta → ACCESSO NEGATO
# ----------------------------------------------------------------
deny_reason["identita_sconosciuta"] if {
    principal := input.attributes.source.principal
    principal != alice_identity
    principal != bob_identity
    print(sprintf("[OPA-PDP] ACCESSO NEGATO: Identità sconosciuta → %v", [principal]))
}
