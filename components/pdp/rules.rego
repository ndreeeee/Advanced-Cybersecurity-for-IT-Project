package envoy.authz

import rego.v1

# =============================================================================
# ZTA 2026 — OPA PDP + SIEM (workflow.md Fase 3)
# -----------------------------------------------------------------------------
# 1. Envoy invia mTLS + JA3 + path/method (HTTP) o mongo_proxy (Mongo)
# 2. OPA interroga Trust Engine → dati da Splunk (density/frequenza) + Mongo
# 3. Allow solo se: identità valida + TPM (se richiesto) + trust + risk SIEM
# =============================================================================

default allow := false

alice_identity := "spiffe://zta.hospital/ns/default/sa/client-alice"
bob_identity := "spiffe://zta.hospital/ns/default/sa/client-bob"

# --- Tipo traffico ---
default is_http := false
is_http if {
	input.attributes.request.http.method != ""
}

default is_mongo := false
is_mongo if {
	input.attributes.metadataContext.filterMetadata["envoy.filters.network.mongo_proxy"]
}

# --- ZTA 6D ---
default user := "unknown"
user := regex.replace(regex.replace(input.attributes.source.principal, "^.*/", ""), "^client-", "")

default software := "unknown"
software := input.attributes.metadataContext.filterMetadata["envoy.filters.listener.tls_inspector"]["ja3"] if {
	input.attributes.metadataContext.filterMetadata["envoy.filters.listener.tls_inspector"]["ja3"] != ""
}

software := input.attributes.request.http.headers["x-client-fingerprint"] if {
	is_http
	not input.attributes.metadataContext.filterMetadata["envoy.filters.listener.tls_inspector"]["ja3"]
	input.attributes.request.http.headers["x-client-fingerprint"] != ""
}

default is_tpm := false
is_tpm if {
	cert_raw := input.attributes.source.certificate
	cert_pem := urlquery.decode(cert_raw)
	certs := crypto.x509.parse_certificates(cert_pem)
	count(certs) > 0
	some ext in certs[0].Extensions
	ext.Id == [1, 3, 6, 1, 4, 1, 9999, 1]
}

default device := "Software-only (no TPM attestation)"
device := "Hardware TPM attested (OID 1.3.6.1.4.1.9999.1)" if {
	is_tpm
}

default network_ip := "0.0.0.0"
network_ip := input.attributes.source.address.socketAddress.address

default resource := "unknown"
resource := input.attributes.request.http.path if {
	is_http
}

resource := "mongodb/patients" if {
	is_mongo
}

default command := "connect"
command := input.attributes.request.http.method if {
	is_http
}

command := "mongo_query" if {
	is_mongo
}

# --- Contesto SIEM (Splunk via Trust Engine — non PostgreSQL) ---
default siem := {
	"trust_score": 0,
	"risk_score": 100,
	"trust_min_required": 0.4,
	"risk_max_allowed": 50,
	"attack_probability": 1,
	"deny_count": 0,
	"allow_count": 0,
	"total_events": 0,
	"max_z_score": 0,
	"note": "fail_safe",
}

siem := resp.body if {
	url := sprintf(
		"http://zta-trust-engine:8182/v1/context?principal=%s&network_ip=%s&user=%s",
		[
			urlquery.encode(input.attributes.source.principal),
			urlquery.encode(network_ip),
			urlquery.encode(user),
		],
	)
	resp := http.send({
		"method": "GET",
		"url": url,
		"force_cache": true,
		"force_cache_duration_seconds": 3,
		"raise_error": true,
		"timeout": "2s",
	})
	print("[DEBUG HTTP]", resp)
	resp.status_code == 200
}

trust_ok if {
	siem.trust_score >= siem.trust_min_required
}

risk_ok if {
	siem.risk_score < siem.risk_max_allowed
}

# --- Regole di autorizzazione ---

is_authorized if {
	input.attributes.source.principal == alice_identity
	is_tpm
	trust_ok
	risk_ok
}

is_authorized if {
	input.attributes.source.principal == bob_identity
	is_tpm
	trust_ok
	risk_ok
}

allow if {
	is_authorized
	log_decision("Access Allowed")
} else if {
	log_decision("Access Denied")
	false
}

log_decision(msg) if {
	print("[OPA-PDP]", json.marshal({
		"Log": msg,
		"user": user,
		"software": software,
		"device": device,
		"network_ip": network_ip,
		"resource": resource,
		"command": command,
		"principal": input.attributes.source.principal,
		"trust_score": siem.trust_score,
		"risk_score": siem.risk_score,
		"attack_probability": siem.attack_probability,
		"deny_count": siem.deny_count,
		"max_z_score": siem.max_z_score,
	}))
}
