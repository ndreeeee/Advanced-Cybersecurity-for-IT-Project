package envoy.authz

import future.keywords.if

# 1. PRINCIPIO ZERO TRUST: Tutto è negato di default
default allow = false

# 2. ESTRAZIONE DATI (La tupla di Envoy)
# Envoy invia i dati tramite il plugin gRPC ext_authz. OPA li mette nell'oggetto "input".
user         := input.attributes.source.principal
network_ip   := input.attributes.source.address.socketAddress.address
action       := input.attributes.request.http.method
resource     := input.attributes.request.http.path

# Il JA3 (Software) e il Device di solito Envoy li inietta come Header HTTP personalizzati
software_ja3 := input.attributes.request.http.headers["x-ja3-fingerprint"]
device_id    := input.attributes.request.http.headers["x-device-id"]

# 3. LA REGOLA SUPREMA DI AUTORIZZAZIONE
allow if {
    # Condizione A: Chiama Splunk e ottieni il rischio di questo IP/JA3
    risk_score := get_risk_from_splunk(network_ip, software_ja3)

    # Condizione B: Il rischio deve essere accettabile (es. minore di 50)
    risk_score < 50

    # Condizione C: (Opzionale per ora) L'utente sta accedendo a una risorsa valida
    # startswith(resource, "/utenti")
}

# 4. INTEGRAZIONE CON SPLUNK (HTTP Send)
# Questa funzione interroga le API REST del vostro container Splunk
get_risk_from_splunk(ip, ja3) := risk if {
    # Costruiamo l'URL per le API di Splunk (sostituirete l'endpoint con quello del MLTK)
    url := sprintf("http://splunk-siem:8089/services/get_risk?ip=%v&ja3=%v", [ip, ja3])

    # OPA fa una chiamata HTTP verso Splunk
    response := http.send({
        "method": "GET",
        "url": url,
        "headers": {
            "Authorization": "Bearer IL_VOSTRO_TOKEN_SPLUNK"
        }
    })

    # Se Splunk risponde 200 OK, leggiamo il valore di rischio dal JSON
    response.status_code == 200
    risk := to_number(response.body.risk_score)
}

# 5. FAIL-SAFE (Cosa succede se Splunk è spento o irraggiungibile?)
# Se Splunk non risponde, per il principio Zero Trust assegniamo il rischio massimo (100)
# così l'accesso viene negato in automatico.
default get_risk_from_splunk(_, _) := 100