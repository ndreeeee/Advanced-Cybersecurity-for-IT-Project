#!/bin/bash
# =============================================================
# Client Simulator (Hospital ZTA)
# Traffic flow: Client (mTLS) -> PEP (Envoy) -> OPA -> MongoDB
# =============================================================

echo "[*] Avvio simulatore client: $CLIENT_NAME ($CLIENT_ROLE)"
echo "[*] Generazione traffico verso il PEP (Envoy)..."
sleep 15  # Attendiamo che Envoy, OPA e Mongo siano pronti

# Puntiamo direttamente a Envoy in HTTPS (la porta dipende dal tuo docker-compose, es. 10001)
PEP_URL="https://pep-envoy:10001"

# Percorsi dei certificati (li monteremo tramite volumi nel docker-compose)
CACERT="/certs/ca.crt"
CLIENT_CERT="/certs/${CLIENT_NAME}.crt"
CLIENT_KEY="/certs/${CLIENT_NAME}.key"

# Funzione per fare chiamate curl in mTLS
# -s: silenzioso
# -k: ignora errori di hostname (utile in ambiente di test Docker)
# --cacert: per verificare che Envoy sia chi dice di essere
# --cert / --key: il nostro "distintivo" mTLS
make_request() {
    local method=$1
    local endpoint=$2
    local payload=$3

    if [ -n "$payload" ]; then
        curl -s -k -X "$method" \
             --cacert "$CACERT" --cert "$CLIENT_CERT" --key "$CLIENT_KEY" \
             -H "Content-Type: application/json" \
             -d "$payload" \
             "$PEP_URL$endpoint"
    else
        curl -s -k -X "$method" \
             --cacert "$CACERT" --cert "$CLIENT_CERT" --key "$CLIENT_KEY" \
             "$PEP_URL$endpoint"
    fi
}

while true; do
    if [ "$CLIENT_ROLE" = "medico" ]; then
        # Alice - Medico legittimo
        echo "[Alice] Richiesta lettura cartelle cliniche (Consentita):"
        make_request "GET" "/api/pazienti/cartelle"
        echo -e "\n"
        sleep 5

        echo "[Alice] Inserimento nuovo referto (Consentita):"
        make_request "POST" "/api/pazienti/referti" '{"paziente": "Mario Rossi", "diagnosi": "Influenza"}'
        echo -e "\n"
        sleep 10

    elif [ "$CLIENT_ROLE" = "kiosk" ]; then
        # Totem in corsia - Solo lettura
        echo "[Kiosk] Lettura parametri vitali (Consentita):"
        make_request "GET" "/api/pazienti/parametri"
        echo -e "\n"
        sleep 5

        echo "[Kiosk] Tentativo di scrittura referto (Bloccato da OPA):"
        make_request "POST" "/api/pazienti/referti" '{"paziente": "Luigi Bianchi", "diagnosi": "Falsa"}'
        echo -e "\n"
        sleep 10

    elif [ "$CLIENT_ROLE" = "hacker" ]; then
        # Bob - Dispositivo ostile o con certificato non valido
        echo "[Bob] Tentativo SQL/NoSQL Injection (Dovrebbe far scattare Snort/Firewall):"
        make_request "POST" "/api/pazienti/referti" '{"paziente": {"$gt": ""}}'
        echo -e "\n"
        sleep 5

        echo "[Bob] Tentativo scansione admin (Bloccato da OPA):"
        make_request "GET" "/api/admin/dump"
        echo -e "\n"
        sleep 5
    fi
done