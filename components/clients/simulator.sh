#!/bin/bash
# =============================================================
# Client Simulator
# Traffic flow: Client → Firewall → Squid → PEP → API Server
# =============================================================

echo "[*] Client avviato: $CLIENT_NAME ($CLIENT_ROLE)"
echo "[*] Traffico diretto a: http://firewall (primo anello ZTA)"
sleep 20  # Attendiamo che tutta la catena sia pronta

# Entry point della catena Zero Trust (il firewall)
GATEWAY="http://firewall"

while true; do
    if [ "$CLIENT_ROLE" = "legit" ]; then
        # Alice — traffico completamente legittimo
        echo "[Alice] Chiedo saldo:"
        curl -s -H "X-Forwarded-For: $CLIENT_IP" "$GATEWAY/api/v1/balance" 2>/dev/null
        echo ""
        sleep 5

        echo "[Alice] Faccio bonifico:"
        curl -s -X POST -H "X-Forwarded-For: $CLIENT_IP" "$GATEWAY/api/v1/transfer" 2>/dev/null
        echo ""
        sleep 10

    elif [ "$CLIENT_ROLE" = "kiosk" ]; then
        # Totem filiale — solo lettura saldi
        echo "[Kiosk] Chiedo saldo:"
        curl -s -H "X-Forwarded-For: $CLIENT_IP" "$GATEWAY/api/v1/balance" 2>/dev/null
        echo ""
        sleep 5

    elif [ "$CLIENT_ROLE" = "suspect" ]; then
        # Bob — dispositivo compromesso
        echo "[Bob] Tentativo SQL Injection + accesso admin:"
        curl -s -H "X-Forwarded-For: $CLIENT_IP" "$GATEWAY/api/v1/admin/dump?id=1'%20OR%201=1--" 2>/dev/null
        echo ""
        sleep 5

        echo "[Bob] Tentativo accesso transfer:"
        curl -s -X POST -H "X-Forwarded-For: $CLIENT_IP" "$GATEWAY/api/v1/transfer" 2>/dev/null
        echo ""
        sleep 5

        echo "[Bob] Tentativo navigazione dominio malevolo via Proxy:"
        curl -s -x http://proxy:3128 http://evil-malware-domain.com 2>/dev/null
        echo ""
        sleep 5
    fi
done
