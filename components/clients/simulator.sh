#!/bin/bash
# Simulatore di traffico in base al ruolo del container

echo "[*] Avvio operatività client: $CLIENT_NAME ($CLIENT_ROLE)"
sleep 15 # Attendiamo che il server e pep si avviino

while true; do
    if [ "$CLIENT_ROLE" = "legit" ]; then
        # Alice fa normali query di balance e trasferimenti
        echo "[Alice] Chiedo saldo:"
        curl -s http://pep/api/v1/balance
        sleep 5
        echo "[Alice] Faccio bonifico:"
        curl -s -X POST http://pep/api/v1/transfer
        sleep 10

    elif [ "$CLIENT_ROLE" = "kiosk" ]; then
        # Il totem fa solo balance (trust base limitato)
        echo "[Kiosk] Chiedo saldo:"
        curl -s http://pep/api/v1/balance
        sleep 5
        
    elif [ "$CLIENT_ROLE" = "suspect" ]; then
        # Bob lancia attacchi e naviga su proxy malevoli
        echo "[Bob Malware] Tentativo Proxy verso server Comando&Controllo:"
        curl -s -x http://proxy:3128 http://evil-malware-domain.com
        sleep 5
        echo "[Bob Malware] Tentativo esfiltrazione dati banca (SQL Injection + Accesso Admin):"
        curl -s "http://pep/api/v1/admin/dump?id=1' OR 1=1--"
        sleep 10
    fi
done
