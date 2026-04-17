#!/bin/bash
# start.sh per il firewall

# 1. Configurazione IPTables di default
# Assicuriamoci che abiliti il forward IPV4
sysctl -w net.ipv4.ip_forward=1

# Politiche di base: logga prima del blocco? Per ora lasciamo default ACCEPT per la demo 
# per non rendere la rete introvabile se sbagliamo configurazioni, ma pronti a bloccare via API.

# Possiamo forzare il traffico dal firewall ad andare verso proxy/snort usando NAT (opzionale per ora, dipende se usiamo routing statico).

# 2. Lancia l'API in foreground
echo "Avvio firewall API su porta 8081..."
uvicorn fw_api:app --host 0.0.0.0 --port 8081
