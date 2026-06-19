#!/bin/bash
# =============================================================
# ZTA Firewall Container Entrypoint (NFTables L4 NAT + API)
# =============================================================

set -e
# Configura e avvia ulogd2 in background per i log di rete
sed -i 's|file="/var/log/ulog/syslogemu.log"|file="/var/log/nftables/firewall.log"|g' /etc/ulogd.conf
ulogd -d
echo "[FW] Inizializzazione Firewall Zero Trust..."

# --- 1. IP Forwarding ---
sysctl -w net.ipv4.ip_forward=1 2>/dev/null || true

# --- 2. Risoluzione DNS di Envoy ---
# nftables ha bisogno dell'IP esatto per fare il NAT
ENVOY_IP=""
while [ -z "$ENVOY_IP" ]; do
    echo "[FW] Cerco l'IP di Envoy (zta-envoy) sulla rete backend..."
    # getent è nativo su Ubuntu, risolve il DNS interno di Docker
    ENVOY_IP=$(getent hosts zta-envoy | awk '{ print $1 }')
    sleep 1
done
echo "[FW] Trovato Envoy all'IP: $ENVOY_IP"

# --- 3. Inizializzazione Base NFTables ---
echo "[FW] Configurazione regole NFTables..."
nft flush ruleset
nft add table ip filter
nft add chain ip filter input { type filter hook input priority 0 \; policy accept \; }
# Crea il set per i ban dinamici della Management API
nft add set ip filter denylist { type ipv4_addr \; }
nft add chain ip filter forward { type filter hook forward priority 0 \; policy accept \; }
# Regole di DROP per gli IP bannati dalla Management API
nft add rule ip filter forward ip saddr @denylist counter drop
nft add rule ip filter input ip saddr @denylist counter drop

# --- 4. LA MAGIA: Il Port Forwarding (DNAT) verso Envoy ---
nft add table ip nat
nft add chain ip nat prerouting { type nat hook prerouting priority -100 \; }
nft add chain ip nat postrouting { type nat hook postrouting priority 100 \; }

# 4.1 Inoltra tutto il traffico TCP legittimo sulla porta 8443 verso Envoy
nft add rule ip nat prerouting tcp dport 8443 counter dnat to $ENVOY_IP:8443

# 4.2 Inoltra il traffico TCP MongoDB sulla porta 27017 (DB) verso Envoy
nft add rule ip nat prerouting tcp dport 27017 counter dnat to $ENVOY_IP:27017
nft add rule ip nat postrouting ip daddr $ENVOY_IP tcp dport 27017 counter masquerade
echo "[FW] Port Forwarding L4 attivato con successo (Porte 8443 e 27017)."

# SNAT (Masquerade) per il traffico legittimo
nft add rule ip nat postrouting ip daddr $ENVOY_IP tcp dport 8443 counter masquerade
echo "[FW] Port Forwarding L4 attivato con successo (Porta 8443)."

# 4.3 LA TRAPPOLA: Log e Drop di tutto il traffico che cerca di aggirare Envoy (es. porta 8000)
echo "[FW] Configurazione Logging e Blocco per porte non autorizzate..."
# Prima inviamo il log a ulogd2 (group 0)
nft add rule ip nat prerouting tcp dport 8000 log group 0 prefix \"[NFT-BLOCK] \" counter
# Poi droppiamo istantaneamente il pacchetto
nft add rule ip nat prerouting tcp dport 8000 drop


# --- 5. Avvio dell'API di Management ---
echo "[FW] Avvio della Management API (Porta 80)..."
exec uvicorn fw_api:app --host 0.0.0.0 --port 80