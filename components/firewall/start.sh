#!/bin/bash
# =============================================================
# ZTA Firewall Container Entrypoint (NFTables L4 NAT + API)
# =============================================================

set -e
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
nft add chain ip filter forward { type filter hook forward priority 0 \; policy accept \; }

# --- 4. LA MAGIA: Il Port Forwarding (DNAT) verso Envoy ---
nft add table ip nat
nft add chain ip nat prerouting { type nat hook prerouting priority -100 \; }
nft add chain ip nat postrouting { type nat hook postrouting priority 100 \; }

# Inoltra tutto il traffico TCP in arrivo sulla porta 8443 verso Envoy (che decifrerà l'mTLS) - CONTATORI ATTIVI
nft add rule ip nat prerouting tcp dport 8443 counter dnat to $ENVOY_IP:8443

# SNAT (Masquerade) per fare in modo che Envoy risponda al Firewall, e il Firewall ad Alice - CONTATORI ATTIVI
nft add rule ip nat postrouting ip daddr $ENVOY_IP tcp dport 8443 counter masquerade
echo "[FW] Port Forwarding L4 attivato con successo (Porta 8443)."

# --- 5. Avvio dell'API di Management ---
echo "[FW] Avvio della Management API (Porta 80)..."
exec uvicorn fw_api:app --host 0.0.0.0 --port 80