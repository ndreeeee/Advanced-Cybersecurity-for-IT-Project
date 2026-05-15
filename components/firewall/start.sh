#!/bin/bash
# =============================================================
# Firewall container entrypoint
# 1. Enable IP forwarding
# 2. Set base iptables logging rules
# 3. Configure rsyslog to forward logs to Splunk
# 4. Start the FastAPI reverse proxy + management API
# =============================================================

set -e

# --- 1. IP Forwarding ---
sysctl -w net.ipv4.ip_forward=1 2>/dev/null || true

# --- 2. Base NFTables rules ---
# Flush existing rules
nft flush ruleset

# Create 'filter' table and 'forward' chain
nft add table ip filter
nft add chain ip filter forward { type filter hook forward priority 0 \; policy accept \; }

# Log all FORWARD traffic (for Splunk visibility)
nft add rule ip filter forward counter log prefix "[FW-FORWARD] "

echo "[FW] NFTables base rules configured."

# --- 3. Rsyslog â†’ Splunk (UDP 1514) ---
if command -v rsyslogd &> /dev/null; then
    cat > /etc/rsyslog.d/50-splunk.conf << 'EOF'
# Forward all logs to Splunk SIEM
*.* @splunk:1514
EOF
    # Ensure any existing rsyslog is killed to pick up new config
    pkill -9 rsyslogd || true
    rsyslogd 2>/dev/null || true
    echo "[FW] Rsyslog forwarding to splunk:1514 started."
fi

# --- 4. Start FastAPI ---
echo "[FW] Starting reverse proxy on port 80 ..."
uvicorn fw_api:app --host 0.0.0.0 --port 80
