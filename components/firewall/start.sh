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

# --- 2. Base IPTables rules ---
# Log all FORWARD traffic before accepting (for Splunk visibility)
iptables -A FORWARD -j LOG --log-prefix "[FW-FORWARD] " --log-level info 2>/dev/null || true
# Default: allow everything (specific DROP rules added dynamically by PEP via /ban)
iptables -P FORWARD ACCEPT 2>/dev/null || true

echo "[FW] IPTables base rules configured."

# --- 3. Rsyslog → Splunk (UDP 1514) ---
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
