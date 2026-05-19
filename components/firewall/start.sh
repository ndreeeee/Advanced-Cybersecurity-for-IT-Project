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

# Create a dynamic set for banned IPs (denylist)
nft add set ip filter denylist { type ipv4_addr \; }

# Master rule: DROP anything in the denylist
nft add rule ip filter forward ip saddr @denylist counter drop

# NFTables NAT configuration (using static IP for Envoy PEP)
echo "[FW] Applying NAT rules (Target: 10.10.10.100)..."
TARGET_IP="10.10.10.100"

# Apply NAT rules directly using static IP
if nft add table ip nat 2>/dev/null && \
   nft add chain ip nat prerouting { type nat hook prerouting priority -100 \; } 2>/dev/null && \
   nft add chain ip nat postrouting { type nat hook postrouting priority 100 \; } 2>/dev/null && \
   nft add rule ip nat prerouting tcp dport 27017 dnat to $TARGET_IP:27017 2>/dev/null && \
   nft add rule ip nat postrouting ip daddr $TARGET_IP masquerade 2>/dev/null; then
  echo "[FW] NAT rules applied successfully using static IP."
else
  echo "[FW] ERROR: Failed to apply NFTables rules."
  exit 1
fi

# Log all other FORWARD traffic (for Splunk visibility)
nft add rule ip filter forward counter log prefix \"[FW-FORWARD] \"

echo "[FW] NFTables configured with dynamic denylist set."

# --- 3. Rsyslog â†’ Splunk (UDP 1514) ---
if command -v rsyslogd &> /dev/null; then
    cat > /etc/rsyslog.d/50-splunk.conf << 'EOF'
# Forward all logs to Splunk SIEM
*.* @splunk-siem:1514
EOF
    # Ensure any existing rsyslog is killed to pick up new config
    pkill -9 rsyslogd || true
    rsyslogd 2>/dev/null || true
    echo "[FW] Rsyslog forwarding to splunk:1514 started."
fi

# --- 4. Start FastAPI ---
echo "[FW] Starting reverse proxy on port 80 ..."
uvicorn fw_api:app --host 0.0.0.0 --port 80
