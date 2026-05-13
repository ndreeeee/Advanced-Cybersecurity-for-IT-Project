#!/bin/bash
# IDS (Snort) entrypoint: rsyslog + snort

# Configure rsyslog to forward to Splunk
mkdir -p /etc/rsyslog.d
cat > /etc/rsyslog.d/50-splunk.conf << 'EOF'
*.* @splunk:1514
EOF
# Ensure any existing rsyslog is killed to pick up new config
pkill -9 rsyslogd || true
rsyslogd 2>/dev/null || true

echo "[IDS] Rsyslog forwarding to splunk:1514 started."
echo "[IDS] Starting Snort IDS on eth0..."

# Snort in alert mode with syslog output (-s) + console
exec snort -s -A console -q -c /opt/etc/snort.conf -i eth0 -l /var/log/snort
