#!/bin/bash
# IDS (Snort) entrypoint: rsyslog + snort

# Configure rsyslog to forward to Splunk
mkdir -p /etc/rsyslog.d
cat > /etc/rsyslog.d/50-splunk.conf << 'EOF'
*.* @splunk:1514
EOF
rsyslogd 2>/dev/null || true

echo "[IDS] Rsyslog forwarding to splunk:1514 started."
echo "[IDS] Starting Snort IDS on eth0..."

# Snort in alert mode with syslog output + console
exec snort -A console -q -c /opt/etc/snort.conf -i eth0 -l /var/log/snort
