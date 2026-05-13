#!/bin/bash
# Proxy (Squid) entrypoint: rsyslog + squid

# Configure rsyslog to forward to Splunk
cat > /etc/rsyslog.d/50-splunk.conf << 'EOF'
*.* @splunk:1514
EOF
# Ensure any existing rsyslog is killed to pick up new config
pkill -9 rsyslogd || true
rsyslogd 2>/dev/null || true

echo "[PROXY] Rsyslog forwarding to splunk:1514 started."
echo "[PROXY] Starting Squid in reverse proxy mode..."

mkdir -p /var/log/squid
touch /var/log/squid/access.log /var/log/squid/cache.log
chown -R proxy:proxy /var/log/squid

/usr/sbin/squid -N -d 1 &
SQUID_PID=$!

tail -f /var/log/squid/access.log &
wait $SQUID_PID
