#!/bin/bash
echo "Avvio di Snort su eth2 (rete esterna Charlie 192.168.100.0/24)..."
mkdir -p /var/log/snort
 
# -A fast: scrive alert leggibili in /var/log/snort/alert
# -l /var/log/snort: cartella di output
# -i eth2: interfaccia rete esterna (Charlie)
# -k none: disabilita checksum validation (necessario in ambiente Docker)
exec snort -q -i eth2 -c /opt/etc/snort.conf -l /var/log/snort -A fast -k none