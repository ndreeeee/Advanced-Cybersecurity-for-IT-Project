#!/bin/bash
echo "Avvio di Snort IDS in modalità Cloud-Native (Zero Trust)..."

# Creiamo la cartella dei log nel caso non esista, per evitare crash
mkdir -p /var/log/snort

# Puliamo eventuali vecchi "file lucchetto" di esecuzioni precedenti
rm -f /var/run/snort_eth0.pid

# Avviamo Snort
# -i eth0 : Ascolta sull'interfaccia principale (che abbiamo attaccato a Envoy)
# -c      : Usa il file di configurazione base
# -l      : Scrivi i file di log nella cartella condivisa con Fluent Bit!
exec snort -i eth0 -c /opt/etc/snort.conf -l /var/log/snort