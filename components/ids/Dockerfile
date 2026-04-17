FROM linton/docker-snort:latest
# Questo container ha già snort pre-installato
COPY local.rules /etc/snort/rules/local.rules
CMD ["snort", "-A", "console", "-q", "-c", "/etc/snort/snort.conf", "-i", "eth0"]
