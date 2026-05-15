FROM linton/docker-snort:latest

# Install rsyslog for log forwarding to Splunk
RUN apt-get update && apt-get install -y rsyslog && rm -rf /var/lib/apt/lists/* || true

COPY local.rules /etc/snort/rules/local.rules
COPY start.sh /start.sh
RUN chmod +x /start.sh

CMD ["/bin/bash", "/start.sh"]
