FROM ubuntu/squid:5.2-22.04_beta

# Install rsyslog for log forwarding to Splunk
RUN apt-get update && apt-get install -y rsyslog && rm -rf /var/lib/apt/lists/*

COPY squid.conf /etc/squid/squid.conf
COPY start.sh /start.sh
RUN chmod +x /start.sh

EXPOSE 3128

# Use bash explicitly so a stray CRLF on the shebang cannot break container start
ENTRYPOINT ["/bin/bash", "/start.sh"]
