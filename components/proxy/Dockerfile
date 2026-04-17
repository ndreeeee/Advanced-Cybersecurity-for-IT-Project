FROM ubuntu/squid:5.2-22.04_beta
COPY squid.conf /etc/squid/squid.conf
EXPOSE 3128
ENTRYPOINT ["/usr/sbin/squid", "-N", "-d", "1"]
