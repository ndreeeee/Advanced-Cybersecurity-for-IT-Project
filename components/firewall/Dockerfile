FROM ubuntu:22.04

# Evitiamo blocchi o domande durante la build
ENV DEBIAN_FRONTEND=noninteractive

# Via rsyslog! Installiamo solo ciò che serve alla rete e all'API
RUN apt-get update && apt-get install -y \
    nftables \
    ulogd2 \
    python3 \
    python3-pip \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Creiamo la cartella dei log che verrà aspirata da Fluent Bit
RUN mkdir -p /var/log/nftables

WORKDIR /app

# Gestione delle dipendenze Python
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# Copia dei sorgenti e dello script di avvio
COPY fw_api.py .
COPY start.sh .
RUN chmod +x start.sh

# Esponiamo la porta per l'API di gestione del firewall
EXPOSE 80

CMD ["./start.sh"]