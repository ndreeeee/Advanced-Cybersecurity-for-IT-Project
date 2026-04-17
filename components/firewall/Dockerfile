FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    iptables \
    python3 \
    python3-pip \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .

RUN pip3 install --no-cache-dir -r requirements.txt

COPY fw_api.py .
COPY start.sh .
RUN chmod +x start.sh

EXPOSE 8081

CMD ["./start.sh"]
