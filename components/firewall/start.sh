#!/bin/bash
sysctl -w net.ipv4.ip_forward=1
echo "Avvio firewall API su porta 8081..."
uvicorn fw_api:app --host 0.0.0.0 --port 8081
