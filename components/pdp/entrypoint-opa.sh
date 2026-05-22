#!/bin/sh
set -e
mkdir -p /var/log/opa
exec /opa run \
  --server \
  --addr=0.0.0.0:8181 \
  --log-level=info \
  --log-format=json \
  --config-file=/etc/opa/config.yaml \
  /policy/rules.rego >> /var/log/opa/decision.log 2>&1
