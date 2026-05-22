FROM openpolicyagent/opa:latest-envoy AS opa_bin

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates bash \
    && rm -rf /var/lib/apt/lists/*

COPY --from=opa_bin /opa /opa
RUN mkdir -p /var/log/opa /policy && chmod 777 /var/log/opa

COPY rules.rego /policy/rules.rego
COPY opa-config.yaml /etc/opa/config.yaml
COPY entrypoint-opa.sh /entrypoint-opa.sh
RUN chmod +x /entrypoint-opa.sh

EXPOSE 8181 9191
ENTRYPOINT ["/entrypoint-opa.sh"]
