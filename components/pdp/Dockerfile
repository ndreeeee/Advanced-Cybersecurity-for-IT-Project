FROM openpolicyagent/opa:latest-envoy AS opa-source
FROM debian:bookworm-slim

# Copia l'eseguibile OPA con il plugin Envoy
COPY --from=opa-source /opa /opa

# Aggiungiamo un utente non root per sicurezza (opzionale ma consigliato)
RUN useradd -u 1000 -m nonroot
RUN mkdir -p /var/log/opa && chown nonroot:nonroot /var/log/opa

USER nonroot
ENTRYPOINT ["sh", "-c"]
