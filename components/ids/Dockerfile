# 1. Partiamo dall'impasto che usavi tu (così le tue regole funzioneranno al 100%)
FROM linton/docker-snort:latest

# 2. Creiamo la directory che Fluent Bit leggerà per prendere i log
RUN mkdir -p /var/log/snort

# 3. Copiamo le tue regole e (se lo hai) il tuo file di configurazione
# (Assicurati che i percorsi di destinazione coincidano con dove li cerca il tuo Snort)
COPY local.rules /etc/snort/rules/local.rules
# COPY snort.conf /etc/snort/snort.conf  <-- De-commenta questa riga se hai un tuo snort.conf nella cartella

# 4. Copiamo il nostro nuovo script snello (senza rsyslog)
COPY start.sh /start.sh
RUN chmod +x /start.sh

# 5. Diciamo al container di partire eseguendo il nostro script
ENTRYPOINT ["/start.sh"]