FROM alpine:latest
RUN apk add --no-cache curl bash jq
COPY simulator.sh /simulator.sh
RUN chmod +x /simulator.sh
CMD ["/simulator.sh"]
