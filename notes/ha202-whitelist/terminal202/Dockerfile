FROM ghcr.io/home-assistant/base:3.24

RUN apk add --no-cache openssh-client ttyd

COPY run.sh /run.sh
COPY connect.sh /connect.sh
RUN chmod +x /run.sh /connect.sh

CMD ["/run.sh"]
