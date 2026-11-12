# HA202 local build: keep all csqtt client binaries on the user's server.
# vendor/csq-socks must be copied locally from the existing csq-socks image;
# do not commit/upload vendor binaries or connection credentials to GitHub.
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl python3 iproute2 iptables util-linux procps \
      passwd iputils-ping && \
    rm -rf /var/lib/apt/lists/*
COPY vendor/csq-socks/ /opt/csq-socks/
COPY manager.py /app/manager.py
RUN chmod 755 /opt/csq-socks/csq-socks && mkdir -p /data/csq-socks && chmod 700 /data/csq-socks
ENTRYPOINT ["python3", "-u", "/app/manager.py"]
