# HA202 local build for standalone CSQTT (no secrets or client binaries in GitHub).
# Existing HA202 vendor/csq-socks is retained; this is a dependency-only fix.
# python3-cryptography is required by /opt/csq-socks/link.py to parse
# encrypted csqtt:// links from protocol version 2.5.
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl python3 python3-cryptography iproute2 iptables util-linux procps \
      passwd iputils-ping && \
    rm -rf /var/lib/apt/lists/*
COPY vendor/csq-socks/ /opt/csq-socks/
COPY manager.py /app/manager.py
RUN chmod 755 /opt/csq-socks/csq-socks && mkdir -p /data/csq-socks && chmod 700 /data/csq-socks
ENTRYPOINT ["python3", "-u", "/app/manager.py"]
