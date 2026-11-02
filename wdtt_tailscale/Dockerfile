# Builds upstream GPLv3 wdttd inside the HAOS app build.
# PIN is the commit referenced by upstream's OpenWrt installer.
ARG BUILD_FROM=alpine:3.22
FROM golang:1.25-alpine AS build
RUN apk add --no-cache git ca-certificates
ARG WDTT_REF=b10e1506f17322061ae9ccd7546ca6fd015776ce
RUN git init /tmp/upstream \
  && cd /tmp/upstream \
  && git remote add origin https://github.com/cWDTT/WDTT-OpenWRT.git \
  && git fetch --depth=1 origin "${WDTT_REF}" \
  && git checkout --detach FETCH_HEAD
WORKDIR /tmp/upstream/wdtt-client/src
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/wdttd ./cmd/wdttd

FROM ${BUILD_FROM}
RUN apk add --no-cache python3 iproute2 wireguard-tools ca-certificates bind-tools
COPY --from=build /out/wdttd /usr/local/bin/wdttd
COPY controller.py /opt/wdtt/controller.py
COPY webui.py /opt/wdtt/webui.py
COPY web/ /opt/wdtt/web/
COPY run.sh /run.sh
# The upstream daemon probes /usr/libexec/wdtt/datapath for routing.
# Minimal HAOS implementation deliberately supports EXTERNAL mode only.
COPY datapath.sh /usr/libexec/wdtt/datapath
RUN chmod +x /run.sh /usr/libexec/wdtt/datapath /usr/local/bin/wdttd \
    && mkdir -p /etc/config /etc/wdtt /var/run/wdtt
CMD ["/run.sh"]
