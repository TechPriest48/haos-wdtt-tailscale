# HA202-specific build: reuse installed, verified csq-socks runtime image.
# Deliberately DO NOT mount the host Docker socket or import old secrets.
FROM csq-socks:local
COPY manager.py /app/manager.py
RUN mkdir -p /data/csq-socks /app && chmod 700 /data/csq-socks
ENTRYPOINT ["python3", "-u", "/app/manager.py"]
