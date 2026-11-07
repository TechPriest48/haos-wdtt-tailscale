#!/bin/sh
set -eu

: "${HA202_TAILSCALE_IP:?Set target IP}"
: "${HA202_SSH_USER:?Set SSH username}"

while :; do
  printf '\n===============================================\n'
  printf ' ТЕРМИНАЛ СЕРВЕРА 202 — TAILSCALE\n'
  printf ' Все команды выполняются на сервере 202.\n'
  printf '===============================================\n\n'

  ssh -tt -i /data/id_ed25519 \
    -o IdentitiesOnly=yes \
    -o StrictHostKeyChecking=yes \
    -o UserKnownHostsFile=/data/known_hosts \
    -o ConnectTimeout=8 \
    -o ServerAliveInterval=30 \
    -o ServerAliveCountMax=3 \
    "${HA202_SSH_USER}@${HA202_TAILSCALE_IP}" || true

  printf '\nSSH disconnected. Press Enter to retry.\n'
  read -r _ || exit 0
done
