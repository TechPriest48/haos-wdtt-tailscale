#!/bin/sh
# Public, sanitized reconstruction — fill settings locally before use.
set -eu

: "${HA202_TAILSCALE_IP:?Set target Tailscale IP locally (do not publish)}"
: "${HA202_SSH_HOST_KEY_SHA256:?Set verified ed25519 SHA256 host-key fingerprint locally}"
: "${HA202_SSH_USER:?Set SSH user locally}"

mkdir -p /data
chmod 700 /data

if [ ! -f /data/id_ed25519 ]; then
  ssh-keygen -q -t ed25519 -N '' -C 'ha200-terminal202' -f /data/id_ed25519
fi
chmod 600 /data/id_ed25519

ssh-keyscan -T 6 -t ed25519 "$HA202_TAILSCALE_IP" 2>/dev/null > /data/known_hosts.pending
ACTUAL=$(ssh-keygen -lf /data/known_hosts.pending -E sha256 | awk 'NR==1 { print $2 }')
if [ "$ACTUAL" != "$HA202_SSH_HOST_KEY_SHA256" ]; then
  echo "ERROR: remote SSH host key fingerprint mismatch"
  rm -f /data/known_hosts.pending
  exit 1
fi
mv /data/known_hosts.pending /data/known_hosts
chmod 600 /data/known_hosts

echo 'Add the following PUBLIC key to HA202 Advanced SSH authorized_keys:'
cat /data/id_ed25519.pub

exec ttyd -W -p 7681 /connect.sh
