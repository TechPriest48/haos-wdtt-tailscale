#!/bin/sh
# Isolation-only watchdog timer smoke test. NEVER changes network routes.
# Must run in a Docker container with --network none --cap-drop ALL,
# --read-only and a dedicated writable /state test volume.
set -eu
[ "$#" -eq 1 ] || { echo 'usage: watchdog-sandbox.sh SESSION_ID' >&2; exit 2; }
session=$1
case "$session" in ''|*[!A-Za-z0-9_-]*) echo 'invalid session id' >&2; exit 2;; esac
[ -d /state ] || { echo 'no /state volume' >&2; exit 3; }
[ ! -e "/state/DEADLINE-$session" ] || { echo 'duplicate session id' >&2; exit 4; }
[ ! -e "/state/CONFIRMED-$session" ] || { echo 'stale confirmation for this session' >&2; exit 4; }
now=$(date +%s)
deadline=$((now + 8))
printf '%s\n' "$deadline" > "/state/DEADLINE-$session"
printf 'TEST_ARMED session=%s deadline_epoch=%s network=none caps=none\n' "$session" "$deadline"
while :; do
    if [ -f "/state/CONFIRMED-$session" ]; then
        printf 'TEST_CONFIRMED session=%s no_routing_action\n' "$session"
        exit 0
    fi
    now=$(date +%s)
    if [ "$now" -ge "$deadline" ]; then
        date -u '+%Y-%m-%dT%H:%M:%SZ' > "/state/EXPIRED-$session"
        rm -f "/state/DEADLINE-$session"
        printf 'TEST_EXPIRED session=%s state_marker_written no_routing_action\n' "$session"
        exit 0
    fi
    sleep 1
done
