#!/bin/sh
# HA202 observer-only whitelist monitor. Does NOT alter routes, Tailscale or Docker.
# Run from the HA202 SSH add-on with host-network curl access.
set -eu
command -v curl >/dev/null 2>&1 || { echo 'ERROR=curl_missing' >&2; exit 2; }
rounds=3
interval=20
if [ "$#" -gt 0 ]; then
    case "$1" in
        --once) rounds=1; interval=0 ;;
        *) echo 'Usage: sh healthcheck-observe.sh [--once]' >&2; exit 2 ;;
    esac
fi
proxy='socks5h://127.0.0.1:11990'
check() {
    mode=$1
    site=$2
    url=$3
    if [ "$mode" = direct ]; then
        if result=$(curl -4 --fail --silent --show-error --location --connect-timeout 4 --max-time 10 --output /dev/null --write-out '%{http_code}:%{time_total}' --noproxy '*' "$url" 2>/dev/null); then
            ok=1
        else
            ok=0
        fi
    else
        if result=$(curl -4 --fail --silent --show-error --location --connect-timeout 4 --max-time 10 --output /dev/null --write-out '%{http_code}:%{time_total}' --proxy "$proxy" "$url" 2>/dev/null); then
            ok=1
        else
            ok=0
        fi
    fi
    if [ "$ok" -eq 0 ]; then
        printf 'probe path=%s site=%s status=FAIL\n' "$mode" "$site"
        return 1
    fi
    code=$(printf '%s' "$result" | cut -d: -f1)
    sec=$(printf '%s' "$result" | cut -d: -f2)
    whole=$(printf '%s' "$sec" | cut -d. -f1)
    case "$whole" in ''|*[!0-9]*) whole=999 ;; esac
    if [ "$mode" = proxy ] && [ "$whole" -ge 8 ]; then
        printf 'probe path=%s site=%s status=SLOW code=%s seconds=%s\n' "$mode" "$site" "$code" "$sec"
        return 1
    fi
    printf 'probe path=%s site=%s status=OK code=%s seconds=%s\n' "$mode" "$site" "$code" "$sec"
    return 0
}
whitelist_streak=0
direct_streak=0
round=1
while [ "$round" -le "$rounds" ]; do
    printf 'ROUND=%s\n' "$round"
    direct_ok=0
    proxy_ok=0
    for site in google cloudflare github; do
        case "$site" in
            google) url=https://www.google.com/generate_204 ;;
            cloudflare) url=https://www.cloudflare.com/ ;;
            github) url=https://github.com/ ;;
        esac
        if check direct "$site" "$url"; then direct_ok=$((direct_ok + 1)); fi
        if check proxy "$site" "$url"; then proxy_ok=$((proxy_ok + 1)); fi
    done
    if [ "$direct_ok" -le 1 ] && [ "$proxy_ok" -ge 2 ]; then
        classification=WHITELIST_CANDIDATE
        whitelist_streak=$((whitelist_streak + 1))
        direct_streak=0
    elif [ "$direct_ok" -eq 3 ]; then
        classification=DIRECT_HEALTHY
        direct_streak=$((direct_streak + 1))
        whitelist_streak=0
    elif [ "$proxy_ok" -lt 2 ]; then
        classification=PROXY_NOT_READY
        whitelist_streak=0
        direct_streak=0
    else
        classification=INCONCLUSIVE
        whitelist_streak=0
        direct_streak=0
    fi
    printf 'classification=%s direct=%s/3 proxy_fast=%s/3 whitelist_streak=%s direct_streak=%s\n' "$classification" "$direct_ok" "$proxy_ok" "$whitelist_streak" "$direct_streak"
    if [ "$round" -lt "$rounds" ]; then sleep "$interval"; fi
    round=$((round + 1))
done
if [ "$whitelist_streak" -ge 3 ]; then
    echo FINAL=WHITELIST_CANDIDATE_OBSERVE_ONLY
elif [ "$direct_streak" -ge 3 ]; then
    echo FINAL=DIRECT_HEALTHY_OBSERVE_ONLY
else
    echo FINAL=NO_SAFE_SWITCH_DECISION_OBSERVE_ONLY
fi
