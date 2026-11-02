#!/bin/sh
# HAOS-safe replacement for OpenWrt datapath: never change host default route.
# The Python controller owns policy rules. This script is intentionally limited.
case "${1:-}" in
  ensure|apply|start|wait-ensure)
    ip link show "${2:-wg-wdtt}" >/dev/null 2>&1 || exit 1
    exit 0 ;;
  status)
    ip link show "${2:-wg-wdtt}" ;;
  stop)
    exit 0 ;;
  *) exit 2 ;;
esac
