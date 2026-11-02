# Changelog

## 0.4.1 — security hotfix

- The web UI override file is now created with permissions 0600 **before** writing
  the WDTT password and VK hashes.
- Added a regression test for override file permissions (24 Python tests).
- Version bumped so HAOS can offer an update from 0.4.0.

## 0.4.0 — security and routing hardening (unverified on HAOS)

- Patch pinned upstream WDTT so `routing_mode=external` does not add any
  VK/TURN/DNS/VPS routes to the HAOS main routing table. Build fails closed
  if the patch no longer matches the upstream source.
- Treat route toggles as strict JSON booleans; enforce IPv6 fail-closed rule
  when routing is enabled. Prevent invalid numeric settings.
- Add throw routes in WDTT policy table for local IPv4 networks so marked
  LAN endpoints use regular host routing; never replace host default route.
- Track owned WireGuard interface across crashes; refuse takeover/deletion of
  unowned network interfaces.
- Bind privileged web panel to internal HAOS bridge (172.30.32.1) only, rather
  than all interfaces. Keep Supervisor ingress IP restrictions.
- Restore default AppArmor protection and drop unnecessary NET_RAW capability.
- Redact configured secrets in controller journal, and write both UCI config
  and web UI secret override files 0600 before persisting secret content.
- Add targeted unit tests for rejection paths, route separation, and recovery.

**Not yet passed:** live HAOS build, AppArmor permission check, VPS
handshake, Tailscale interoperation, forced power loss, full packet captures.
This remains EXPERIMENTAL and is not production-approved.
