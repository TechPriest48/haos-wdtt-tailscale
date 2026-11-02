# WDTT Tailscale Gateway for HAOS

**Status:** experimental pre-production build 0.4.1; no end-to-end HAOS/VPS test.

1. Make a Home Assistant backup and verify **local LAN** access before touching routing.
2. Add repository `https://github.com/TechPriest48/haos-wdtt-tailscale`
   in the HAOS app store and install the WDTT Tailscale Gateway add-on.
3. Keep `connection_mode: off` and `route_tailscale: false` until the build
   and Ingress panel work. Ingress binds only to `172.30.32.1:8765` on the
   HAOS supervisor bridge; if the address is missing it intentionally fails.
4. Configure WDTT server `IP:PORT`, password, 1–4 VK hashes and permanent device ID.
   Do not provide a VPS SSH password. A strong, unique WDTT secret is essential.
5. Start `connection_mode: always`, leaving `route_tailscale: false`. Check
   `wg-wdtt` and real tunnel traffic while core integrations remain on WAN.
6. Only with local LAN access: set official Tailscale add-on
   `userspace_networking: false` and verify `tailscale0` appears.
7. Enable Tailscale routing only after validated live tests. IPv6 blocked for
   marked traffic when active; private LAN IPv4 routes are passed to main.
8. Switch to `connection_mode: auto` only after verifying that network probes
   distinguish an operator restriction from DNS outages, general connectivity
   failures, and recovery of the normal route.

## Explicit limitations and remaining risks

- The upstream WDTT implementation uses a DTLS handshake without server
  certificate verification. Authentication ultimately relies on the shared WDTT
  password/WRAP and WireGuard material; a weak or stolen password is risky.
- The worker cannot obtain Tailscale peer/DERP health directly from the
  **separate** Tailscale add-on. Auto mode is based on direct TCP reachability,
  not a definitive operator whitelist event or verified Tailscale health.
- Host network and NET_ADMIN are necessary for policy routing of Tailscale's
  own marked transport. A compromise of this add-on still affects host networking.
- Crash recovery only deletes a WireGuard link when a persisted ownership marker
  exists and the interface type is WireGuard; it refuses unknown resources.
  No cleanup can be guaranteed for a sudden host power loss without testing.
- A first-time build downloads the pinned upstream WDTT source and Go modules;
  reproducibility and HAOS Docker compatibility still require live validation.

**Do not deploy as the sole path to your smart home.**
