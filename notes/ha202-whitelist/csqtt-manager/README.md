# CSQTT — управление (HA202)

Experimental local Home Assistant app for HA202. Admin-only Home Assistant Ingress panel accepts a `csqtt://` link and updates the **existing** `csq-socks` Docker container. The link is parsed locally by the original `csq-socks` parser. No credentials are logged or included in this repository.

- **Save** validates the link and stores it without disconnecting the current proxy session.
- **Apply** restarts **SOCKS only**, verifies a fixed HTTPS endpoint, and attempts to restore the prior link if activation fails.
- **Rollback** restores the saved prior link.
- Apply is blocked unless the target container reports mode `socks` (never perform network-changing `tun` operations).

## Security and limits

Requires `docker_api: true`, hence **Protection mode must be disabled for this new app only**. This is a high-privilege capability; never disable protection mode for the HA200 SSH app to accommodate it. No ports published, admin-only HA Ingress, CSRF protected forms, no query-string credentials. Secrets/old configuration persist temporarily in private app `/data` and may be included in HA backups. Protect backups and restrict HA admin access.

Existing image `csq-socks:local` and Docker container `csq-socks` must already be present on HA202. Build uses local image; no external installer.

Neither the app nor its actions alter host `ip rule`, `ip route`, default route, Tailscale table 52, or KeenDNS. It is **not** a routing watchdog, full-tunnel setup, or UDP Tailscale implementation.

To install, copy this folder to `/addons/csqtt_manager`, reload local apps/add-ons in HA202 Supervisor, install and start. Opening the panel does not modify the proxy. Enter the new link only after confirming access. The link should never be pasted into GitHub or this chat.
