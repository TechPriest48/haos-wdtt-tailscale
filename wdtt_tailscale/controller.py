#!/usr/bin/env python3
"""Experimental HAOS WDTT/Tailscale policy gateway.

NOT a standalone VPN implementation. Uses upstream wdttd in UCI external mode.
Conservative design: never replaces the host default route. Route opt-in only.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import signal
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from collections import deque
from webui import PanelState, WebServer, SETTINGS_PATH
from pathlib import Path

OPTIONS_PATH = Path(os.getenv("OPTIONS_PATH", "/data/options.json"))
UCI_PATH = Path(os.getenv("UCI_PATH", "/etc/config/wdtt"))
IFACE = "wg-wdtt"
TABLE = "7477"
PRIORITY = "4990"   # before Tailscale's 52xx rules
TS_MARK = "0x80000/0xff0000"
SO_MARK_VALUE = 0x80000
TEST_TARGETS = (("1.1.1.1", 443), ("9.9.9.9", 443))
# Throw routes let marked packets headed for LAN use the normal main table.
LAN_BYPASS = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16")
OWNED_LINK = Path(os.getenv("WDTT_OWNED_LINK", "/data/wg-wdtt-owned.json"))
SECRET_VALUES: set[str] = set()

JOURNAL = deque(maxlen=300)
JOURNAL_LOCK = threading.RLock()


def note(msg: str) -> None:
    # Redact errors too, not just stdout lines emitted by the Go daemon.
    for secret in tuple(SECRET_VALUES):
        if secret:
            msg = msg.replace(secret, "[REDACTED]")
    line = "[WDTT-HAOS] " + msg
    with JOURNAL_LOCK:
        JOURNAL.append(line[:1000])
    print(line, flush=True)


def cmd(*args: str, check: bool = True, timeout: int = 12) -> subprocess.CompletedProcess:
    return subprocess.run(list(args), check=check, text=True, capture_output=True, timeout=timeout)


def existing_link(name: str) -> bool:
    return cmd("ip", "link", "show", "dev", name, check=False).returncode == 0


def uci_quote(v: str) -> str:
    """Safely emit one single-quoted UCI field (upstream parser is line-oriented)."""
    if any(x in v for x in ("\n", "\r", "'", '"', "\\", "\x00")):
        raise ValueError("UCI values must not contain quote, backslash or newlines")
    return "'" + v + "'"


def validate_peer(peer: str) -> str:
    """Accept IPv4:port or DNS:port (no IPv6 literal in this prototype)."""
    host, sep, port = peer.rpartition(":")
    if not sep or not host or not port.isdecimal() or not (1 <= int(port) <= 65535):
        raise ValueError("peer must have HOST:PORT format")
    if not re.fullmatch(r"[a-zA-Z0-9.-]+", host) or ".." in host:
        raise ValueError("unsupported peer host")
    return peer


def hashes_clean(text: str) -> str:
    values = []
    for raw in re.split(r"[,;\s]+", text.strip()):
        if not raw:
            continue
        raw = raw.split("/join/")[-1].split("?")[0].strip("/ ")
        if not re.fullmatch(r"[a-zA-Z0-9_=-]+", raw):
            raise ValueError("invalid VK hash/call URL")
        if raw not in values:
            values.append(raw)
    if not values or len(values) > 4:
        raise ValueError("provide 1-4 VK call hashes")
    return ",".join(values)


@dataclass
class Opts:
    mode: str
    peer: str
    password: str
    hashes: str
    device_id: str
    workers: int
    mtu: int
    turn_transport: str
    obfs_mode: str
    vk_auth_mode: str
    go_dns: str
    probe_hosts: tuple[str, ...]
    interval: int
    failures: int
    recovery_seconds: int
    route_tailscale: bool
    block_ipv6: bool

    @classmethod
    def load(cls, path: Path) -> "Opts":
        if path == OPTIONS_PATH:
            return cls.from_raw(read_settings())
        return cls.from_raw(json.loads(path.read_text(encoding="utf8")))

    @classmethod
    def from_raw(cls, raw: dict) -> "Opts":
        mode = raw.get("connection_mode", "off")
        if mode not in ("off", "always", "auto"):
            raise ValueError("unknown connection_mode")
        peer = str(raw.get("peer", "")).strip()
        password = str(raw.get("password", ""))
        hashes = str(raw.get("vk_hashes", ""))
        device_id = str(raw.get("device_id", "")).strip()
        if mode != "off":
            validate_peer(peer)
            if not password:
                raise ValueError("password missing")
            hashes = hashes_clean(hashes)
            if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,64}", device_id):
                raise ValueError("invalid stable device_id")
        hosts = tuple(h.strip() for h in str(raw.get("probe_hosts", "")).split(",") if h.strip())
        if mode == "auto":
            if len(hosts) < 2 or any(not re.fullmatch(r"[a-zA-Z0-9.-]+", h) for h in hosts):
                raise ValueError("configure at least two probe hostnames")
        def strict_int(key: str, default: int) -> int:
            value = raw.get(key, default)
            if type(value) is not int:
                raise ValueError(f"{key} must be an integer")
            return value

        workers = strict_int("workers", 9)
        mtu = strict_int("mtu", 1240)
        interval = strict_int("check_interval", 20)
        failures = strict_int("failure_threshold", 3)
        recovery_seconds = strict_int("recovery_seconds", 300)
        def strict_bool(key: str, default: bool) -> bool:
            value = raw.get(key, default)
            if type(value) is not bool:
                raise ValueError(f"{key} must be boolean (true/false), not a string")
            return value
        route_tailscale = strict_bool("route_tailscale", False)
        block_ipv6 = strict_bool("route_ipv6_block", True)
        if route_tailscale and not block_ipv6:
            raise ValueError("route_ipv6_block must be enabled when routing Tailscale")
        turn_transport = str(raw.get("turn_transport", "udp"))
        obfs_mode = str(raw.get("obfs_mode", "audio"))
        vk_auth_mode = str(raw.get("vk_auth_mode", "vkcalls"))
        go_dns = str(raw.get("go_dns", "doh-yandex"))
        if (workers < 9 or workers > 108 or mtu < 1100 or mtu > 1420
                or interval < 10 or interval > 300 or failures < 1 or failures > 15
                or recovery_seconds < 60 or recovery_seconds > 3600):
            raise ValueError("numeric config out of bounds")
        if turn_transport not in ("udp", "tcp"):
            raise ValueError("turn_transport must be udp|tcp")
        if obfs_mode not in ("audio", "video"):
            raise ValueError("obfs_mode must be audio|video")
        if vk_auth_mode not in ("vkcalls", "legacy"):
            raise ValueError("vk_auth_mode must be vkcalls|legacy")
        if go_dns not in ("doh-yandex", "doh-cloudflare", "yandex"):
            raise ValueError("unsupported VK API DNS mode")
        return cls(mode, peer, password, hashes, device_id, workers, mtu, turn_transport, obfs_mode, vk_auth_mode, go_dns, hosts, interval,
                   failures, recovery_seconds, route_tailscale, block_ipv6)


def write_uci(opts: Opts) -> None:
    UCI_PATH.parent.mkdir(parents=True, exist_ok=True)
    content = "\n".join((
        "config globals 'globals'",
        "  option enabled '1'",
        "  option peer " + uci_quote(opts.peer),
        "  option password " + uci_quote(opts.password),
        "  option hashes " + uci_quote(opts.hashes),
        "  option device_id " + uci_quote(opts.device_id),
        "  option workers " + uci_quote(str(opts.workers)),
        "  option mtu " + uci_quote(str(opts.mtu)),
        "  option listen '127.0.0.1:9000'",
        "  option turn_transport " + uci_quote(opts.turn_transport),
        "  option obfs_mode " + uci_quote(opts.obfs_mode),
        "  option go_dns " + uci_quote(opts.go_dns),
        "  option routing_mode 'external'",
        "  option tunnel_mode 'wg'",
        "  option iface 'wg-wdtt'",
        "  option vk_auth_mode " + uci_quote(opts.vk_auth_mode),
        "  option captcha_mode 'auto'",
        "  option uplink_iface 'auto'",
        "",
    ))
    tmp = UCI_PATH.with_suffix(".tmp")
    # Set permissions BEFORE writing the secret; default umask could expose it.
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf8") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    tmp.replace(UCI_PATH)


def own_rule_present(version: str = "-4") -> bool:
    p = cmd("ip", version, "rule", "show", check=False)
    return any(re.match(r"^\s*" + PRIORITY + r":", line) for line in p.stdout.splitlines())


def table_routes(version: str = "-4") -> str:
    return cmd("ip", version, "route", "show", "table", TABLE, check=False).stdout.strip()


def matching_owned_rule(version: str) -> bool:
    """Only our exact priority+mark+table may be removed on post-crash recovery."""
    p = cmd("ip", version, "rule", "show", check=False).stdout.lower()
    for line in p.splitlines():
        if re.match(r"^\s*" + PRIORITY + r":", line):
            return ("0x80000/0xff0000" in line and
                    ("lookup 7477" in line or "lookup " + TABLE in line))
    return False


def recover_stale_rules(block_ipv6: bool) -> None:
    """Remove leftover route/rule *only* when they exactly match our deployment."""
    v4_rule = own_rule_present("-4")
    v4_route = table_routes("-4")
    v6_rule = own_rule_present("-6")
    v6_route = table_routes("-6")
    if v4_rule and not matching_owned_rule("-4"):
        note("WARN: priority 4990 owned by another service, not touching it")
        return
    if v6_rule and not matching_owned_rule("-6"):
        note("WARN: IPv6 priority 4990 owned by another service, not touching it")
        return
    if v4_route and not all(
        ("dev wg-wdtt" in x and x.lstrip().startswith("default "))
        or any(x.lstrip().startswith("throw " + net) for net in LAN_BYPASS)
        for x in v4_route.splitlines()
    ):
        note("WARN: routing table 7477 has foreign IPv4 routes; not touching it")
        return
    if v6_route and not all(x.lstrip().startswith("unreachable default") for x in v6_route.splitlines()):
        note("WARN: routing table 7477 has foreign IPv6 routes; not touching it")
        return
    if v4_rule or v4_route or v6_rule or v6_route:
        note("Cleaning exact stale WDTT policy routes from a prior unclean exit")
        Routes(True).disable(force=True)


class Routes:
    def __init__(self, ipv6: bool):
        self.ipv6 = ipv6
        self.active = False

    def conflict(self) -> str | None:
        if own_rule_present("-4") or table_routes("-4"):
            return f"table {TABLE} or priority {PRIORITY} occupied (IPv4)"
        if self.ipv6 and (own_rule_present("-6") or table_routes("-6")):
            return f"table {TABLE} or priority {PRIORITY} occupied (IPv6)"
        return None

    def enable(self) -> None:
        if self.active:
            return
        if not existing_link(IFACE):
            raise RuntimeError("WDTT interface missing")
        if not existing_link("tailscale0"):
            raise RuntimeError("tailscale0 absent: set userspace_networking: false and restart Tailscale")
        conflict = self.conflict()
        if conflict:
            raise RuntimeError(conflict)
        try:
            for network in LAN_BYPASS:
                cmd("ip", "-4", "route", "add", "throw", network, "table", TABLE)
            cmd("ip", "-4", "route", "add", "default", "dev", IFACE, "table", TABLE)
            if self.ipv6:
                cmd("ip", "-6", "route", "add", "unreachable", "default", "table", TABLE)
            cmd("ip", "-4", "rule", "add", "pref", PRIORITY, "fwmark", TS_MARK, "lookup", TABLE)
            if self.ipv6:
                cmd("ip", "-6", "rule", "add", "pref", PRIORITY, "fwmark", TS_MARK, "lookup", TABLE)
            # Explicitly validate marked lookup before considering the route active.
            route = cmd("ip", "-4", "route", "get", "1.1.1.1", "mark", "0x80000").stdout
            if "dev " + IFACE not in route:
                raise RuntimeError("marked route lookup does not select wg-wdtt")
            self.active = True
            note("Tailscale transport route active (not the HAOS default route)")
        except Exception:
            self.disable(force=True)
            raise

    def disable(self, force: bool = False) -> None:
        if not self.active and not force:
            return
        # Remove only our exact mark-based rule and single named route.
        for ver in ("-4", "-6"):
            if ver == "-6" and not self.ipv6:
                continue
            cmd("ip", ver, "rule", "del", "pref", PRIORITY, "fwmark", TS_MARK, "lookup", TABLE, check=False)
        cmd("ip", "-4", "route", "del", "default", "dev", IFACE, "table", TABLE, check=False)
        for network in LAN_BYPASS:
            cmd("ip", "-4", "route", "del", "throw", network, "table", TABLE, check=False)
        if self.ipv6:
            cmd("ip", "-6", "route", "del", "unreachable", "default", "table", TABLE, check=False)
        self.active = False
        note("Tailscale policy rules removed")


def tcp_probe(host: str, port: int = 443, timeout: float = 3.0, mark: bool = False) -> bool:
    """Test real TCP connectivity; no HTTP semantics or DNS-dependent success code."""
    try:
        if mark:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                s.settimeout(timeout)
                s.setsockopt(socket.SOL_SOCKET, getattr(socket, "SO_MARK", 36), SO_MARK_VALUE)
                s.connect((host, port))
                return True
            finally:
                s.close()
        # Resolve only A records, so an IPv6 route can't mask IPv4 restrictions.
        infos = socket.getaddrinfo(host, port, family=socket.AF_INET, type=socket.SOCK_STREAM)
        for info in infos[:2]:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout)
                    s.connect(info[4])
                    return True
            except OSError:
                continue
    except (OSError, socket.gaierror):
        pass
    return False


def direct_available(hosts: tuple[str, ...]) -> bool:
    success = sum(tcp_probe(h, timeout=3.0) for h in hosts)
    # Reachability heuristic, not a provider whitelist event.
    note(f"Direct TCP 443: {success}/{len(hosts)} reachable")
    return success >= (len(hosts) + 1) // 2


def wdtt_ready() -> bool:
    if not existing_link(IFACE):
        return False
    p = cmd("/usr/local/bin/wdttd", "-status", check=False, timeout=5)
    if p.returncode:
        return False
    try:
        snap = json.loads(p.stdout)
    except (json.JSONDecodeError, ValueError):
        return False
    return snap.get("wg_applied") is True and snap.get("state") == "connected"


def marked_egress() -> bool:
    return any(tcp_probe(host, port, timeout=6.0, mark=True) for host, port in TEST_TARGETS)


def owned_wireguard_link() -> bool:
    """Never take over a link without persisted evidence that we created it."""
    if not OWNED_LINK.exists() or not existing_link(IFACE):
        return False
    try:
        record = json.loads(OWNED_LINK.read_text('utf8'))
        if record.get('iface') != IFACE or record.get('kind') != 'wireguard':
            return False
        r = cmd('ip', '-d', 'link', 'show', 'dev', IFACE, check=False)
        return r.returncode == 0 and bool(re.search(r'\bwireguard\b', r.stdout))
    except (OSError, ValueError, TypeError):
        return False


def remove_owned_link() -> bool:
    if not existing_link(IFACE):
        OWNED_LINK.unlink(missing_ok=True)
        return True
    if not owned_wireguard_link():
        note('Refusing to remove unknown wg-wdtt interface; manual inspection required')
        return False
    p = cmd('ip', 'link', 'del', IFACE, check=False)
    if p.returncode == 0:
        OWNED_LINK.unlink(missing_ok=True)
        note('Removed stale owned WireGuard interface')
        return True
    return False


def remember_owned_link() -> None:
    if not existing_link(IFACE):
        return
    # This is called only while OUR child daemon is running and no link
    # existed before it started. Persist a marker for crash recovery.
    OWNED_LINK.parent.mkdir(parents=True, exist_ok=True)
    tmp = OWNED_LINK.with_suffix('.tmp')
    tmp.write_text(json.dumps({'iface': IFACE, 'kind': 'wireguard'}), encoding='utf8')
    tmp.chmod(0o600)
    os.replace(tmp, OWNED_LINK)


class Gateway:
    def __init__(self, opts: Opts):
        self.opts = opts
        self.process: subprocess.Popen | None = None
        self.routes = Routes(opts.block_ipv6)
        self.stopping = False
        self.failures = 0
        self.good_since: float | None = None
        self.started: float | None = None
        self.last_attempt = 0.0
        self.last_route_attempt = 0.0

    def stop(self) -> None:
        self.stopping = True
        self.routes.disable()
        self.stop_daemon()

    def stop_daemon(self) -> None:
        p = self.process
        self.process = None
        if p and p.poll() is None:
            p.terminate()
            try:
                p.wait(timeout=12)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()
        self.started = None
        # Daemon teardown is normally automatic; recover only interfaces
        # previously observed as created by this add-on.
        if existing_link(IFACE):
            remove_owned_link()
        else:
            OWNED_LINK.unlink(missing_ok=True)

    def start_daemon(self) -> None:
        if self.process and self.process.poll() is None:
            return
        if existing_link(IFACE):
            if not remove_owned_link():
                raise RuntimeError("wg-wdtt exists and is not owned by this add-on; refusing takeover")
        if time.monotonic() - self.last_attempt < 15:
            return
        self.last_attempt = time.monotonic()
        # Only remember the link if we observe it while our child is alive.
        write_uci(self.opts)
        note(f"Starting upstream wdttd (peer={self.opts.peer}, mode=external)")
        self.process = subprocess.Popen(["/usr/local/bin/wdttd"], stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT, text=True, bufsize=1)
        self.started = time.monotonic()
        p = self.process

        def pump():
            assert p.stdout is not None
            for line in p.stdout:
                safe = line.strip().replace(self.opts.password, "[REDACTED]")
                for h in self.opts.hashes.split(","):
                    if h:
                        safe = safe.replace(h, "[HASH]")
                note("wdttd: " + safe[:800])
        threading.Thread(target=pump, daemon=True).start()

    def loop(self) -> None:
        note("Configuration accepted; external routing selected. Original HAOS main route unchanged.")
        if not self.opts.route_tailscale:
            note("route_tailscale=false (safe test): no policy routing will be installed")
        while not self.stopping:
            try:
                self.tick()
            except Exception as exc:
                note(f"Recovery after error: {exc}")
                self.routes.disable()
                self.stop_daemon()
            time.sleep(self.opts.interval)

    def tick(self) -> None:
        if self.opts.mode == "off":
            if self.process:
                self.routes.disable()
                self.stop_daemon()
            return
        now = time.monotonic()
        direct_ok = direct_available(self.opts.probe_hosts) if self.opts.mode == "auto" else False
        if self.opts.mode == "auto":
            if direct_ok:
                self.failures = 0
                if self.good_since is None:
                    self.good_since = now
            else:
                self.failures += 1
                self.good_since = None
            want = self.process is not None and (self.process.poll() is None)
            if self.failures >= self.opts.failures:
                want = True
            if direct_ok and self.good_since is not None and now - self.good_since >= self.opts.recovery_seconds:
                want = False
        else:
            want = True

        if not want:
            if self.process:
                note("Direct path stable or mode off: stopping WDTT")
                self.routes.disable()
                self.stop_daemon()
            return
        if self.process and self.process.poll() is not None:
            note(f"wdttd exited ({self.process.returncode}); will retry")
            self.routes.disable()
            self.stop_daemon()
        if not self.process:
            self.start_daemon()
            return
        if existing_link(IFACE):
            remember_owned_link()
        if not wdtt_ready():
            if self.routes.active:
                self.routes.disable()
            if self.started is not None and now - self.started > 130:
                note("WDTT not ready after 130s; restarting")
                self.stop_daemon()
            else:
                note("Waiting for WDTT handshake/configuration")
            return
        if not self.opts.route_tailscale:
            note("WDTT up, but Tailscale routing is disabled in settings")
            return
        if not self.routes.active:
            # Avoid oscillating Tailscale routes every probe after an unsuccessful test.
            if now - self.last_route_attempt < 120:
                return
            self.last_route_attempt = now
            self.routes.enable()
            if not marked_egress():
                self.routes.disable()
                # Do not continually hijack Tailscale; retry next interval.
                note("VPN marked egress failed; rolled back to direct routing")
                return
            note("Marked egress TCP test succeeded via WDTT")
        else:
            # If a third party modified the route, fail safely and avoid assuming success.
            if not own_rule_present("-4") or ("dev " + IFACE) not in table_routes("-4"):
                note("Policy routing changed externally; disabling our rules")
                self.routes.disable()
                return
            if not marked_egress():
                note("WDTT marked egress failed; removing policy rule")
                self.routes.disable()


def read_settings(overlay: dict | None = None) -> dict:
    raw = json.loads(OPTIONS_PATH.read_text(encoding="utf8"))
    if overlay is None and SETTINGS_PATH.exists():
        overlay = json.loads(SETTINGS_PATH.read_text(encoding="utf8"))
    if overlay:
        raw.update(overlay)
    return raw


def status_snapshot(gateway: Gateway) -> dict:
    try:
        tunnel = wdtt_ready() if gateway.process is not None else False
    except Exception:
        tunnel = False
    return {
        "phase": ("off" if gateway.opts.mode == "off" else
                  "connected" if tunnel else "connecting" if gateway.process else "idle"),
        "connection_mode": gateway.opts.mode,
        "tunnel": tunnel,
        "routing": gateway.routes.active,
        "tailscale": existing_link("tailscale0"),
        "direct_ok": gateway.good_since is not None if gateway.opts.mode == "auto" else None,
        "route_enabled": gateway.opts.route_tailscale,
        "peer": gateway.opts.peer,
        "updated_at": int(time.time()),
    }


def main() -> int:
    try:
        opts = Opts.load(OPTIONS_PATH)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        note("Configuration error: " + str(exc))
        return 2
    SECRET_VALUES.clear()
    SECRET_VALUES.update([opts.password, *opts.hashes.split(',')])
    recover_stale_rules(opts.block_ipv6)
    # A prior process may have been killed before deleting its interface.
    if OWNED_LINK.exists() and existing_link(IFACE):
        remove_owned_link()
    elif OWNED_LINK.exists() and not existing_link(IFACE):
        OWNED_LINK.unlink(missing_ok=True)
    gateway = Gateway(opts)
    panel = PanelState(read_settings, JOURNAL)
    # HAOS host bridge address: NO listening socket on LAN/public interfaces.
    # If missing, fail closed rather than exposing a privileged settings API.
    webserver = WebServer(("172.30.32.1", 8765), panel, Opts.from_raw)
    thread = threading.Thread(target=webserver.serve_forever, daemon=True)
    thread.start()
    note("Control panel via Home Assistant Ingress (port 8765; Supervisor proxy only)")
    stopped = False

    def handle_signal(signum, frame):
        nonlocal stopped
        stopped = True
    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)
    try:
        while not stopped:
            if panel.reload.is_set():
                try:
                    replacement = Opts.load(OPTIONS_PATH)
                    gateway.stop()
                    gateway = Gateway(replacement)
                    SECRET_VALUES.clear()
                    SECRET_VALUES.update([replacement.password, *replacement.hashes.split(',')])
                    panel.reload.clear()
                    note("Settings applied; reconnection will follow selected mode")
                except Exception as exc:
                    panel.reload.clear()
                    note("Invalid pending settings: " + str(exc))
            try:
                gateway.tick()
            except Exception as exc:
                note("Recovery after error: " + str(exc))
                gateway.routes.disable()
                gateway.stop_daemon()
            snap = status_snapshot(gateway)
            with panel.lock:
                panel.status = snap
            for _ in range(gateway.opts.interval):
                if stopped or panel.reload.is_set():
                    break
                time.sleep(1)
    finally:
        gateway.stop()
        webserver.shutdown()
        webserver.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
