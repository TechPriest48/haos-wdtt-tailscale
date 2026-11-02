"""Ingress-only control panel for WDTT Tailscale Gateway.

Never expose these endpoints to an untrusted client. All write requests are
restricted to HA ingress proxy and are validated against the same Opts schema.
"""
from __future__ import annotations

import json
import os
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

SETTINGS_PATH = Path(os.getenv('UI_SETTINGS_PATH', '/data/ui-overrides.json'))
WEB_PATH = Path(__file__).with_name('web')
CONFIG_KEYS = {
    'connection_mode', 'peer', 'password', 'vk_hashes', 'device_id',
    'workers', 'mtu', 'turn_transport', 'obfs_mode', 'vk_auth_mode', 'go_dns', 'probe_hosts', 'check_interval',
    'failure_threshold', 'recovery_seconds', 'route_tailscale', 'route_ipv6_block',
}
PRIVATE_KEYS = {'password', 'vk_hashes'}

# Deliberately fixed, read-only diagnostics: no shell or untrusted argv.
DIAGNOSTICS = {
    'client': ('/usr/local/bin/wdttd', '-status'),
    'interfaces': ('ip', '-brief', 'link', 'show'),
    'tailscale': ('ip', '-details', 'link', 'show', 'tailscale0'),
    'tunnel': ('ip', '-details', 'link', 'show', 'wg-wdtt'),
    'wireguard': ('wg', 'show', 'wg-wdtt'),
    'rules': ('ip', '-4', 'rule', 'show'),
    'routing-table': ('ip', '-4', 'route', 'show', 'table', '7477'),
    'route-check': ('ip', '-4', 'route', 'get', '1.1.1.1', 'mark', '0x80000'),
}



class PanelState:
    def __init__(self, config_loader, journal):
        self.config_loader = config_loader
        self.journal = journal
        self.lock = threading.RLock()
        self.reload = threading.Event()
        self.status = {'phase': 'starting', 'connection_mode': 'off', 'tunnel': False,
                       'routing': False, 'tailscale': False, 'direct_ok': None,
                       'updated_at': 0}

    def settings(self):
        raw = self.config_loader()
        safe = {k: raw.get(k) for k in CONFIG_KEYS if k not in PRIVATE_KEYS}
        for secret in PRIVATE_KEYS:
            safe[secret + '_configured'] = bool(raw.get(secret))
        safe['vk_hash_count'] = len([part for part in str(raw.get('vk_hashes') or '').split(',') if part.strip()])
        return safe

    def save(self, patch, validator):
        if not isinstance(patch, dict) or not patch or set(patch) - CONFIG_KEYS:
            raise ValueError('Неподдерживаемые поля настроек')
        with self.lock:
            existing = {}
            if SETTINGS_PATH.exists():
                existing = json.loads(SETTINGS_PATH.read_text('utf-8'))
            changed = dict(existing)
            for k, v in patch.items():
                if k in PRIVATE_KEYS and v == '':
                    continue  # Blank secret input does not erase the configured secret
                if isinstance(v, (dict, list)):
                    raise ValueError('Некорректное значение для ' + k)
                changed[k] = v
            # Validate prospective data BEFORE applying it to disk.
            validated = self.config_loader(changed)
            validator(validated)
            SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
            tmp = SETTINGS_PATH.with_suffix('.tmp')
            with tmp.open('w', encoding='utf8') as f:
                json.dump(changed, f, ensure_ascii=False, indent=2)
            os.chmod(tmp, 0o600)
            os.replace(tmp, SETTINGS_PATH)
            self.reload.set()
        return self.settings()


class WebServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, state, validator):
        self.state = state
        self.validator = validator
        super().__init__(address, PanelHandler)


class PanelHandler(BaseHTTPRequestHandler):
    server: WebServer

    def log_message(self, fmt, *args):
        pass

    def _authorized(self):
        # HA Supervisor's Ingress proxy IP, per Home Assistant ingress docs.
        # Loopback is allowed for local smoke tests. Direct LAN clients are denied.
        allowed = set(os.getenv('INGRESS_PROXY_IP', '172.30.32.2').split(','))
        allowed.update(['127.0.0.1', '::1'])
        return self.client_address[0] in allowed

    def _send(self, code, body, mime='application/json; charset=utf-8'):
        self.send_response(code)
        self.send_header('Content-Type', mime)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'SAMEORIGIN')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj, ensure_ascii=False).encode('utf8'))

    def do_GET(self):
        if not self._authorized():
            return self._json(403, {'error': 'Ingress only'})
        path = urlsplit(self.path).path
        if path == '/api/status':
            with self.server.state.lock:
                snap = dict(self.server.state.status)
            return self._json(200, snap)
        if path == '/api/settings':
            return self._json(200, self.server.state.settings())
        if path == '/api/logs':
            with self.server.state.lock:
                lines = list(self.server.state.journal)
            return self._json(200, {'lines': lines[-150:]})
        filenames = {'/': 'index.html', '/index.html': 'index.html',
                     '/style.css': 'style.css', '/app.js': 'app.js'}
        name = filenames.get(path)
        if not name:
            return self._json(404, {'error': 'Not found'})
        mime = {'index.html': 'text/html; charset=utf-8',
                'style.css': 'text/css; charset=utf-8',
                'app.js': 'text/javascript; charset=utf-8'}[name]
        return self._send(200, (WEB_PATH / name).read_bytes(), mime)

    def do_POST(self):
        if not self._authorized():
            return self._json(403, {'error': 'Ingress only'})
        path = urlsplit(self.path).path
        if path not in ('/api/settings', '/api/diagnostics'):
            return self._json(404, {'error': 'Not found'})
        if self.headers.get('X-WDTT-UI') != '1' or not self.headers.get('Content-Type', '').startswith('application/json'):
            return self._json(403, {'error': 'Request header required'})
        # Explicit origin check prevents cross-site requests from other LAN pages.
        origin = self.headers.get('Origin')
        host = self.headers.get('Host')
        if origin and urlsplit(origin).netloc != host:
            return self._json(403, {'error': 'Invalid origin'})
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if not (1 <= length <= 16384):
                raise ValueError('Неверная длина запроса')
            patch = json.loads(self.rfile.read(length))
            if path == '/api/diagnostics':
                # A small allowlist is safer than exposing a privileged shell.
                if not isinstance(patch, dict) or set(patch) != {'command'}:
                    raise ValueError('Команда диагностики не поддерживается')
                key = patch['command']
                if not isinstance(key, str) or key not in DIAGNOSTICS:
                    raise ValueError('Команда диагностики не поддерживается')
                try:
                    p = subprocess.run(DIAGNOSTICS[key], capture_output=True, text=True, timeout=5, shell=False)
                    output = (p.stdout + ('\n' + p.stderr if p.stderr else ''))[:8000]
                    return self._json(200, {'command': key, 'exit_code': p.returncode,
                                            'output': output or 'Нет вывода'})
                except (subprocess.TimeoutExpired, OSError) as exc:
                    return self._json(503, {'error': 'Диагностика недоступна: ' + type(exc).__name__})
            settings = self.server.state.save(patch, self.server.validator)
            return self._json(200, {'ok': True, 'settings': settings})
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            return self._json(400, {'error': str(exc)})
        except OSError:
            return self._json(500, {'error': 'Не удалось сохранить настройки'})
