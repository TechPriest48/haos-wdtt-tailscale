#!/usr/bin/env python3
"""HAOS native CSQTT add-on: independent SOCKS5 only, no host routes.

Its Docker container is built from locally installed csq-socks:local and runs
its own CSQTT subprocess. It does not access Docker API or another container.
The feature `csq-socks tun` MUST NOT be offered until verified rollback exists.
"""
from __future__ import annotations

import html
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs
from urllib.request import Request, urlopen

BASE = Path('/opt/csq-socks')
DATA = Path('/data')
STORE = DATA / 'csq-socks'
CONFIG_DIR = Path('/root/.config/csq-socks')
CONFIG = STORE / 'conn.json'
BACKUP = STORE / 'previous.json'
MODE = Path('/run/csq-socks/mode')
PORT = 11891  # Local host SOCKS port; not the existing container's bridge proxy.
CSRF = secrets.token_urlsafe(32)
MAX_BODY = 12000
LOCK = threading.RLock()
STATE = {'busy': False, 'message': 'Ожидание ссылки.', 'last_ok': None}


class AppError(Exception):
    pass


def atomic_secret(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + '.new')
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        os.chmod(path, 0o600)
    finally:
        temp.unlink(missing_ok=True)


def configure_storage() -> None:
    STORE.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(STORE, 0o700)
    CONFIG_DIR.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if CONFIG_DIR.is_symlink():
        if CONFIG_DIR.resolve() != STORE.resolve():
            raise AppError('Непредвиденная ссылка на папку конфигурации.')
    elif CONFIG_DIR.exists():
        if any(CONFIG_DIR.iterdir()):
            raise AppError('В образе найдена чужая конфигурация; не перезаписываю.')
        CONFIG_DIR.rmdir()
        CONFIG_DIR.symlink_to(STORE, target_is_directory=True)
    else:
        CONFIG_DIR.symlink_to(STORE, target_is_directory=True)


def parse_link(link: str) -> bytes:
    if not (link.startswith('csqtt://') and len(link) < 8192):
        raise AppError('Нужна полная ссылка csqtt://.')
    if any(ord(ch) < 33 or ord(ch) == 127 for ch in link):
        raise AppError('Ссылка содержит пробелы или управляющие символы.')
    try:
        p = subprocess.run(['python3', '-I', str(BASE / 'link.py'), 'parse'],
                           input=link, capture_output=True, text=True, timeout=8, check=False)
        if p.returncode != 0:
            raise AppError('Неверная ссылка CSQTT.')
        data = json.loads(p.stdout)
        if str(data.get('line')) not in ('2.1', '2.5'):
            raise AppError('Неподдерживаемый тип ссылки.')
        if not data.get('host') or not data.get('port'):
            raise AppError('В ссылке нет адреса сервера.')
        if not isinstance(data.get('hashes'), list):
            raise AppError('Некорректные параметры звонков.')
        return (json.dumps(data, separators=(',', ':'), ensure_ascii=False) + '\n').encode()
    except (OSError, ValueError, subprocess.TimeoutExpired) as e:
        raise AppError('Не удалось проверить ссылку локальным клиентом.') from e


def mode() -> str:
    try:
        return MODE.read_text().strip()
    except OSError:
        return 'off'


def run_cli(action: str, *args: str, timeout: int = 120) -> None:
    if action not in {'up', 'down'}:
        raise AppError('Недопустимая команда.')
    # Do not leak SUPERVISOR_TOKEN or other HA app environment variables
    # into the CSQTT client or its descendants.
    env = {'PATH': os.getenv('PATH', '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'),
           'HOME': '/root', 'WAIT': '90'}
    if 'TZ' in os.environ:
        env['TZ'] = os.environ['TZ']
    # Never pass link, tokens, or credentials in arguments; don't echo output.
    try:
        result = subprocess.run([str(BASE / 'csq-socks'), action, *args], env=env,
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as e:
        raise AppError('Клиент не завершил подключение вовремя.') from e
    if result.returncode != 0:
        raise AppError('Команда CSQTT не прошла. Проверьте ссылку и доступность сервера.')


def check_https() -> bool:
    for url in ('https://www.google.com/generate_204', 'https://github.com/'):
        try:
            rc = subprocess.run(['curl', '-4', '--fail', '--silent', '--show-error',
                                 '--connect-timeout', '5', '--max-time', '15',
                                 '--socks5-hostname', f'127.0.0.1:{PORT}',
                                 '--output', '/dev/null', url],
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=18)
            if rc.returncode == 0:
                return True
        except (OSError, subprocess.TimeoutExpired):
            pass
    return False


def start_socks() -> None:
    if mode() == 'tun':
        raise AppError('Обнаружен TUN-режим; его изменение запрещено.')
    if mode() == 'off':
        run_cli('up', str(PORT))
    if mode() != 'socks' or not check_https():
        raise AppError('SOCKS не прошёл HTTPS-проверку.')


def stop_socks() -> None:
    if mode() == 'tun':
        raise AppError('TUN-режим запрещён для управления этой панелью.')
    if mode() == 'socks':
        run_cli('down', timeout=25)


def save_link(text: str) -> None:
    parsed = parse_link(text)
    if CONFIG.exists() and not BACKUP.exists():
        atomic_secret(BACKUP, CONFIG.read_bytes())
    atomic_secret(CONFIG, parsed)
    STATE['message'] = 'Ссылка сохранена. Текущее SOCKS-соединение не прерывалось.'


def apply_link() -> None:
    if not CONFIG.exists():
        raise AppError('Сначала сохраните ссылку.')
    old_was_connected = mode() == 'socks'
    if mode() == 'tun':
        raise AppError('Нельзя применять ссылку в TUN-режиме.')
    try:
        if old_was_connected:
            stop_socks()
        start_socks()
        BACKUP.unlink(missing_ok=True)
        STATE['message'] = 'Новая ссылка применена, HTTPS через CSQTT работает.'
        STATE['last_ok'] = True
    except AppError as e:
        if BACKUP.exists():
            atomic_secret(CONFIG, BACKUP.read_bytes())
            BACKUP.unlink(missing_ok=True)
            try:
                stop_socks()
                if old_was_connected:
                    start_socks()
                STATE['message'] = 'Новая ссылка не прошла проверку; прежняя восстановлена.'
            except AppError:
                STATE['message'] = 'Старая ссылка восстановлена на диске, но соединение не подтвердилось.'
        else:
            STATE['message'] = 'Подключение не прошло проверку; резервной ссылки нет.'
        STATE['last_ok'] = False
        raise AppError(STATE['message']) from e


def rollback() -> None:
    if not BACKUP.exists():
        raise AppError('Нет сохранённой предыдущей ссылки.')
    if mode() == 'tun':
        raise AppError('Не могу менять конфигурацию в TUN-режиме.')
    active = mode() == 'socks'
    if active:
        stop_socks()
    atomic_secret(CONFIG, BACKUP.read_bytes())
    BACKUP.unlink(missing_ok=True)
    if active:
        start_socks()
    STATE['message'] = 'Предыдущая ссылка восстановлена.'


def perform(action: str, link: str = '') -> None:
    with LOCK:
        if STATE['busy']:
            raise AppError('Другая операция уже выполняется.')
        STATE['busy'] = True
    def worker():
        try:
            if action == 'save':
                save_link(link)
            elif action == 'apply':
                apply_link()
            elif action == 'disconnect':
                stop_socks()
                STATE['message'] = 'SOCKS остановлен; системные маршруты не менялись.'
            elif action == 'connect':
                start_socks()
                STATE['last_ok'] = True
                STATE['message'] = 'SOCKS активен, HTTPS подтверждён.'
            elif action == 'rollback':
                rollback()
            elif action == 'test':
                STATE['last_ok'] = check_https() if mode() == 'socks' else False
                STATE['message'] = 'HTTPS через SOCKS работает.' if STATE['last_ok'] else 'HTTPS через SOCKS не прошёл.'
        except AppError as e:
            STATE['message'] = str(e)
            STATE['last_ok'] = False
        except Exception:
            STATE['message'] = 'Внутренняя ошибка приложения; изменения маршрутов не выполнялись.'
            STATE['last_ok'] = False
        finally:
            with LOCK:
                STATE['busy'] = False
    threading.Thread(target=worker, daemon=True).start()


def require_ingress_port() -> int:
    override = os.getenv('CSQTT_TEST_PORT')
    if override:
        return int(override)
    token = os.getenv('SUPERVISOR_TOKEN', '')
    if not token:
        raise AppError('Нет токена Supervisor: запуск только как дополнение HAOS.')
    req = Request('http://supervisor/addons/self/info',
                  headers={'Authorization': 'Bearer ' + token})
    with urlopen(req, timeout=10) as resp:
        doc = json.load(resp)
    port = int(doc['data']['ingress_port'])
    if not 62000 <= port <= 65500:
        raise AppError('Supervisor не назначил безопасный порт Ingress.')
    return port


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        return   # never log a csqtt URL or any form data

    def allowed(self):
        return self.client_address[0] == '172.30.32.2' or os.getenv('CSQTT_TEST_PORT')

    def reply(self, code: int, body: bytes, kind: str = 'text/html; charset=utf-8') -> None:
        self.send_response(code)
        self.send_header('Content-Type', kind)
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'")
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if not self.allowed():
            self.reply(403, b'Forbidden', 'text/plain')
            return
        if self.path.split('?', 1)[0] not in ('/', '/index.html'):
            self.reply(404, b'Not found', 'text/plain')
            return
        with LOCK:
            message = html.escape(STATE['message'])
            busy = STATE['busy']
            last_ok = STATE['last_ok']
        status = html.escape(mode())
        installed = CONFIG.exists()
        old = BACKUP.exists()
        disabled = ' disabled' if busy else ''
        status_color = '#1f7a53' if status == 'socks' and last_ok else '#a56c2b'
        document = f'''<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>CSQTT HA202</title>
<style>body{{font-family:system-ui,sans-serif;max-width:720px;margin:2em auto;padding:0 1em;background:#f8fafc;color:#1d2939}}
main{{background:white;padding:1.5em;border-radius:14px;box-shadow:0 2px 12px #0001}}
input{{width:100%;padding:.7em;border:1px solid #cbd5e1;border-radius:6px;box-sizing:border-box}}
button{{padding:.75em 1.1em;margin:.4em .3em .4em 0;border:0;border-radius:6px;background:#2563eb;color:white;cursor:pointer}}
button:disabled{{opacity:.5}}.note{{color:#475569;font-size:.9em}}.status{{color:{status_color}}}</style></head>
<body><main><h2>CSQTT на HA202</h2><p class="status">Режим: <b>{status}</b>; ссылка: {'сохранена' if installed else 'не задана'}</p>
<p>{message}</p><p class="note">Собственный SOCKS5-клиент в дополнении. Только TCP, localhost:{PORT}. Не управляет Tailscale или Docker.</p>
<form method="post" action=""><input type="hidden" name="csrf" value="{CSRF}">
<input type="hidden" name="action" value="save"><label for="link">Новая ссылка csqtt://</label>
<input id="link" name="link" type="password" required autocomplete="off" placeholder="csqtt://…" maxlength="8192">
<button{disabled}>Сохранить ссылку</button></form><p class="note">Ссылка не отображается повторно. Права файла 0600; резервная копия остаётся в /data до применения.</p>
<form method="post" action=""><input type="hidden" name="csrf" value="{CSRF}">
<button name="action" value="apply"{disabled}>Применить и проверить HTTPS</button>
<button name="action" value="connect"{disabled}>Подключить SOCKS</button>
<button name="action" value="disconnect"{disabled}>Отключить SOCKS</button>
<button name="action" value="test"{disabled}>Проверить HTTPS</button>
{'<button name="action" value="rollback">Вернуть прежнюю ссылку</button>' if old else ''}</form>
<p class="note">{('Операция выполняется, обновите страницу для статуса.' if busy else 'Обновите страницу для проверки статуса.')}</p>
<p class="note">Полный TUN и системные маршруты в этой версии намеренно не меняются. Вход только через Home Assistant Ingress.</p>
</main></body></html>'''
        self.reply(200, document.encode('utf-8'))

    def do_POST(self):
        if not self.allowed() or self.path not in ('/', ''):
            self.reply(403, b'Forbidden', 'text/plain')
            return
        try:
            length = int(self.headers.get('Content-Length', '0'))
        except ValueError:
            length = 0
        if not (0 < length <= MAX_BODY):
            self.reply(413, b'Request too large', 'text/plain')
            return
        try:
            form = parse_qs(self.rfile.read(length).decode('utf-8'), keep_blank_values=True)
            csrf = form.get('csrf', [''])[0]
            action = form.get('action', [''])[0]
            if not secrets.compare_digest(csrf, CSRF):
                self.reply(403, b'CSRF rejected', 'text/plain')
                return
            if action not in {'save', 'apply', 'connect', 'disconnect', 'test', 'rollback'}:
                self.reply(400, b'Invalid action', 'text/plain')
                return
            perform(action, form.get('link', [''])[0])
            self.send_response(303)
            self.send_header('Location', './')
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Content-Length', '0')
            self.end_headers()
        except (ValueError, UnicodeError, AppError):
            self.reply(400, b'Action rejected', 'text/plain')


def shutdown(*_):
    if mode() == 'socks':
        try:
            stop_socks()
        except Exception:
            pass
    raise SystemExit(0)


def main() -> None:
    configure_storage()
    port = require_ingress_port()
    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    auto = False
    try:
        auto = json.loads((DATA / 'options.json').read_text()).get('auto_start') is True
    except (OSError, ValueError):
        pass
    if auto and CONFIG.exists():
        perform('connect')
    # Bind the host's internal Supervisor interface, not LAN/Tailscale.
    host = '127.0.0.1' if os.getenv('CSQTT_TEST_PORT') else '172.30.32.1'
    server = ThreadingHTTPServer((host, port), Handler)
    print('CSQTT ingress ready; host routing unchanged.', flush=True)
    server.serve_forever(poll_interval=0.5)


if __name__ == '__main__':
    main()