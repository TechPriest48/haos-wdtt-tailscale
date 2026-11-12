#!/usr/bin/env python3
"""CSQTT link manager for a single preexisting HA202 csq-socks Docker container.

No network routing commands. Credentials are never included in command line
arguments, application logs, browser URLs, or repository files.
"""
from __future__ import annotations

import html
import http.client
import io
import json
import os
import secrets
import socket
import subprocess
import tarfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, urlsplit

DOCKER_SOCKET = '/run/docker.sock'
DATA = '/data'
TARGET = 'csq-socks'
CFG_DIR = '/root/.config/csq-socks'
CFG_PATH = CFG_DIR + '/conn.json'
MODE_PATH = '/run/csq-socks/mode'
BACKUP_PATH = DATA + '/previous_conn.tar'
STATUS_PATH = DATA + '/manager_status.json'
MAX_LINK = 8192
CSRF = secrets.token_urlsafe(32)
LOCK = threading.RLock()
STATE = {'busy': False, 'message': 'Готово. Рабочая сеть не изменена.', 'pending': False}


class ManagerError(Exception):
    pass


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, timeout: float = 20):
        super().__init__('localhost', timeout=timeout)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(DOCKER_SOCKET)


def docker(method: str, path: str, body: bytes | None = None, timeout: float = 25):
    conn = UnixHTTPConnection(timeout=timeout)
    try:
        headers = {'Content-Type': 'application/json'}
        if body is not None and path.startswith('/containers/') and '/archive?' in path:
            headers['Content-Type'] = 'application/x-tar'
        conn.request(method, '/v1.43' + path, body=body, headers=headers)
        resp = conn.getresponse()
        content = resp.read()
        status = resp.status
        if not 200 <= status < 300:
            raise ManagerError('Нет доступа к контейнеру или Docker API (HTTP %d).' % status)
        return content
    except (OSError, http.client.HTTPException) as ex:
        raise ManagerError('Docker API недоступен; проверьте разрешения приложения.') from ex
    finally:
        conn.close()


def container_ready():
    meta = json.loads(docker('GET', '/containers/%s/json' % TARGET))
    if meta.get('Name') != '/' + TARGET:
        raise ManagerError('Не найден ожидаемый контейнер csq-socks.')
    if not meta.get('State', {}).get('Running'):
        raise ManagerError('Контейнер csq-socks остановлен.')


def read_tar(path: str):
    try:
        raw = docker('GET', '/containers/%s/archive?path=%s' % (TARGET, quote(path, safe='')))
    except ManagerError as exc:
        raise ManagerError('Не удалось прочитать сохранённую конфигурацию контейнера.') from exc
    if len(raw) > 256_000:
        raise ManagerError('Размер конфигурации неожиданно велик.')
    return raw


def tar_content(raw: bytes):
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as tar:
        members = [m for m in tar.getmembers() if m.isfile()]
        if len(members) != 1 or members[0].size > 32_768:
            raise ManagerError('Некорректный файл конфигурации контейнера.')
        return tar.extractfile(members[0]).read()


def make_tar(filename: str, content: bytes):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w') as tar:
        meta = tarfile.TarInfo(filename)
        meta.size = len(content)
        meta.mode = 0o600
        meta.uid = meta.gid = 0
        tar.addfile(meta, io.BytesIO(content))
    return output.getvalue()


def put_config(content: bytes):
    data = make_tar('conn.json', content)
    docker('PUT', '/containers/%s/archive?path=%s' % (TARGET, quote(CFG_DIR, safe='')),
           body=data, timeout=25)


def secret_file(path: str, data: bytes):
    os.makedirs(DATA, exist_ok=True)
    tmp = path + '.tmp'
    fd = os.open(tmp, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, 'wb') as file:
            file.write(data)
            file.flush()
            os.fsync(file.fileno())
        os.replace(tmp, path)
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass


def save_state():
    tmp = dict(STATE)
    tmp['busy'] = False
    tmp = {'pending': bool(tmp['pending']), 'message': str(tmp['message'])[:400]}
    secret_file(STATUS_PATH, json.dumps(tmp, ensure_ascii=False).encode('utf-8'))


def validate_link(link: str):
    if not link.startswith('csqtt://') or len(link) > MAX_LINK or any(ord(c) < 32 for c in link):
        raise ManagerError('Вставьте полную ссылку csqtt:// без переносов строк.')
    try:
        process = subprocess.run(['python3', '-I', '/opt/csq-socks/link.py', 'parse'],
                                 input=link, text=True, capture_output=True, timeout=5)
        if process.returncode:
            raise ManagerError('Ссылка не прошла проверку csq-socks.')
        obj = json.loads(process.stdout)
        if str(obj.get('line')) not in ('2.1', '2.5'):
            raise ManagerError('Неизвестный формат ссылки csqtt.')
        if not obj.get('host') or not obj.get('port'):
            raise ManagerError('Ссылка не содержит адрес сервера csqtt.')
        return (json.dumps(obj, ensure_ascii=False, separators=(',', ':')) + '\n').encode('utf-8')
    except (OSError, ValueError, subprocess.TimeoutExpired) as ex:
        raise ManagerError('Ошибка проверки ссылки в локальном csq-socks.') from ex


def exec_container(args, timeout=60):
    req = {'AttachStdout': False, 'AttachStderr': False, 'AttachStdin': False,
           'Tty': False, 'User': 'root', 'Cmd': args}
    response = json.loads(docker('POST', '/containers/%s/exec' % TARGET,
                                 json.dumps(req).encode('utf-8')))
    exec_id = response.get('Id')
    if not exec_id:
        raise ManagerError('Не удалось подготовить команду в контейнере.')
    docker('POST', '/exec/%s/start' % exec_id,
           json.dumps({'Detach': True, 'Tty': False}).encode('utf-8'))
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        info = json.loads(docker('GET', '/exec/%s/json' % exec_id))
        if not info.get('Running', False):
            if info.get('ExitCode') == 0:
                return
            raise ManagerError('Команда csq-socks завершилась ошибкой.')
        time.sleep(1)
    raise ManagerError('Истёк срок выполнения команды csq-socks.')


def current_mode():
    try:
        return tar_content(read_tar(MODE_PATH)).decode('utf-8').strip()
    except ManagerError:
        return 'unknown'


def check_proxy():
    exec_container(['curl', '-4', '-f', '-sS', '--connect-timeout', '5', '--max-time', '15',
                    '--socks5-hostname', '127.0.0.1:1089', '-o', '/dev/null',
                    'https://www.google.com/generate_204'], timeout=25)


def restart_socks():
    exec_container(['/opt/csq-socks/csq-socks', 'down'], timeout=35)
    exec_container(['/opt/csq-socks/csq-socks', 'up'], timeout=290)
    check_proxy()


def save_new(link: str):
    parsed = validate_link(link)
    container_ready()
    with LOCK:
        if STATE['busy']:
            raise ManagerError('Уже выполняется другая операция.')
        if not os.path.exists(BACKUP_PATH):
            prev = read_tar(CFG_PATH)
            tar_content(prev)
            secret_file(BACKUP_PATH, prev)
        try:
            put_config(parsed)
        except Exception:
            if os.path.isfile(BACKUP_PATH):
                with open(BACKUP_PATH, 'rb') as f:
                    put_config(tar_content(f.read()))
            raise
        STATE['pending'] = True
        STATE['message'] = 'Новая ссылка сохранена. Действующее соединение не прерывалось.'
        save_state()


def rollback():
    with LOCK:
        if not os.path.isfile(BACKUP_PATH):
            raise ManagerError('Предыдущая ссылка недоступна.')
        with open(BACKUP_PATH, 'rb') as f:
            content = tar_content(f.read())
        put_config(content)
        mode = current_mode()
        if mode == 'socks':
            restart_socks()
        os.unlink(BACKUP_PATH)
        STATE['pending'] = False
        STATE['message'] = ('Предыдущая ссылка восстановлена и SOCKS проверен.' if mode == 'socks'
                            else 'Предыдущая ссылка восстановлена; активное соединение не изменялось.')
        save_state()


def apply_new():
    with LOCK:
        if not STATE['pending'] or not os.path.exists(BACKUP_PATH):
            raise ManagerError('Нет новой ссылки для применения.')
        container_ready()
        mode = current_mode()
        if mode != 'socks':
            raise ManagerError('Переподключение запрещено: текущий режим не SOCKS (режим %s).' % mode)
        try:
            restart_socks()
            os.unlink(BACKUP_PATH)
            STATE['pending'] = False
            STATE['message'] = 'Новая ссылка активирована. HTTPS через SOCKS успешно проверен.'
            save_state()
        except Exception:
            try:
                with open(BACKUP_PATH, 'rb') as f:
                    old = tar_content(f.read())
                put_config(old)
                restart_socks()
                os.unlink(BACKUP_PATH)
                STATE['pending'] = False
                STATE['message'] = 'Новая ссылка не заработала; прежняя восстановлена и проверена.'
            except Exception:
                STATE['message'] = ('Новая ссылка не прошла проверку; автоматическое восстановление '
                                    'не подтверждено. Рабочие маршруты не изменялись.')
            save_state()


def run_task(fn):
    try:
        fn()
    except ManagerError as exc:
        with LOCK:
            STATE['message'] = str(exc)
            save_state()
    except Exception:
        with LOCK:
            STATE['message'] = 'Ошибка операции. Секреты не выводятся в журнал.'
            save_state()
    finally:
        with LOCK:
            STATE['busy'] = False


def page():
    with LOCK:
        pending = STATE['pending']
        busy = STATE['busy']
        msg = STATE['message']
    disabled = ' disabled' if busy else ''
    return ('<!doctype html><html lang="ru"><head><meta charset="UTF-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            '<title>CSQTT — управление</title><style>'
            'body{font:16px system-ui,sans-serif;background:#111827;color:#f3f4f6;margin:0;padding:24px}'
            'main{max-width:660px;margin:auto}label{display:block;margin:20px 0 8px}'
            'input{box-sizing:border-box;width:100%%;padding:12px;border-radius:8px;'
            'border:1px solid #64748b;background:#1f2937;color:white}'
            'button{padding:11px 16px;margin:12px 8px 0 0;border:0;border-radius:8px;'
            'background:#2563eb;color:white;cursor:pointer}'
            'button.secondary{background:#374151}button:disabled{opacity:.4;cursor:default}'
            '.status{padding:14px;border:1px solid #4b5563;border-radius:8px}'
            'p{line-height:1.5;color:#d1d5db}small{color:#9ca3af}</style></head><body><main>'
            '<h1>CSQTT — управление</h1>'
            '<p>Ссылка сохраняется только на HA202. Маршруты Home Assistant и Tailscale не меняются.</p>'
            '<div class="status" role="status">%s%s</div>'
            '<form method="post"><input type="hidden" name="csrf" value="%s">'
            '<label for="link">Новая ссылка csqtt://</label>'
            '<input id="link" name="link" type="password" autocomplete="off" spellcheck="false" '
            'placeholder="csqtt://…" maxlength="8192" required>'
            '<button type="submit" name="action" value="save"%s>Сохранить без переподключения</button>'
            '</form><form method="post"><input type="hidden" name="csrf" value="%s">'
            '<button type="submit" name="action" value="apply"%s>Применить к SOCKS</button>'
            '<button class="secondary" type="submit" name="action" value="rollback"%s>Вернуть предыдущую</button>'
            '</form><p><small>Применение кратковременно отключает только SOCKS. В режиме TUN '
            'применение заблокировано. Новая ссылка: %s. Автоматических сетевых правил нет.</small></p>'
            '<form method="get"><button class="secondary" type="submit">Обновить статус</button></form>'
            '</main></body></html>') % (
                html.escape(msg), ' (выполняется…)' if busy else '', html.escape(CSRF), disabled,
                html.escape(CSRF), disabled, disabled, 'сохранена, ожидает применения' if pending else 'нет')


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def response(self, data: bytes, status=200):
        self.send_response(status)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Security-Policy',
                         "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if urlsplit(self.path).path not in ('', '/', '/index.html'):
            self.response(b'Not found', 404)
            return
        self.response(page().encode('utf-8'))

    def do_POST(self):
        try:
            size = int(self.headers.get('Content-Length', '0'))
        except ValueError:
            size = 0
        if not 0 < size <= 12_000 or not self.headers.get('Content-Type', '').startswith('application/x-www-form-urlencoded'):
            self.response(b'Bad request', 400)
            return
        data = self.rfile.read(size).decode('utf-8', 'strict')
        form = parse_qs(data, keep_blank_values=True)
        if not secrets.compare_digest(form.get('csrf', [''])[0], CSRF):
            self.response(b'Forbidden', 403)
            return
        action = form.get('action', [''])[0]
        if action == 'save':
            try:
                save_new(form.get('link', [''])[0])
            except ManagerError as exc:
                with LOCK:
                    STATE['message'] = str(exc)
                    save_state()
        elif action in ('apply', 'rollback'):
            with LOCK:
                if not STATE['busy']:
                    STATE['busy'] = True
                    threading.Thread(target=run_task,
                                     args=(apply_new if action == 'apply' else rollback,), daemon=True).start()
        else:
            self.response(b'Bad request', 400)
            return
        self.send_response(303)
        self.send_header('Location', './')
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()

def main():
    os.makedirs(DATA, exist_ok=True)
    os.chmod(DATA, 0o700)
    if os.path.exists(STATUS_PATH):
        try:
            saved = json.loads(open(STATUS_PATH, encoding='utf-8').read())
            STATE['pending'] = bool(saved.get('pending', False))
            STATE['message'] = str(saved.get('message', 'Готово.'))[:400]
        except (OSError, ValueError):
            pass
    print('CSQTT manager listening through Home Assistant Ingress on port 8099; no link logging.', flush=True)
    ThreadingHTTPServer(('0.0.0.0', 8099), Handler).serve_forever()

if __name__ == '__main__':
    main()
