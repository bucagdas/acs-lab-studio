#!/usr/bin/env python3
"""Root WSL endpoint: ephemeral TAP devices, local UI and private control leases."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import select
import signal
import socket
import socketserver
import struct
import sys
import tempfile
import threading
import subprocess

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))
from windows.protocol import (Channel, HELLO, FRAME, SELECT, ACK, STATUS, READY,
                              STOP, ERROR, frame_record, unpack_frame, pppoe_frame)


class Relay:
    def __init__(self, channel, cards, folder):
        if not isinstance(cards, list) or not 1 <= len(cards) <= 64:
            raise ValueError('Windows fiziksel Ethernet listesi boş veya geçersiz.')
        self.channel, self.cards, self.folder = channel, cards, Path(folder)
        self.stop = threading.Event()
        self.taps, self.items = [], []
        self.pending, self.pending_lock = {}, threading.Lock()
        self.selection = threading.Lock()
        self.active = None
        self.lab = self.http = self.control = None
        self.started_servers = []
        self.state = self.folder / 'inventory.json'

    def create_taps(self):
        tag = secrets.token_hex(3)
        for index, card in enumerate(self.cards):
            if (not isinstance(card.get('mac'), str) or
                    re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', card['mac']) is None):
                raise ValueError('Windows Ethernet adresi geçersiz.')
            name = 'aw' + tag + str(index)
            fd = os.open('/dev/net/tun', os.O_RDWR | os.O_NONBLOCK)
            self.taps.append(fd)
            # IFF_TAP | IFF_NO_PI, nonpersistent: closing the fd deletes it.
            fcntl.ioctl(fd, 0x400454ca, struct.pack('16sH', name.encode(), 0x0002 | 0x1000))
            subprocess.run(['ip', 'link', 'set', 'dev', name, 'address', card['mac']], check=True)
            subprocess.run(['ip', 'link', 'set', 'dev', name, 'up'], check=True)
            self.items.append({'id': name, 'name': str(card['name']) + ' · ' + str(card['description']),
                               'mac': card['mac'], 'guid': card['guid'], 'active': bool(card['active'])})

    def save(self):
        temporary = self.state.with_suffix('.tmp')
        temporary.write_text(json.dumps({'control': str(self.folder / 'control.sock'),
                                         'adapters': self.items}))
        os.chmod(temporary, 0o600)
        temporary.replace(self.state)

    def request(self, kind, **values):
        key = secrets.token_hex(8)
        event = threading.Event()
        slot = {'event': event}
        with self.pending_lock:
            self.pending[key] = slot
        try:
            self.channel.json(kind, {'request': key, **values})
            if not event.wait(12):
                raise ValueError('Windows paket köprüsü yanıt vermedi.')
            result = slot['result']
            if not result.get('ok'):
                raise ValueError(result.get('error', 'Windows adaptörü açılamadı.'))
            return result
        finally:
            with self.pending_lock:
                self.pending.pop(key, None)

    def control_handler(self):
        relay = self
        class Handler(socketserver.StreamRequestHandler):
            def reply(self, value):
                self.wfile.write(json.dumps(value).encode() + b'\n')
                self.wfile.flush()

            def handle(self):
                self.connection.settimeout(15)
                lease = False
                try:
                    raw = self.rfile.readline(4097)
                    if len(raw) > 4096 or not raw.endswith(b'\n'):
                        raise ValueError('Geçersiz köprü isteği.')
                    data = json.loads(raw)
                    if not isinstance(data, dict):
                        raise ValueError('Geçersiz köprü isteği.')
                    if data.get('op') == 'status':
                        result = relay.request(STATUS)
                        current = {item['guid']: item for item in result['adapters']}
                        for item in relay.items:
                            item['active'] = bool(current.get(item['guid'], {}).get('active', False))
                        relay.save()
                        self.reply({'ok': True})
                        return
                    if data.get('op') != 'select' or not relay.selection.acquire(blocking=False):
                        raise ValueError('Başka bir Ethernet oturumu çalışıyor.')
                    lease = True
                    index = next((i for i, item in enumerate(relay.items) if item['id'] == data.get('iface')), None)
                    if index is None:
                        raise ValueError('Fiziksel Ethernet adaptörü bulunamadı.')
                    relay.active = index
                    relay.request(SELECT, index=index)
                    self.reply({'ok': True})
                    # Only this lease may activate the physical capture. EOF
                    # from discovery/runner releases it, even after a crash.
                    self.connection.settimeout(1)
                    while not relay.stop.is_set():
                        try:
                            if self.connection.recv(1) in (b'', b'R'):
                                break
                        except socket.timeout:
                            continue
                except (ValueError, OSError, KeyError) as exc:
                    try:
                        self.reply({'ok': False, 'error': str(exc)})
                    except OSError:
                        pass
                finally:
                    if lease:
                        relay.active = None
                        try:
                            relay.request(SELECT, index=None)
                        except (OSError, ValueError):
                            pass
                        relay.selection.release()
                        try:
                            self.reply({'ok': True})
                        except OSError:
                            pass
        return Handler

    def stop_gracefully(self, request):
        try:
            if self.lab is not None:
                self.lab.stop()
                if self.lab.process is not None:
                    self.lab.process.wait(timeout=20)
            self.channel.json(ACK, {'request': request.get('request'), 'ok': True})
            self.stop.set()
        except (ValueError, subprocess.TimeoutExpired):
            self.channel.json(ACK, {'request': request.get('request'), 'ok': False,
                                    'error': 'Yazma veya geri alma sürüyor. Panelde işlemin bitmesini bekle.'})

    def read_windows(self):
        try:
            while not self.stop.is_set():
                kind, payload = self.channel.receive()
                if kind == FRAME:
                    index, raw = unpack_frame(payload)
                    if index == self.active and index < len(self.taps):
                        try:
                            os.write(self.taps[index], raw)
                        except BlockingIOError:
                            pass
                elif kind == ACK:
                    result = json.loads(payload)
                    with self.pending_lock:
                        slot = self.pending.get(result.get('request'))
                        if slot is not None:
                            slot['result'] = result
                            slot['event'].set()
                elif kind == STOP:
                    request = json.loads(payload)
                    # Keep processing activation/release ACKs while the worker
                    # drains; waiting in this reader would deadlock cleanup.
                    threading.Thread(target=self.stop_gracefully, args=(request,), daemon=True).start()
                elif kind == ERROR:
                    raise ValueError(json.loads(payload).get('error', 'Windows paket bağlantısı kesildi.'))
                else:
                    raise ValueError('Beklenmeyen Windows paket kaydı.')
        except Exception as exc:
            print('[lab] Windows bağlantısı kapandı: ' + str(exc), file=sys.stderr, flush=True)
            self.stop.set()
            with self.pending_lock:
                for slot in self.pending.values():
                    slot['result'] = {'ok': False, 'error': 'Windows paket köprüsü kapandı.'}
                    slot['event'].set()

    def tap_loop(self):
        while not self.stop.is_set():
            ready, _, _ = select.select(self.taps, [], [], 0.5)
            for fd in ready:
                index = self.taps.index(fd)
                try:
                    raw = os.read(fd, 65536)
                    if index == self.active and pppoe_frame(raw):
                        self.channel.send(FRAME, frame_record(index, raw))
                except (OSError, ValueError):
                    if not self.stop.is_set():
                        self.stop.set()

    def serve(self, port):
        self.create_taps()
        self.save()
        os.environ['ACS_WINDOWS_BRIDGE_STATE'] = str(self.state)
        import app
        from http.server import ThreadingHTTPServer
        self.lab = app.LAB = app.Lab(BASE)
        # A Windows launch and a normal Linux launch must share the same lock.
        lockfile = open(self.lab.state_dir / 'app.lock', 'a')
        try:
            fcntl.flock(lockfile, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.control = socketserver.ThreadingUnixStreamServer(str(self.folder / 'control.sock'), self.control_handler())
            self.control.daemon_threads = True
            self.http = ThreadingHTTPServer(('127.0.0.1', port), app.Handler)
            for target in (self.read_windows, self.tap_loop):
                threading.Thread(target=target, daemon=True).start()
            for server in (self.control, self.http):
                threading.Thread(target=server.serve_forever, daemon=True).start()
                self.started_servers.append(server)
            self.channel.json(READY, {'url': f'http://127.0.0.1:{port}', 'adapters': len(self.items)})
            self.stop.wait()
        finally:
            self.stop.set()
            if self.lab is not None:
                self.lab.stop_discovery()
                process = self.lab.process
                if process is not None and process.poll() is None:
                    # With the host transport gone, recovery cannot complete.
                    # Stop only our worker and preserve its pending journal.
                    self.lab.log('Windows bağlantısı kesildi; bekleyen geri alma kaydını kontrol edin.', 'warn')
                    process.send_signal(signal.SIGINT)
                    try:
                        process.wait(timeout=20)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait(timeout=5)
            for server in (self.http, self.control):
                if server is not None:
                    if server in self.started_servers:
                        server.shutdown()
                    server.server_close()
            lockfile.close()

    def close(self):
        self.stop.set()
        for fd in self.taps:
            os.close(fd)
        self.taps.clear()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=8890)
    args = parser.parse_args()
    if sys.platform != 'linux' or os.geteuid() != 0 or not 1024 <= args.port <= 65535:
        raise SystemExit('WSL 2 root oturumu ve geçerli panel portu gerekli.')
    os.umask(0o077)
    channel = Channel(sys.stdin.buffer, sys.stdout.buffer)
    kind, payload = channel.receive()
    if kind != HELLO:
        raise SystemExit('Windows başlangıç bilgisi alınamadı.')
    cards = json.loads(payload)['adapters']
    with tempfile.TemporaryDirectory(prefix='acsbridge-', dir='/run') as folder:
        relay = Relay(channel, cards, folder)
        try:
            relay.serve(args.port)
        except (OSError, ValueError) as exc:
            channel.json(ERROR, {'error': str(exc)})
            raise
        finally:
            relay.close()


if __name__ == '__main__':
    main()
