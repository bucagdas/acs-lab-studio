#!/usr/bin/env python3
"""Windows entry point. Npcap stays on Windows; PPP/IP and UI run in WSL 2."""
import argparse
import ctypes
import importlib.util
import json
import os
import socket
from pathlib import Path
import subprocess
import sys
import threading
import uuid
import venv
import webbrowser

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))
from windows.capture import adapters, Capture
from windows.protocol import Channel, HELLO, FRAME, SELECT, ACK, STATUS, READY, STOP, ERROR, unpack_frame

TARGET = '/var/lib/acs-lab-studio'


def decode_output(data):
    if data.startswith((b'\xff\xfe', b'\xfe\xff')):
        return data.decode('utf-16').strip()
    if b'\x00' in data[:80]:
        return data.decode('utf-16-le').strip()
    return data.decode('utf-8-sig').strip()


def wsl_command(distro, *args):
    return ['wsl.exe', '--distribution', distro, '--user', 'root', '--exec', *args]


def output(command):
    result = subprocess.run(command, capture_output=True, timeout=30)
    if result.returncode:
        raise RuntimeError('Komut çalışmadı. WSL 2 kurulumunu ve seçilen dağıtımı kontrol edin.')
    return decode_output(result.stdout)


def distribution(requested=None):
    names = [name.strip() for name in output(['wsl.exe', '--list', '--quiet']).splitlines() if name.strip()]
    if not names:
        raise RuntimeError('Önce WSL 2 ve Ubuntu kurun. WINDOWS.md dosyasına bakın.')
    if requested is not None:
        if requested not in names:
            raise ValueError('Seçilen WSL dağıtımı kurulu değil.')
        selected = requested
    elif len(names) == 1:
        selected = names[0]
    else:
        for number, name in enumerate(names, 1):
            print(f'{number}. {name}')
        value = input('WSL dağıtım numarası: ').strip()
        if not value.isdigit() or not 1 <= int(value) <= len(names):
            raise ValueError('Geçerli bir dağıtım seçin.')
        selected = names[int(value) - 1]
    release = output(wsl_command(selected, 'uname', '-r')).lower()
    if 'wsl2' not in release:
        raise RuntimeError('Bu dağıtım WSL 2 kullanmıyor. WINDOWS.md dosyasına bakın.')
    return selected


def setup(distro):
    environment = BASE / '.venv-win'
    python = environment / 'Scripts' / 'python.exe'
    if not python.exists():
        venv.EnvBuilder(with_pip=True).create(environment)
    subprocess.run([str(python), '-m', 'pip', 'install', '-r', str(BASE / 'requirements.txt')], check=True)
    source = output(wsl_command(distro, 'wslpath', '-a', '-u', str(BASE)))
    subprocess.run(wsl_command(distro, 'sh', source + '/windows/setup-wsl.sh', source), check=True)
    print('Hazırlık tamamlandı. Güncel Npcap kuruluyken Baslat.cmd dosyasını yönetici olarak açın.')


def check(distro):
    problems = []
    if importlib.util.find_spec('scapy') is None:
        problems.append('Windows Python ortamında Scapy yok; Kurulum.cmd çalıştırın.')
    dll = Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32' / 'Npcap' / 'wpcap.dll'
    if not dll.is_file():
        problems.append('Npcap bulunamadı. Resmi kurulum bağlantısı WINDOWS.md içinde.')
    cards = adapters()
    if not cards:
        problems.append('USB veya dahili fiziksel Ethernet kartı bulunamadı.')
    for card in cards:
        print(f"{card['name']}: {card['description']} ({'aktif' if card['active'] else 'pasif'})")
    result = subprocess.run(wsl_command(distro, TARGET + '/.venv/bin/python3',
                                        TARGET + '/windows/check_backend.py'))
    if result.returncode:
        problems.append('WSL hazırlığı eksik; Kurulum.cmd ve WINDOWS.md dosyasına bakın.')
    for problem in problems:
        print('Eksik: ' + problem, file=sys.stderr)
    return cards, problems


class WindowsRelay:
    def __init__(self, process, cards, port):
        self.process, self.cards, self.port = process, cards, port
        self.channel = Channel(process.stdout, process.stdin)
        self.capture = Capture(cards, self.channel)
        self.finished = threading.Event()
        self.stop_reply = threading.Event()
        self.stop_key = None
        self.stop_result = None
        self.error = None

    def read(self):
        try:
            while not self.finished.is_set():
                kind, payload = self.channel.receive()
                if kind == FRAME:
                    index, raw = unpack_frame(payload)
                    self.capture.send(index, raw)
                elif kind in (SELECT, STATUS):
                    request = json.loads(payload)
                    response = {'request': request.get('request')}
                    try:
                        if kind == SELECT:
                            self.capture.select(request.get('index'))
                        else:
                            response['adapters'] = adapters()
                        response['ok'] = True
                    except Exception as exc:
                        response.update(ok=False, error=str(exc))
                    self.channel.json(ACK, response)
                elif kind == READY:
                    print(f'ACS Lab Studio: http://127.0.0.1:{self.port}', flush=True)
                    print('Panelde Ethernet kartını seçin. Çıkmadan önce işlemi panelden durdurun.', flush=True)
                    webbrowser.open(f'http://127.0.0.1:{self.port}')
                elif kind == ACK:
                    response = json.loads(payload)
                    if response.get('request') == self.stop_key:
                        self.stop_result = response
                        self.stop_reply.set()
                elif kind == ERROR:
                    raise RuntimeError(json.loads(payload).get('error', 'WSL paket bağlantısı başarısız.'))
                else:
                    raise ValueError('Beklenmeyen WSL paket kaydı.')
        except Exception as exc:
            if self.process.poll() not in (None, 0) or not self.stop_reply.is_set():
                self.error = str(exc)
        finally:
            self.finished.set()

    def stop(self):
        self.stop_key = uuid.uuid4().hex
        self.stop_reply.clear()
        self.channel.json(STOP, {'request': self.stop_key})
        if not self.stop_reply.wait(25):
            print('WSL kapanışı bekleniyor. İşlem sürüyorsa paneli kontrol edin.', flush=True)
            return False
        if not self.stop_result.get('ok'):
            print(self.stop_result.get('error', 'İşlemin bitmesini bekleyin.'), flush=True)
            return False
        return True

    def run(self):
        self.channel.json(HELLO, {'adapters': self.cards})
        threading.Thread(target=self.read, daemon=True).start()
        try:
            while not self.finished.is_set():
                try:
                    self.finished.wait(0.25)
                except KeyboardInterrupt:
                    try:
                        if self.stop():
                            self.finished.wait(35)
                            break
                    except KeyboardInterrupt:
                        continue
        finally:
            try:
                self.capture.close()
            except Exception:
                self.error = self.error or 'Windows paket dinleme bağlantısı kapatılamadı.'
            if self.process.stdin:
                self.process.stdin.close()
            try:
                self.process.wait(timeout=35)
            except subprocess.TimeoutExpired:
                # Killing only wsl.exe closes the pipe; the backend cleans its
                # owned worker and TAP devices and retains recovery journals.
                self.process.terminate()
            if self.error:
                raise RuntimeError(self.error)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mode', choices=('setup', 'check', 'run'), default='run')
    parser.add_argument('--distro')
    parser.add_argument('--port', type=int, default=8890)
    args = parser.parse_args()
    if sys.platform != 'win32':
        raise SystemExit('Bu başlatıcı Windows içindir. Mac: Baslat.command, Linux: Baslat.sh.')
    if sys.maxsize <= 2 ** 32:
        raise SystemExit('Windows başlatıcısı için 64 bit Python kullanın.')
    if not 1024 <= args.port <= 65535:
        raise ValueError('Panel portu 1024-65535 aralığında olmalı.')
    selected = distribution(args.distro)
    if args.mode == 'setup':
        setup(selected)
        return
    cards, problems = check(selected)
    if problems or args.mode == 'check':
        if problems:
            raise SystemExit(1)
        return
    if not ctypes.windll.shell32.IsUserAnAdmin():
        raise RuntimeError('Baslat.cmd dosyasını sağ tıklayıp yönetici olarak çalıştırın.')
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        try:
            probe.bind(('127.0.0.1', args.port))
        except OSError as exc:
            raise RuntimeError('Panel portu kullanılıyor. Eski oturumu kapatın veya --port ile başka port seçin.') from exc
    # No capture is opened until an interface lease arrives from the UI.
    process = subprocess.Popen(wsl_command(selected, TARGET + '/.venv/bin/python3',
                                           TARGET + '/windows/wsl_relay.py', '--port', str(args.port)),
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=None, bufsize=0)
    WindowsRelay(process, cards, args.port).run()


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        print('Hata: ' + str(exc), file=sys.stderr)
        raise SystemExit(1)
