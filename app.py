#!/usr/bin/env python3
import argparse
import sys
if sys.platform == 'win32':
    raise SystemExit('Windows için Baslat.cmd kullanın. Windows bağlantısı Npcap ve WSL 2 üzerinden çalışır.')
import fcntl
import hmac
import json
import secrets
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from lab import Lab, interfaces, interface_details
from host_network import host_info

BASE=Path(__file__).resolve().parent
TOKEN=secrets.token_urlsafe(32)
LAB=None


class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args): pass

    def common(self):
        self.send_header('Cache-Control','no-store')
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('Referrer-Policy','no-referrer')
        self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")

    def respond(self,code,data,mime='application/json',download=False):
        if not isinstance(data,bytes):data=json.dumps(data,ensure_ascii=False).encode()
        self.send_response(code)
        self.common()
        self.send_header('Content-Type',mime)
        self.send_header('Content-Length',str(len(data)))
        if download:self.send_header('Content-Disposition','attachment; filename="acs-test-report.txt"')
        self.end_headers()
        self.wfile.write(data)

    def local(self):
        return self.headers.get('Host')==f'127.0.0.1:{self.server.server_port}'

    def authenticated(self):
        return self.local() and hmac.compare_digest(self.headers.get('X-Local-Token',''),TOKEN)

    def do_GET(self):
        if not self.local():
            self.respond(403,{})
            return
        request=urlsplit(self.path)
        if request.path=='/api/bootstrap':
            self.respond(200,{'token':TOKEN,'interfaces':interfaces(),'host':host_info(),'state':LAB.snapshot(),
                              'reference':{'label':'Önceki cihaz testi', 'result':'WRITE_TEST_PASS_RESTORED',
                                           'sequence':'1 → 0 → okundu: 0 → 1 → okundu: 1',
                                           'note':'Bu, mevcut oturumun sonucu değildir.'}})
        elif request.path=='/api/events':
            if not self.authenticated():self.respond(403,{});return
            try:after=max(0,int(parse_qs(request.query).get('after',['0'])[0]))
            except ValueError:self.respond(400,{'error':'Geçersiz cursor.'});return
            self.respond(200,LAB.snapshot(after))
        elif request.path=='/api/report':
            if not self.authenticated():self.respond(403,{});return
            self.respond(200,LAB.export(),'text/plain; charset=utf-8',True)
        elif request.path=='/api/interface':
            if not self.authenticated():self.respond(403,{});return
            try:self.respond(200,interface_details(parse_qs(request.query).get('name',[''])[0]))
            except ValueError as exc:self.respond(400,{'error':str(exc)})
        else:
            files={'/':('index.html','text/html; charset=utf-8'),'/app.js':('app.js','text/javascript; charset=utf-8'),
                   '/style.css':('style.css','text/css; charset=utf-8')}
            if request.path not in files:self.respond(404,{});return
            name,mime=files[request.path]
            self.respond(200,(BASE/'static'/name).read_bytes(),mime)

    def do_POST(self):
        origin=f'http://127.0.0.1:{self.server.server_port}'
        if not self.authenticated() or self.headers.get('Origin') not in (None,origin):
            self.respond(403,{})
            return
        try:
            length=int(self.headers.get('Content-Length',0))
            if not 0<length<=8192:raise ValueError('İstek boyutu geçersiz.')
            data=json.loads(self.rfile.read(length))
            if self.path=='/api/discover':
                self.respond(200,LAB.discover(data))
                return
            if self.path=='/api/start':LAB.start(data)
            elif self.path=='/api/discovery/stop':LAB.stop_discovery()
            elif self.path=='/api/stop':LAB.stop()
            else:self.respond(404,{});return
            self.respond(200,LAB.snapshot())
        except (ValueError,TypeError) as exc:
            self.respond(400,{'error':str(exc)})
        except Exception:
            self.respond(500,{'error':'İşlem başlatılamadı. Terminali ve kurtarma durumunu kontrol edin.'})


if __name__=='__main__':
    p=argparse.ArgumentParser(description='Local ACS Lab Studio')
    p.add_argument('--port',type=int,default=8890)
    p.add_argument('--preview',action='store_true',help='Arayüzü ağ testi çalıştırmadan aç')
    args=p.parse_args()
    LAB=Lab(preview=args.preview)
    lockfile=open(LAB.state_dir/'app.lock','a')
    try:fcntl.flock(lockfile,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError:raise SystemExit('ACS Lab Studio zaten açık.')
    server=ThreadingHTTPServer(('127.0.0.1',args.port),Handler)
    print(f'ACS Lab Studio: http://127.0.0.1:{server.server_port}',flush=True)
    print('Ağ testi yalnızca arayüzde Başlat seçilince çalışır. Çıkmadan önce testi arayüzden durdurun.',flush=True)
    try:
        while True:
            try:
                server.serve_forever()
                break
            except KeyboardInterrupt:
                try:
                    LAB.stop()
                except ValueError:
                    print('Geri alma bekliyor; panel açık tutuluyor. İşlemin bitmesini bekleyin.',flush=True)
                    continue
                if LAB.process is not None:
                    try:LAB.process.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        print('Ağ temizliği sürüyor; panel açık tutuluyor.',flush=True)
                        continue
                break
    finally:
        LAB.stop_discovery()
        if LAB.discovery_thread is not None:LAB.discovery_thread.join(timeout=3)
        server.server_close()
