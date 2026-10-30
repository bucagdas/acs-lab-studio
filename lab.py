"""Bounded ACS session controller and evidence tracking."""
import importlib.util
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
import uuid
from collections import deque
from pathlib import Path
from network_recovery import recover
from host_network import (host_info, valid_interface_name, interfaces,
                          interface_details, dependency_issues, service_address,
                          service_addresses, prepare_socket)

BASE = Path(__file__).resolve().parent
STEPS = ['link', 'inform', 'methods', 'names', 'read', 'write', 'restore']
ROLLBACK = ('transformer-cli set Device.Services.X_000E50_AccessManagement.SSH.CliUsers.1.RebootPersistent 1\n'
            'transformer-cli apply\n'
            'transformer-cli get Device.Services.X_000E50_AccessManagement.SSH.CliUsers.1.RebootPersistent')


def validate_settings(data):
    if not isinstance(data, dict):
        raise ValueError('Test ayarları geçersiz.')
    mode = data.get('mode')
    iface = data.get('iface', '')
    mac = data.get('mac', '')
    if isinstance(mac, str):mac=mac.lower()
    vlan = data.get('vlan', 35)
    duration = data.get('duration', 300)
    if mode not in ('readonly', 'write', 'configure', 'log_upload', 'sts_probe', 'root_password'):
        raise ValueError('Geçerli bir test türü seçin.')
    if not valid_interface_name(iface):
        raise ValueError('Geçerli bir fiziksel Ethernet adaptörü seçin.')
    if not isinstance(mac, str) or not re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', mac):
        raise ValueError('Cihazın WAN MAC adresi geçersiz.')
    first = int(mac[:2], 16)
    if first & 1 or mac == '00:00:00:00:00:00':
        raise ValueError('Tek bir router’a ait unicast MAC adresi gerekli.')
    if type(vlan) is not int or not 1 <= vlan <= 4094:
        raise ValueError('VLAN 1–4094 arasında olmalı.')
    if type(duration) is not int or not 120 <= duration <= 900:
        raise ValueError('Test süresi 120–900 saniye arasında olmalı.')
    result=dict(mode=mode, iface=iface, mac=mac, vlan=vlan, duration=duration)
    for name,default in [('local_ip','10.116.13.100'),('peer_ip','10.116.13.101'),
                         ('acs_ip','193.192.97.234'),('management_ip','192.168.1.1')]:
        if name not in data:continue
        try:address=ipaddress.IPv4Address(data[name])
        except (ValueError,TypeError):raise ValueError('Geçerli bir IPv4 adresi gerekli: '+name)
        if address.is_multicast or address.is_loopback or address.is_unspecified or address==ipaddress.IPv4Address('255.255.255.255'):
            raise ValueError('Bu IP adresi test için kullanılamaz: '+name)
        result[name]=str(address)
    if result.get('local_ip','10.116.13.100')==result.get('peer_ip','10.116.13.101'):
        raise ValueError('Bilgisayar PPP ve router PPP IP adresleri farklı olmalı.')
    if mode=='configure':
        target=data.get('target',1)
        ssh=data.get('ssh_action','keep')
        persistence=data.get('persistence','keep')
        password=data.get('cli_password','')
        web_role=data.get('web_admin_role','keep')
        if web_role not in ('keep','engineer','admin'):raise ValueError('Web admin rol seçimi geçersiz.')
        if type(target) is not int or target not in (1,2):raise ValueError('Hedef CLI hesabı 1 veya 2 olmalı.')
        if ssh not in ('keep','enable','disable') or persistence not in ('keep','0','1'):
            raise ValueError('Yazılacak ayarlar geçersiz.')
        if not isinstance(password,str) or (password and not re.fullmatch(r'[A-Za-z0-9_.@+\-]{12,64}',password)):
            raise ValueError('CLI parolası 12–64 karakter olmalı: harf, rakam ve _ . @ + - kullanılabilir.')
        if ssh=='keep' and persistence=='keep' and not password and web_role=='keep':
            raise ValueError('En az bir yapılandırma işlemi seçin.')
        result.update(target=target,ssh_action=ssh,persistence=persistence,cli_password=password,web_admin_role=web_role)
    if mode=='root_password':
        password=data.get('root_password','')
        confirmation=data.get('root_password_confirm','')
        if data.get('root_password_ack') is not True:
            raise ValueError('Root parola değişikliğinin bu cihazdaki root erişimini etkilediğini onaylayın.')
        if not isinstance(password,str) or not re.fullmatch(r'[A-Za-z0-9_.@+\-]{12,64}',password):
            raise ValueError('Root parolası 12–64 karakter olmalı: harf, rakam ve _ . @ + - kullanılabilir.')
        if not isinstance(confirmation,str) or password!=confirmation:
            raise ValueError('Root parola alanları eşleşmiyor.')
        enable_ssh=data.get('root_enable_lan_ssh',False)
        if type(enable_ssh) is not bool:raise ValueError('LAN SSH seçimi geçersiz.')
        result.update(root_password=password,root_password_confirm=confirmation,root_password_ack=True,root_enable_lan_ssh=enable_ssh)
    return result


def public_line(line):
    # Omit packet dumps, PAP/CHAP credentials, raw SOAP and authentication data.
    if not re.match(r'^\[(?:acs(?::\d+)?|cwmp|write-test|config|sts|root-password|ppp|pppoe|dns|ntp|lab|\*)\]', line):
        return None
    if line.startswith('[root-password]'):
        # Do not hide status just because the category contains 'password'.
        # Never forward arbitrary payload/debug text from this category.
        if 'ROOT_PASSWORD_TRANSFER_FAILED' in line:
            code=re.search(r'kod=(\d{4})',line)
            return '[lab] Root ayarları aktarımı başarısız.' + (' Cihaz hata kodu: '+code.group(1) if code else '')
        if 'ROOT_PASSWORD_TRANSFER_REPORTED' in line:
            return '[lab] Root ayarları aktarımı tamamlandı; SSH ile doğrula.'
        if 'ROOT_PASSWORD_DOWNLOAD_SENT' in line:
            return '[lab] Root ayarları aktarımı istendi.'
        if line=='[root-password] STS dosyası hedef routera gönderildi':
            return '[lab] Root ayar dosyası hedef cihaza gönderildi.'
        return None
    if any(word in line.lower() for word in ('password', 'authorization', 'cookie', '<?xml', '<soap', 'pap auth', 'chap auth')):
        return None
    if line.startswith(('[dns]', '[ntp]')) and not any(word in line.lower() for word in ('listening', 'failed')):
        return None
    line = re.sub(r'(Inform from )\S+', r'\1[cihaz]', line)
    return line[:1200]


class Lab:
    def discover(self, data):
        if not isinstance(data, dict):
            raise ValueError('Keşif ayarları geçersiz.')
        iface = data.get('iface')
        with self.lock:
            if self.process is not None and self.process.poll() is None:
                raise ValueError('Keşif için önce çalışan ACS oturumunu tamamlayın.')
            reasons = self.readiness()
            if reasons:
                raise ValueError(' '.join(reasons))
            if iface not in {item['id'] for item in interfaces()}:
                raise ValueError('Geçerli bir Ethernet adaptörü seçin.')
            if self.discovery['running']:
                raise ValueError('Bir WAN keşfi zaten çalışıyor.')
            self.discovery_cancel = threading.Event()
            self.discovery = {'running': True, 'iface': iface, 'candidates': [],
                              'error': '', 'cancelled': False, 'id': uuid.uuid4().hex}
            self.discovery_thread = threading.Thread(target=self._discover_worker,
                                                      args=(iface, self.discovery_cancel), daemon=True)
            self.discovery_thread.start()
            return dict(self.discovery)

    def _discover_worker(self, iface, cancel):
        from discovery import discover
        try:
            candidates = discover(iface, cancel)
            message = ''
        except Exception:
            candidates = []
            message = 'Paket dinleme başarısız; adaptör ve yakalama yetkisini kontrol edin.'
        with self.lock:
            self.discovery.update(running=False, candidates=candidates, error=message,
                                  cancelled=cancel.is_set())

    def stop_discovery(self):
        with self.lock:
            self.discovery_cancel.set()

    def __init__(self, base=BASE, preview=False):
        self.base = Path(base)
        self.preview = preview
        self.state_dir = self.base/'.state'
        self.runs = self.base/'.runs'
        for path in (self.state_dir, self.runs):
            path.mkdir(exist_ok=True, parents=True, mode=0o700)
        self.journal = self.state_dir/'write_probe_state.json'
        self.lock = threading.RLock()
        self.discovery_cancel = threading.Event()
        self.discovery_thread = None
        self.discovery = {'running': False, 'iface': None, 'candidates': [],
                          'error': '', 'cancelled': False, 'id': None}
        self.process = None
        self.worker_thread = None
        self.finished = None
        self.cleanup_failed = False
        self.events = deque(maxlen=4000)
        self.sequence = 0
        self.run_id = None
        self.run_dir = None
        self.settings = None
        self.started = None
        self.outcome = 'idle'
        self.steps = {name:'waiting' for name in STEPS}
        self.values = {}
        self.stopping = False
        self.worker_marker = False
        self.error = ''
        self.router_confirmed=False

    def read_journal(self):
        try:
            data = json.loads(self.journal.read_text())
            if not isinstance(data, dict) or data.get('status') not in ('pending', 'restored'):
                return {'status':'unknown'}
            return data
        except FileNotFoundError:
            return {}
        except (ValueError, OSError):
            return {'status':'unknown'}

    def read_configuration(self):
        if not self.run_dir:return {}
        try:return json.loads((self.run_dir/'configuration-state.json').read_text())
        except (OSError,ValueError):return {}

    def read_capabilities(self):
        if not self.run_dir:return {}
        try:return json.loads((self.run_dir/'capabilities.json').read_text())
        except (OSError,ValueError):return {}

    def read_upload_probe(self):
        if not self.run_dir:return {}
        try:return json.loads((self.run_dir/'upload-probe.json').read_text())
        except (OSError,ValueError):return {}

    def read_root_password_transfer(self):
        if not self.run_dir:return {}
        try:return json.loads((self.run_dir/'root-password-transfer.json').read_text())
        except (OSError,ValueError):return {}

    def _running(self):
        return bool((self.process is not None and self.process.poll() is None) or
                    (self.worker_thread is not None and self.worker_thread.is_alive()))

    def recover_network(self):
        with self.lock:
            if self.preview or os.geteuid() != 0:
                raise ValueError('Ağ kurtarma için uygulamayı yönetici yetkisiyle açın.')
            if self._running() or self.discovery['running']:
                raise ValueError('Önce mevcut ağ oturumunun kapanmasını bekleyin.')
            try:
                restored = recover(self.base)
            except (OSError, ValueError) as exc:
                raise ValueError(str(exc)) from exc
            self.error = ''
            self.log('Geçici ağ ayarı geri alındı.' if restored else 'Bekleyen ağ kurtarma kaydı yok.')
            return self.snapshot()

    def readiness(self):
        reasons=[]
        if self.preview:
            reasons.append('Önizleme modu: ağ testleri devre dışı.')
        reasons.extend(dependency_issues())
        if os.geteuid() != 0:
            reasons.append('Ağ testi için ' + host_info()['launcher'] + ' dosyasını sudo yetkisiyle çalıştırın.')
        if importlib.util.find_spec('scapy') is None:
            reasons.append('Bu Python ortamında scapy bulunamadı.')
        running=self._running()
        if (self.state_dir/'pap-recovery.json').exists() and not running:
            reasons.append('Geçici ağ ayarı geri alınmalı. Ağ ayarını kurtar düğmesini kullanın.')
        return reasons

    def log(self, message, kind='info'):
        self.sequence += 1
        event={'id':self.sequence, 'time':time.strftime('%H:%M:%S'), 'message':message, 'kind':kind}
        self.events.append(event)
        if self.run_dir:
            path=self.run_dir/'session.log'
            fd=os.open(path, os.O_WRONLY|os.O_APPEND|os.O_CREAT, 0o600)
            with os.fdopen(fd,'a') as f:
                f.write(f"{event['time']} [{kind}] {message}\n")

    def snapshot(self, after=0):
        with self.lock:
            running=self._running()
            journal=self.read_journal()
            pending=journal.get('status') in ('pending','unknown')
            write_in_flight=bool(self.settings and self.settings['mode'] in ('write','sts_probe','root_password') and self.steps['inform']=='done' and self.outcome=='running')
            if self.settings and self.settings['mode']=='configure' and self.steps['inform']=='done' and self.outcome=='running':write_in_flight=True
            return dict(running=running, outcome='needs_restore' if pending and not running else self.outcome,
                        steps=dict(self.steps), values=dict(self.values), runId=self.run_id,
                        settings=self.settings, elapsed=round((self.finished or time.monotonic())-self.started) if self.started else 0,
                        finishing=running and (self.outcome != 'running' or self.stopping),
                        networkRecovery=(self.state_dir/'pap-recovery.json').exists() and not running,
                        cleanupFailed=self.cleanup_failed,
                        journal=journal, pending=pending, canStop=running and self.outcome=='running' and not pending and not write_in_flight,
                        events=[e for e in self.events if e['id']>after], cursor=self.sequence,
                        readiness=self.readiness(), rollback=ROLLBACK, error=self.error, routerConfirmed=self.router_confirmed,
                        configuration=self.read_configuration(), discovery=dict(self.discovery), capabilities=self.read_capabilities(), uploadProbe=self.read_upload_probe(),
                        rootPasswordTransfer=self.read_root_password_transfer())

    @staticmethod
    def free_ports(settings=None):
        settings=settings or {}
        local=settings.get('local_ip','10.116.13.100')
        acs=settings.get('acs_ip','193.192.97.234')
        endpoints=[(socket.SOCK_STREAM,ip,port) for ip in service_addresses(local,acs) for port in (80,443)]
        endpoints += [(socket.SOCK_DGRAM,service_address(local),port) for port in (53,123)]
        sockets=[]
        try:
            for kind,ip,port in endpoints:
                sock=socket.socket(socket.AF_INET,kind)
                sockets.append(sock)
                try:
                    prepare_socket(sock)
                    sock.bind((ip,port))
                except OSError as exc:raise ValueError(f'{ip}:{port} kullanılıyor veya açılamıyor. Önce eski test sunucusunu durdurun.') from exc
        finally:
            for sock in sockets:sock.close()

    def start(self, data):
        settings=validate_settings(data)
        with self.lock:
            if self.discovery['running']:
                raise ValueError('Önce WAN keşfini durdurun veya tamamlanmasını bekleyin.')
            if self._running():
                raise ValueError('Bir test çalışıyor veya ağ temizliği sürüyor.')
            reasons=self.readiness()
            if reasons:raise ValueError(' '.join(reasons))
            if settings['iface'] not in {item['id'] for item in interfaces()}:
                raise ValueError('Seçilen Ethernet adaptörü bu bilgisayarda bulunamadı.')
            journal=self.read_journal()
            if journal.get('status')=='unknown':
                raise ValueError('Geri alma kaydı okunamıyor. SSH ile mevcut değeri kontrol edin.')
            if journal.get('status')=='pending' and settings['mode']!='write':
                raise ValueError('Bekleyen geri alma var. Yazma / geri alma testini seçin.')
            self.free_ports(settings)
            self.run_id=uuid.uuid4().hex[:12]
            self.run_dir=self.runs/self.run_id
            self.run_dir.mkdir(mode=0o700)
            if settings['mode']=='write' and journal.get('status')=='restored':
                (self.run_dir/'previous-restored.json').write_text(json.dumps(journal))
                self.journal.unlink()
            self.settings={k:v for k,v in settings.items() if k not in ('cli_password','root_password','root_password_confirm','root_password_ack')}
            if settings['mode']=='configure':self.settings['passwordRequested']=bool(settings.get('cli_password'))
            if settings['mode']=='root_password':self.settings['passwordRequested']=True
            self.events.clear()
            self.steps={name:'waiting' for name in STEPS}
            self.steps['link']='active'
            if settings['mode'] in ('readonly','log_upload'):
                self.steps['write']=self.steps['restore']='skipped'
            elif settings['mode'] in ('configure','root_password'):self.steps['restore']='skipped'
            self.values={}
            self.stopping=False
            self.worker_marker=False
            self.error=''
            self.router_confirmed=False
            self.outcome='running'
            self.finished=None
            self.cleanup_failed=False
            self.started=time.monotonic()
            command=[sys.executable,'-u',str(self.base/'runner.py'),'--mode',settings['mode'],
                     '--iface',settings['iface'],'--peer-mac',settings['mac'],'--vlan',str(settings['vlan']),
                     '--duration',str(settings['duration']),'--run-dir',str(self.run_dir)]
            try:
                self.process=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
                                              text=True,bufsize=1,start_new_session=True)
                worker_settings={k:v for k,v in settings.items() if k not in ('root_password_confirm','root_password_ack')}
                self.process.stdin.write(json.dumps(worker_settings)+'\n')
                self.process.stdin.close()
                settings['root_password']=''
                settings['root_password_confirm']=''
            except OSError as exc:
                self.outcome='failed'
                raise ValueError('Test motoru başlatılamadı.') from exc
            self.log('Test başlatıldı. Router WAN → seçilen Ethernet; yönetim SSH → Wi-Fi/LAN.')
            if journal.get('status')=='pending':self.log('Yarım kalan deneme algılandı; önce eski değer geri yüklenecek.','warn')
            self.worker_thread=threading.Thread(target=self._watch,args=(self.process,),daemon=True)
            self.worker_thread.start()

    def consume(self, line):
        with self.lock:
            line=line.strip()
            if line.startswith('[pppoe] PADI'):
                self.router_confirmed=True
                self.log('Seçilen cihazdan PPPoE isteği alındı; bağlantı doğrulandı.')
            if 'ipcp: up' in line or 'local  IP address' in line:
                self.steps['link']='done'
                if self.steps['inform']=='waiting':self.steps['inform']='active'
            for marker,step in [('received RPC=Inform ','inform'),('received RPC=GetRPCMethodsResponse ','methods'),
                                ('received RPC=GetParameterNamesResponse ','names'),('received RPC=GetParameterValuesResponse ','read')]:
                if marker in line:
                    self.steps[step]='done'
                    next_step={'inform':'methods','methods':'names','names':'read'}.get(step)
                    if next_step and self.steps.get(next_step)=='waiting':self.steps[next_step]='active'
            if '[lab] NETWORK_CLEANUP_FAILED' in line:
                self.cleanup_failed=True
                self.error='Ağ temizliği tamamlanamadı. Ağ kurtarma durumunu kontrol edin.'
            if 'SetParameterValues RebootPersistent=0' in line:self.steps['write']='active'
            if '[config] Sending selected settings' in line:self.steps['write']='active'
            if '[sts] STS_DOWNLOAD_SENT' in line:self.steps['write']='active'
            if '[sts] STS_TOGGLE_VERIFIED' in line:self.steps['write']='done';self.steps['restore']='active'
            if '[sts] STS_PASS_RESTORED' in line:
                journal=self.read_journal()
                if journal.get('status')=='restored' and journal.get('toggle_verified') is True:
                    self.steps['write']=self.steps['restore']='done';self.outcome='success';self.worker_marker=True
            if '[sts] STS_PROBE_FAILED' in line:
                self.outcome='needs_restore' if self.read_journal().get('status')=='pending' else 'failed'
                self.error='STS testi doğrulanamadı; geri alma durumunu kontrol edin.'
            if '[lab] LOG_UPLOAD_VERIFIED' in line and self.read_upload_probe().get('status')=='verified':
                self.outcome='success';self.worker_marker=True
            if '[write-test] WRITE_TEST_REFUSED' in line:
                self.outcome='failed';self.error='Başlangıç ayarları uygun değil; test yazma yapmadan durdu.'
            if '[lab] LOG_UPLOAD_FAILED' in line:
                self.outcome='failed';self.error='Standart log aktarımı doğrulanamadı.'
            if '[root-password] ROOT_PASSWORD_TRANSFER_REPORTED' in line:
                self.steps['write']='done';self.outcome='password_check_required';self.worker_marker=True
            if '[root-password] ROOT_PASSWORD_TRANSFER_FAILED' in line:
                self.outcome='failed';self.error=self.read_root_password_transfer().get('error') or 'Root parola aktarımı doğrulanmadı; aktarım hata kodunu kontrol edin.'
            if '[config] CONFIG_APPLIED_VERIFIED' in line:
                if self.read_configuration().get('status')=='verified':
                    self.steps['write']='done';self.outcome='success';self.worker_marker=True
            if '[config] CONFIG_PASSWORD_ACKNOWLEDGED' in line:
                if self.read_configuration().get('status')=='password_acknowledged':
                    self.steps['write']='done';self.outcome='password_check_required';self.worker_marker=True
            if '[config] CONFIG_FAILED' in line:
                self.outcome='failed';self.error='Seçilen ayarların uygulanması doğrulanamadı. Günlüğü ve cihaz ayarlarını kontrol edin.'
            if "changed value readback='0' verified=True" in line:self.steps['write']='done'
            if 'stage=probe_restore' in line:self.steps['restore']='active'
            if 'WRITE_TEST_PASS_RESTORED' in line:
                self.worker_marker=True
                journal=self.read_journal()
                if journal.get('status')=='restored' and journal.get('toggle_verified') is True:
                    self.steps['write']=self.steps['restore']='done'
                    self.outcome='success'
            if 'RESTORED_BUT_TOGGLE_NOT_PROVEN' in line:
                self.steps['restore']='done'
                self.outcome='restored_only'
            if 'read-only diagnostic complete' in line and self.settings and self.settings['mode']=='readonly':
                self.worker_marker=True
                self.outcome='success'
                self.steps['inform']=self.steps['methods']=self.steps['names']=self.steps['read']='done'
            if '[acs] CPE SOAP Fault' in line and self.settings and self.settings['mode']=='readonly':
                self.outcome='failed';self.error='Router salt okunur ACS sorgusuna hata döndürdü.';self.stopping=True
                if self.process and self.process.poll() is None:
                    try:self.process.send_signal(signal.SIGINT)
                    except OSError:pass
            match=re.search(r'CliUsers\.([12])\.(Username|Enable|Access|RebootPersistent) = (.+)',line)
            if match:self.values[match[1]+'.'+match[2]]=match[3].strip("'\"")
            if 'changed value readback=' in line:
                self.values['writeReadback']='0' if 'verified=True' in line else 'doğrulanamadı'
            if 'WRITE_TEST_PASS_RESTORED' in line:self.values['restoreReadback']='1'
            if ('SOAP Fault' in line and 'Inventory group ' not in line) or 'RESTORE_UNCONFIRMED' in line:
                self.error='Cihaz hatası veya geri alma doğrulama sorunu; günlüğü kontrol edin.'
            message=public_line(line)
            if message:self.log(message,'warn' if any(t in line.lower() for t in ['fault','failed','unconfirmed','mismatch']) else 'info')

    def _watch(self, process):
        try:
            for line in process.stdout:self.consume(line)
            code=process.wait()
            with self.lock:
                journal=self.read_journal()
                if journal.get('status') in ('pending','unknown'):
                    self.outcome='needs_restore'
                    self.log('Geri alma doğrulanmadı. Router SSH üzerinden geri alma komutlarını uygulayın.','warn')
                elif self.outcome not in ('success','restored_only','password_check_required','failed'):
                    self.outcome='stopped' if self.stopping else 'incomplete' if code==0 else 'failed'
                self.finished=time.monotonic()
                if code != 0 or (self.state_dir/'pap-recovery.json').exists():
                    self.cleanup_failed=True
                    self.error='Ağ motoru temiz kapanmadı. Ağ kurtarma durumunu kontrol edin.'
                if self.cleanup_failed:
                    self.outcome='failed'
                self.log(f'Test motoru kapandı. Sonuç: {self.outcome}.')
        except Exception:
            with self.lock:
                self.outcome='needs_restore' if self.read_journal().get('status')=='pending' else 'failed'
                self.error='Test çıktısı okunamadı; süreç ve geri alma durumunu kontrol edin.'
                self.finished=time.monotonic()

    def stop(self):
        with self.lock:
            if not self.process or self.process.poll() is not None:return
            if self.read_journal().get('status') in ('pending','unknown'):
                raise ValueError('Yazma/geri alma sürüyor. Testi durdurmak yerine geri alma sonucunu bekleyin.')
            if self.settings['mode'] in ('write','configure','sts_probe','root_password') and self.steps['inform']=='done' and self.outcome=='running':
                raise ValueError('Yazma testi oturumu başladı. Doğrulama ve geri alma bitene kadar bekleyin.')
            self.stopping=True
            self.log('Durdurma istendi; testin başlattığı PPP işlemi temizleniyor.')
            self.process.send_signal(signal.SIGINT)

    def export(self):
        with self.lock:
            report={'runId':self.run_id,'outcome':self.outcome,'settings':self.settings,
                    'steps':self.steps,'values':self.values,'journal':self.read_journal(),
                    'configuration':self.read_configuration(),'capabilities':self.read_capabilities(),'uploadProbe':self.read_upload_probe(),
                    'rootPasswordTransfer':self.read_root_password_transfer(),
                    'note':'Bu rapor yalnızca bu oturuma aittir. Stok cihazda ilk erişim kanıtı değildir.'}
            text=json.dumps(report,ensure_ascii=False,indent=2)+'\n\n'
            text+='\n'.join(f"{e['time']} {e['message']}" for e in self.events)
            return text.encode()
