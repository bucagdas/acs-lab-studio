"""Bounded STS Download test: one known 1 -> 0 -> 1 value, recoverable journal."""
import json
import os
import secrets
import threading
from http.server import BaseHTTPRequestHandler
from host_network import LabHTTPServer as ThreadingHTTPServer, service_address

PATH = 'Device.Services.X_000E50_AccessManagement.SSH.CliUsers.1.'
JOURNAL_NAME = 'write_probe_state.json'
SCRIPT = b'set clash.engineer.persist_ssh_on_reboot=0\n'


def install(engine, run, state_dir, peer_ip, local_ip, port=8778):
    journal = state_dir / JOURNAL_NAME
    report_path = run / 'sts-probe.json'
    token = secrets.token_urlsafe(24)
    endpoint = '/sts-test/' + token
    command = 'acs-lab-sts-' + secrets.token_hex(6)
    report = {'status': 'waiting', 'commandKey': command, 'target': PATH + 'RebootPersistent',
              'baseline': None, 'toggle': None, 'restore': None, 'served': False}
    lock = threading.RLock()

    def write_json(path, data):
        temp = path.with_name(path.name + '.tmp')
        fd = os.open(temp, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
        with os.fdopen(fd, 'w') as f:
            json.dump(data, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, path)

    def save(**updates):
        with lock:
            report.update(updates)
            write_json(report_path, report)
    save()

    class Receiver(BaseHTTPRequestHandler):
        def log_message(self, *args):pass
        def do_GET(self):
            if self.client_address[0] != peer_ip or self.path != endpoint:
                self.send_response(403);self.send_header('Content-Length','0');self.end_headers();return
            self.send_response(200)
            self.send_header('Content-Type','text/plain')
            self.send_header('Content-Length',str(len(SCRIPT)))
            self.end_headers()
            self.wfile.write(SCRIPT)
            save(served=True)
            print('[sts] Test dosyası cihaza gönderildi',flush=True)

    server = ThreadingHTTPServer((service_address(local_ip),port),Receiver)
    server.daemon_threads=True
    threading.Thread(target=server.serve_forever,daemon=True).start()

    class StsHandler(engine.ACSHandler):
        def fail(self,message):
            save(status='failed',error=message)
            self.server.state.stage='sts_failed'
            print('[sts] STS_PROBE_FAILED: '+message,flush=True)
            self._send(204)

        def _sts_request(self,stage,build):
            st=self.server.state;mid=st.next_id();st.pending_id=mid;st.stage=stage
            self._send(200,build(mid))

        def matches(self,mid):
            if mid==self.server.state.pending_id:return True
            self.fail('RPC yanıt kimliği eşleşmedi')
            return False

        def values_request(self,stage):
            self._sts_request(stage,lambda mid:engine._get_parameter_values(self.server.state.namespace,mid,
                         [PATH+'Username',PATH+'Enable',PATH+'Access',PATH+'RebootPersistent']))

        def _handle_rpc_methods_response(self,root,received_id):
            if not self.matches(received_id):return
            methods=[n.text or '' for n in root.iter() if engine._local_name(n.tag)=='string']
            if not {'Download','GetParameterValues','SetParameterValues'}.issubset(methods):
                self.fail('Download / okuma / geri alma yöntemlerinden biri yok');return
            phase=report['status']
            if phase=='waiting':self.values_request('sts_baseline')
            elif phase=='transfer_complete':self.values_request('sts_toggle_read')
            else:self.server.state.stage='sts_wait';self._send(204)

        def _handle_get_values_response(self,root,received_id):
            if not self.matches(received_id):return
            st=self.server.state;values={}
            for node in root.iter():
                if engine._local_name(node.tag)!='ParameterValueStruct':continue
                name=next((c.text or '' for c in node if engine._local_name(c.tag)=='Name'),'')
                value=next((c.text or '' for c in node if engine._local_name(c.tag)=='Value'),'')
                if name.startswith(PATH):
                    name=name[len(PATH):]
                    if name in values:self.fail('Yinelenen değer');return
                    values[name]={'true':'1','false':'0'}.get(value,value)
            required={'Username','Enable','Access','RebootPersistent'}
            if set(values)!=required or values['Username']!='engineer':
                self.fail('engineer hesabı ve tüm başlangıç alanları doğrulanamadı');return
            current=values['RebootPersistent']
            if st.stage=='sts_baseline':
                if current!='1' or values['Enable']!='0' or values['Access']!='NONE':
                    self.fail('Güvenli başlangıç koşulu sağlanmadı; yazma yapılmadı');return
                if journal.exists():
                    try:existing=json.loads(journal.read_text())
                    except (OSError,ValueError):self.fail('Geri alma kaydı okunamıyor');return
                    if existing.get('status')!='restored':self.fail('Bekleyen geri alma kaydı var');return
                # This is the same journal and recovery path used by the previously
                # verified 1 -> 0 -> 1 probe. Save before sending Download.
                write_json(journal,{'status':'pending','path':PATH+'RebootPersistent',
                                    'original':'1','toggle_verified':False,'source':'sts_download'})
                save(status='download_requested',baseline='1')
                def body(mid):
                    inner=('<cwmp:Download><CommandKey>'+command+'</CommandKey>'
                           '<FileType>3 Vendor Configuration File</FileType><URL>http://'+local_ip+':'+str(port)+endpoint+'</URL>'
                           '<Username></Username><Password></Password><FileSize>'+str(len(SCRIPT))+'</FileSize>'
                           '<TargetFileName></TargetFileName><DelaySeconds>0</DelaySeconds>'
                           '<SuccessURL></SuccessURL><FailureURL></FailureURL></cwmp:Download>')
                    return engine._envelope(st.namespace,inner,mid)
                print('[sts] STS_DOWNLOAD_SENT: tek geçici ayar, önceden geri alma kaydı oluşturuldu',flush=True)
                self._sts_request('sts_download_response',body)
            elif st.stage=='sts_toggle_read':
                if current!='0':self.fail('STS sonrası değer 0 okunamadı; geri alma gerekli');return
                data=json.loads(journal.read_text());data['toggle_verified']=True;write_json(journal,data)
                save(status='restore_requested',toggle='0')
                print('[sts] STS_TOGGLE_VERIFIED: 0 okundu, eski değer 1 geri yükleniyor',flush=True)
                def body(mid):
                    inner=('<cwmp:SetParameterValues><ParameterList soap-enc:arrayType="cwmp:ParameterValueStruct[1]">'
                           '<ParameterValueStruct><Name>'+PATH+'RebootPersistent</Name><Value xsi:type="xsd:boolean">1</Value>'
                           '</ParameterValueStruct></ParameterList><ParameterKey></ParameterKey></cwmp:SetParameterValues>')
                    return engine._envelope(st.namespace,inner,mid)
                self._sts_request('sts_restore_response',body)
            elif st.stage=='sts_restore_read':
                if current!='1':self.fail('Geri yükleme sonrası 1 doğrulanamadı');return
                data=json.loads(journal.read_text());data['status']='restored';write_json(journal,data)
                save(status='verified',restore='1')
                print('[sts] STS_PASS_RESTORED: 1 → 0 → 1 okundu ve geri alındı',flush=True)
                st.stage='sts_done';self._send(204)
            else:self.fail('Beklenmeyen okuma aşaması')

        def _handle_extra_rpc(self,rpc_name,msg_id,root):
            st=self.server.state
            if rpc_name=='DownloadResponse':
                if not self.matches(msg_id):return True
                status=engine._find_text(root,'Status')
                if st.stage!='sts_download_response' or status not in ('0','1'):
                    self.fail('Download yanıtı geçersiz');return True
                if status=='0':
                    if not report['served']:self.fail('Cihaz test dosyasını almadı');return True
                    save(status='transfer_complete',downloadStatus=status,transferFaultCode='0')
                    self.values_request('sts_toggle_read')
                else:
                    save(status='waiting_transfer',downloadStatus=status)
                    st.stage='sts_wait';self._send(204)
                return True
            if rpc_name=='SetParameterValuesResponse':
                if not self.matches(msg_id):return True
                status=engine._find_text(root,'Status')
                if st.stage!='sts_restore_response' or status not in ('0','1'):
                    self.fail('Geri alma yanıtı geçersiz');return True
                self.values_request('sts_restore_read')
                return True
            if rpc_name=='TransferComplete':
                key=engine._find_text(root,'CommandKey');fault=engine._find_text(root,'FaultCode')
                if key==command:
                    if fault=='0' and report['served']:
                        save(status='transfer_complete',transferFaultCode=fault)
                        print('[sts] Download tamamlandı; değer okunacak',flush=True)
                    else:
                        save(status='failed',transferFaultCode=fault,error='Transfer tamamlanmadı')
                        print('[sts] STS_PROBE_FAILED: transfer tamamlanmadı, geri alma gerekli',flush=True)
                self._send(200,engine._envelope(st.namespace,'<cwmp:TransferCompleteResponse/>',msg_id))
                return True
            return False

        def _handle_profile_fault(self,root,received_id):
            if self.matches(received_id):self.fail('SOAP Fault '+str(engine._find_text(root,'FaultCode')))

    engine.ACSHandler=StsHandler
    return server
