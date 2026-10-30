"""One-device ACS STS root-password update; the secret stays in memory only."""
import json
import re
import secrets
import threading
from http.server import BaseHTTPRequestHandler
from host_network import LabHTTPServer as ThreadingHTTPServer, service_address


ROOT_SHELL_SETUP = r'''if sed -i 's#^\(root:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:\).*#\1/bin/ash#' /etc/passwd &&
grep -q '^root:.*:/bin/ash$' /etc/passwd; then
    logger -t ACS_ROOT_SHELL_TEST ROOT_SHELL_READY
else
    logger -t ACS_ROOT_SHELL_TEST ROOT_SHELL_FAILED
    exit 1
fi
'''


def root_shell_service():
    # The STS service-name grammar forbids slash characters. Decode this fixed,
    # readable script only after parsing; no password or user input is encoded.
    encoded = ''.join('\\%03o' % byte for byte in ROOT_SHELL_SETUP.encode('ascii'))
    return "/etc/init.d/x;printf${IFS}'" + encoded + "'|sh"


def validate_sts_layout(payload):
    actions = {'enable', 'restart'}
    for line in payload.decode('ascii').splitlines():
        if line == 'reboot off':
            continue
        if re.fullmatch(r'set dropbear\.lan\.(?:Interface=lan|enable=1|RootLogin=1|RootPasswordAuth=1|PasswordAuth=1)', line):
            continue
        parts = line.split()
        if (not parts or not re.fullmatch(r'/etc/init.d/[^/*]+', parts[0]) or
                len(parts) > 2 or (len(parts) == 2 and parts[1] not in actions)):
            raise ValueError('Hazırlanan dosya cihazın STS komut biçimine uymuyor.')
    return payload


def build_payload(settings):
    password = settings.get('root_password', '')
    if not isinstance(password, str) or not re.fullmatch(r'[A-Za-z0-9_.@+\-]{12,64}', password):
        raise ValueError('Root parola biçimi geçersiz.')
    enable_ssh = settings.get('root_enable_lan_ssh', False)
    if type(enable_ssh) is not bool:
        raise ValueError('LAN SSH seçimi geçersiz.')
    # STS service-name matching forbids any slash after /etc/init.d/.
    # Keep the proven password operation on one service line; express LAN
    # configuration and service actions with the firmware's native STS syntax.
    body = 'echo${IFS}root:' + password + '|chpasswd'
    body += '&&logger${IFS}-t${IFS}ACS_ROOT_PASS_TEST${IFS}CHPASS_OK'
    body += '||logger${IFS}-t${IFS}ACS_ROOT_PASS_TEST${IFS}CHPASS_FAIL'
    lines = ['reboot off']
    if enable_ssh:
        lines += [
            'set dropbear.lan.Interface=lan',
            'set dropbear.lan.enable=1',
            'set dropbear.lan.RootLogin=1',
            'set dropbear.lan.RootPasswordAuth=1',
            'set dropbear.lan.PasswordAuth=1',
        ]
    lines.append('/etc/init.d/x;' + body)
    if enable_ssh:
        # Stock root uses restricted_shell, which can authenticate successfully
        # and then refuse a shell. Opening root SSH must also permit its shell.
        lines.append(root_shell_service())
        lines += ['/etc/init.d/dropbear enable', '/etc/init.d/dropbear restart']
    return validate_sts_layout(('\n'.join(lines) + '\n').encode('ascii'))


def install(engine, settings, run, peer_ip, local_ip, port=8778):
    payload = build_payload(settings)
    enable_ssh = settings.get('root_enable_lan_ssh', False)
    settings['root_password'] = ''
    token = secrets.token_urlsafe(24)
    route = '/root-password/' + token
    command = 'root-password-' + secrets.token_hex(6)
    report = {'status': 'waiting', 'served': False, 'commandKey': command, 'lanSshRequested': enable_ssh}

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
            self.send_response(200)
            self.send_header('Content-Length', str(len(payload)))
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(payload)
            save(served=True, servedBytes=len(payload))
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
                         transferFaultCode=fault,
                         error='' if transferred else 'Cihaz aktarımı veya config uygulamasını reddetti (kod '+str(fault)+').')
                    if transferred:
                        print('[root-password] ROOT_PASSWORD_TRANSFER_REPORTED: SSH ile doğrulama gerekli', flush=True)
                    else:
                        print('[root-password] ROOT_PASSWORD_TRANSFER_FAILED: kod=' + str(fault), flush=True)
                self._send(200, engine._envelope(state.namespace,
                                                 '<cwmp:TransferCompleteResponse/>', message_id))
                return True
            return False

        def _handle_profile_fault(self, root, received_id):
            self.fail('SOAP Fault ' + str(engine._find_text(root, 'FaultCode')))

    engine.ACSHandler = Handler
    return server
