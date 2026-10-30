"""One standard VendorLogFile.1 Upload to a peer-restricted local receiver."""
import hashlib
import json
import os
import secrets
import threading
from http.server import BaseHTTPRequestHandler
from host_network import LabHTTPServer as ThreadingHTTPServer, service_address

MAX_LOG = 2 * 1024 * 1024


def install(engine, run, peer_ip, local_ip, port=8778):
    token = secrets.token_urlsafe(24)
    endpoint = '/vendor-log/' + token
    command = 'acs-lab-log-' + secrets.token_hex(6)
    url = f'http://{local_ip}:{port}' + endpoint
    report = {'status': 'waiting', 'commandKey': command, 'fileType': '4 Vendor Log File 1',
              'namePath': 'Device.DeviceInfo.VendorLogFile.1.Name', 'requestedName': 'logread'}
    lock = threading.RLock()
    receiver_ready = False

    def save(**changes):
        with lock:
            report.update(changes)
            received = report.get('received', False)
            complete = report.get('rpcStatus') == '0' or report.get('transferFaultCode') == '0'
            newly_verified = received and complete and report.get('status') not in ('failed','verified')
            if newly_verified:
                report['status'] = 'verified'
            tmp = run / 'upload-probe.tmp'
            tmp.write_text(json.dumps(report, ensure_ascii=False, indent=2))
            tmp.replace(run / 'upload-probe.json')
            if newly_verified:
                print('[lab] LOG_UPLOAD_VERIFIED: local file receipt and device completion confirmed', flush=True)
    save()

    class Receiver(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def log_message(self, *args):
            pass

        def respond(self, status):
            self.send_response(status)
            self.send_header('Content-Length', '0')
            self.end_headers()

        def do_PUT(self):
            if self.client_address[0] != peer_ip or self.path != endpoint:
                self.respond(403)
                return
            try:
                transfer = self.headers.get('Transfer-Encoding', '').lower()
                data = bytearray()
                self.connection.settimeout(15)
                if transfer == 'chunked':
                    while True:
                        line = self.rfile.readline(128)
                        if not line.endswith(b'\r\n'):
                            raise ValueError('invalid chunk header')
                        count = int(line.strip().split(b';', 1)[0], 16)
                        if count == 0:
                            if self.rfile.readline(8192) != b'\r\n':
                                raise ValueError('trailers unsupported')
                            break
                        if count < 0 or len(data) + count > MAX_LOG:
                            raise ValueError('size limit')
                        chunk = self.rfile.read(count)
                        if len(chunk) != count or self.rfile.read(2) != b'\r\n':
                            raise ValueError('truncated chunk')
                        data.extend(chunk)
                elif transfer:
                    raise ValueError('unsupported transfer encoding')
                else:
                    count = int(self.headers.get('Content-Length', '-1'))
                    if not 0 < count <= MAX_LOG:
                        raise ValueError('size limit')
                    data.extend(self.rfile.read(count))
                    if len(data) != count:
                        raise ValueError('truncated body')
                if not data:
                    raise ValueError('empty log')
                digest = hashlib.sha256(data).hexdigest()
                with lock:
                    if report.get('received'):
                        self.respond(409)
                        return
                    fd = os.open(run / 'vendor-log.bin', os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                    with os.fdopen(fd, 'wb') as f:
                        f.write(data)
                    save(received=True, bytes=len(data), sha256=digest)
                print('[lab] Vendor log received locally: bytes=%d sha256=%s' % (len(data), digest), flush=True)
                self.respond(201)
            except (ValueError, OSError):
                save(receiverError='Invalid, oversized or interrupted upload')
                self.close_connection = True
                self.respond(400)

    receiver = ThreadingHTTPServer((service_address(local_ip), port), Receiver)
    receiver.daemon_threads = True
    receiver_ready = True
    threading.Thread(target=receiver.serve_forever, daemon=True).start()

    class UploadHandler(engine.ACSHandler):
        def fail(self, message):
            save(status='failed', error=message)
            self.server.state.stage = 'upload_failed'
            print('[lab] LOG_UPLOAD_FAILED: ' + message, flush=True)
            self._send(204)

        def _probe_request(self, stage, build):
            st = self.server.state
            mid = st.next_id()
            st.pending_id = mid
            st.stage = stage
            self._send(200, build(mid))

        def matches(self, received_id):
            if received_id == self.server.state.pending_id:
                return True
            self.fail('RPC response ID mismatch')
            return False

        def _handle_rpc_methods_response(self, root, received_id):
            if not self.matches(received_id):
                return
            if report.get('sent'):
                self.server.state.stage = 'upload_pending'
                self._send(204)
                return
            methods = [node.text or '' for node in root.iter() if engine._local_name(node.tag) == 'string']
            if 'Upload' not in methods or 'GetParameterValues' not in methods or not receiver_ready:
                self.fail('Required Upload/GetParameterValues or local receiver unavailable')
                return
            self._probe_request('upload_name_check', lambda mid: engine._get_parameter_values(self.server.state.namespace, mid, [report['namePath']]))

        def _handle_get_values_response(self, root, received_id):
            if not self.matches(received_id):
                return
            if self.server.state.stage != 'upload_name_check':
                self.fail('Unexpected value response')
                return
            names = []
            for node in root.iter():
                if engine._local_name(node.tag) == 'ParameterValueStruct':
                    name = next((c.text or '' for c in node if engine._local_name(c.tag) == 'Name'), '')
                    value = next((c.text or '' for c in node if engine._local_name(c.tag) == 'Value'), '')
                    if name == report['namePath']:
                        names.append(value)
            if names != ['logread']:
                self.fail('VendorLogFile.1 is not the expected logread record')
                return
            save(status='requested', sent=True)
            def body(mid):
                inner = ('<cwmp:Upload><CommandKey>' + command + '</CommandKey>'
                         '<FileType>4 Vendor Log File 1</FileType><URL>' + url + '</URL>'
                         '<Username></Username><Password></Password><DelaySeconds>0</DelaySeconds></cwmp:Upload>')
                return engine._envelope(self.server.state.namespace, inner, mid)
            print('[lab] Requesting only standard VendorLogFile.1 logread; no configuration write', flush=True)
            self._probe_request('upload_response', body)

        def _handle_extra_rpc(self, rpc_name, msg_id, root):
            st = self.server.state
            if rpc_name == 'UploadResponse':
                if not self.matches(msg_id):
                    return True
                status = engine._find_text(root, 'Status')
                if st.stage != 'upload_response' or status not in ('0', '1'):
                    self.fail('Invalid UploadResponse')
                    return True
                save(rpcStatus=status)
                st.stage = 'upload_pending'
                print('[lab] UploadResponse Status=' + status, flush=True)
                self._send(204)
                return True
            if rpc_name == 'TransferComplete':
                received_key = engine._find_text(root, 'CommandKey')
                fault = engine._find_text(root, 'FaultCode')
                if received_key == command:
                    if fault == '0':
                        save(transferFaultCode=fault)
                    else:
                        save(transferFaultCode=fault,status='failed',error='TransferComplete reported a fault')
                        print('[lab] LOG_UPLOAD_FAILED: TransferComplete fault '+str(fault),flush=True)
                    print('[lab] TransferComplete for requested log: FaultCode=' + str(fault), flush=True)
                self._send(200, engine._envelope(st.namespace, '<cwmp:TransferCompleteResponse/>', msg_id))
                return True
            return False

        def _handle_profile_fault(self, root, received_id):
            if self.matches(received_id):
                self.fail('SOAP Fault ' + str(engine._find_text(root, 'FaultCode')))

    engine.ACSHandler = UploadHandler
    return receiver
