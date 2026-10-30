import json
import unittest
import types
from unittest.mock import patch
from pathlib import Path
import xml.etree.ElementTree as ET
import test_configure
from upload_probe import install
from lab import validate_settings


class UploadProbeTests(unittest.TestCase):
    def setUp(self):
        self.fixture=test_configure.ConfigureTests();self.fixture.setUp()
        self.run=self.fixture.run;self.engine=self.fixture.engine
        self.server=types.SimpleNamespace(daemon_threads=False,serve_forever=lambda:None)
        with patch('upload_probe.ThreadingHTTPServer',return_value=self.server) as factory:
            install(self.engine,self.run,'10.116.13.101','10.116.13.100')
            self.receiver_class=factory.call_args[0][1]
        self.h=self.engine.ACSHandler();self.h.sent=[]
        self.h.request=object()  # BaseHTTPRequestHandler owns this socket attribute.
        count=iter(range(30))
        self.h.server=types.SimpleNamespace(state=types.SimpleNamespace(namespace='urn:dslforum-org:cwmp-1-2',pending_id='initial',next_id=lambda:'id'+str(next(count))))

    def tearDown(self):self.fixture.tearDown()

    def start(self,name='logread'):
        self.h._handle_rpc_methods_response(ET.fromstring('<r><string>Upload</string><string>GetParameterValues</string></r>'),'initial')
        root=ET.fromstring('<r><ParameterValueStruct><Name>Device.DeviceInfo.VendorLogFile.1.Name</Name><Value>'+name+'</Value></ParameterValueStruct></r>')
        self.h._handle_get_values_response(root,self.h.server.state.pending_id)

    def report(self):return json.loads((self.run/'upload-probe.json').read_text())

    def test_only_standard_log_is_requested_and_not_repeated(self):
        self.start()
        body=self.h.sent[-1][1]
        self.assertIn(b'<FileType>4 Vendor Log File 1</FileType>',body)
        self.assertIn(b'http://10.116.13.100:8778/vendor-log/',body)
        self.assertNotIn(b'SetParameterValues',body)
        self.h._handle_rpc_methods_response(ET.fromstring('<r/>'),self.h.server.state.pending_id)
        self.assertEqual(sum(b'<cwmp:Upload>' in body for _,body in self.h.sent),1)

    def test_other_log_path_refuses_upload(self):
        self.start(name='/proc/rip/0108')
        self.assertEqual(self.report()['status'],'failed')
        self.assertFalse(any(b'<cwmp:Upload>' in body for _,body in self.h.sent))

    def test_response_does_not_claim_receipt(self):
        self.start()
        self.h._handle_extra_rpc('UploadResponse',self.h.server.state.pending_id,ET.fromstring('<r><Status>1</Status></r>'))
        self.assertNotEqual(self.report()['status'],'verified')
        key=self.report()['commandKey']
        self.h._handle_extra_rpc('TransferComplete','tc',ET.fromstring('<r><CommandKey>'+key+'</CommandKey><FaultCode>0</FaultCode></r>'))
        self.assertNotEqual(self.report()['status'],'verified')

    def test_wrong_id_stops_request(self):
        self.h._handle_rpc_methods_response(ET.fromstring('<r/>'),'wrong')
        self.assertEqual(self.report()['status'],'failed')

    def test_receiver_rejects_other_peer_without_reading_body(self):
        h=self.receiver_class.__new__(self.receiver_class)
        h.client_address=('192.168.1.99',1);h.path='/anything'
        result=[];h.respond=lambda status:result.append(status)
        h.do_PUT()
        self.assertEqual(result,[403])

    def test_receipt_and_device_completion_are_both_required(self):
        import io,hashlib
        from unittest.mock import Mock
        from urllib.parse import urlsplit
        self.start()
        body=ET.fromstring(self.h.sent[-1][1])
        url=next(n.text for n in body.iter() if n.tag=='URL')
        self.h._handle_extra_rpc('UploadResponse',self.h.server.state.pending_id,ET.fromstring('<r><Status>0</Status></r>'))
        receiver=self.receiver_class.__new__(self.receiver_class)
        data=b'harmless test log line\n'
        receiver.client_address=('10.116.13.101',1234);receiver.path=urlsplit(url).path
        receiver.connection=Mock();receiver.headers={'Content-Length':str(len(data))}
        receiver.rfile=io.BytesIO(data);responses=[];receiver.respond=responses.append
        receiver.do_PUT()
        self.assertEqual(responses,[201])
        self.assertEqual(self.report()['status'],'verified')
        self.assertEqual(self.report()['sha256'],hashlib.sha256(data).hexdigest())
        self.assertEqual((self.run/'vendor-log.bin').read_bytes(),data)

    def test_oversized_upload_is_not_saved(self):
        from unittest.mock import Mock
        from urllib.parse import urlsplit
        self.start()
        body=ET.fromstring(self.h.sent[-1][1]);url=next(n.text for n in body.iter() if n.tag=='URL')
        receiver=self.receiver_class.__new__(self.receiver_class)
        receiver.client_address=('10.116.13.101',1);receiver.path=urlsplit(url).path
        receiver.connection=Mock();receiver.headers={'Content-Length':str(3*1024*1024)}
        responses=[];receiver.respond=responses.append;receiver.do_PUT()
        self.assertEqual(responses,[400])
        self.assertFalse((self.run/'vendor-log.bin').exists())

    def test_probe_mode_validation(self):
        result=validate_settings({'mode':'log_upload','iface':'en11','mac':'60:d8:a4:97:16:d9','vlan':35,'duration':600})
        self.assertEqual(result['mode'],'log_upload')
