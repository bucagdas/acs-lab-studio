import json
import types
import unittest
import xml.etree.ElementTree as ET
from unittest.mock import patch
import test_configure
from sts_probe import install, PATH

class STSTests(unittest.TestCase):
    def setUp(self):
        self.fixture=test_configure.ConfigureTests(); self.fixture.setUp()
        self.engine=self.fixture.engine; self.run=self.fixture.run
        self.server=types.SimpleNamespace(daemon_threads=False,serve_forever=lambda:None)
        with patch('sts_probe.ThreadingHTTPServer',return_value=self.server) as factory:
            install(self.engine,self.run,self.run,'10.116.13.101','10.116.13.100')
            self.receiver=factory.call_args[0][1]
        self.h=self.engine.ACSHandler(); self.h.sent=[]; self.h.request=object()
        ids=iter(range(100))
        self.st=types.SimpleNamespace(namespace='urn:dslforum-org:cwmp-1-2',pending_id='start',next_id=lambda:'id'+str(next(ids)))
        self.h.server=types.SimpleNamespace(state=self.st)
    def tearDown(self): self.fixture.tearDown()
    def values(self,value='1',enable='0'):
        fields={'Username':'engineer','Enable':enable,'Access':'NONE','RebootPersistent':value}
        return ET.fromstring('<r>'+''.join('<ParameterValueStruct><Name>'+PATH+k+'</Name><Value>'+v+'</Value></ParameterValueStruct>' for k,v in fields.items())+'</r>')
    def start(self,enable='0'):
        self.h._handle_rpc_methods_response(ET.fromstring('<r><string>Download</string><string>GetParameterValues</string><string>SetParameterValues</string></r>'),'start')
        self.h._handle_get_values_response(self.values(enable=enable),self.st.pending_id)
    def journal(self): return json.loads((self.run/'write_probe_state.json').read_text())
    def test_unsafe_baseline_never_writes(self):
        self.start(enable='1')
        self.assertFalse((self.run/'write_probe_state.json').exists())
        self.assertFalse(any(b'<cwmp:Download>' in body for _,body in self.h.sent))
    def test_download_and_restoration(self):
        self.start(); self.assertEqual(self.journal()['status'],'pending')
        self.assertIn(b'3 Vendor Configuration File',self.h.sent[-1][1])
        self.h._handle_extra_rpc('DownloadResponse',self.st.pending_id,ET.fromstring('<r><Status>1</Status></r>'))
        import io
        from urllib.parse import urlsplit
        body=ET.fromstring(next(b for _,b in self.h.sent if b'<cwmp:Download>' in b))
        url=next(n.text for n in body.iter() if n.tag=='URL')
        receiver=self.receiver.__new__(self.receiver)
        receiver.client_address=('10.116.13.101',1234);receiver.path=urlsplit(url).path
        receiver.send_response=lambda code:None;receiver.send_header=lambda *args:None;receiver.end_headers=lambda:None
        receiver.wfile=io.BytesIO();receiver.do_GET()
        key=json.loads((self.run/'sts-probe.json').read_text())['commandKey']
        self.h._handle_extra_rpc('TransferComplete','tc-id',ET.fromstring('<r><CommandKey>'+key+'</CommandKey><FaultCode>0</FaultCode></r>'))
        ack=ET.fromstring(self.h.sent[-1][1]);self.assertTrue(any(n.text=='tc-id' for n in ack.iter()))
        self.assertTrue(any(n.tag.endswith('TransferCompleteResponse') for n in ack.iter()))
        self.st.pending_id='next'
        self.h._handle_rpc_methods_response(ET.fromstring('<r><string>Download</string><string>GetParameterValues</string><string>SetParameterValues</string></r>'),'next')
        self.h._handle_get_values_response(self.values(value='0'),self.st.pending_id)
        self.assertTrue(self.journal()['toggle_verified'])
        self.h._handle_extra_rpc('SetParameterValuesResponse',self.st.pending_id,ET.fromstring('<r><Status>0</Status></r>'))
        self.h._handle_get_values_response(self.values(value='1'),self.st.pending_id)
        self.assertEqual(self.journal()['status'],'restored')
        self.assertEqual(json.loads((self.run/'sts-probe.json').read_text())['status'],'verified')
    def test_wrong_response_id_keeps_journal_pending(self):
        self.start(); self.h._handle_extra_rpc('DownloadResponse','wrong',ET.fromstring('<r><Status>0</Status></r>'))
        self.assertEqual(self.journal()['status'],'pending')
        self.assertEqual(json.loads((self.run/'sts-probe.json').read_text())['status'],'failed')
