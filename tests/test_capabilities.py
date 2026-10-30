import json
import tempfile
import types
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
import test_configure
from capabilities import install


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.fixture=test_configure.ConfigureTests()
        self.fixture.setUp()
        self.engine=self.fixture.engine
        self.run=self.fixture.run
        install(self.engine,self.run)
        self.h=self.engine.ACSHandler()
        self.h.sent=[]
        count=iter(range(100))
        self.h.server=types.SimpleNamespace(state=types.SimpleNamespace(namespace='urn:dslforum-org:cwmp-1-2',pending_id='initial',next_id=lambda:'id'+str(next(count))))

    def tearDown(self):self.fixture.tearDown()

    def start(self):
        root=ET.fromstring('<r><string>GetParameterNames</string><string>GetParameterValues</string><string>Download</string><string>Upload</string></r>')
        self.h._handle_rpc_methods_response(root,'initial')

    def report(self):return json.loads((self.run/'capabilities.json').read_text())

    def test_methods_fault_continuation_and_no_writes(self):
        self.start()
        self.assertIn('Download',self.report()['methods'])
        self.h._handle_profile_fault(ET.fromstring('<r><FaultCode>9005</FaultCode></r>'),self.h.server.state.pending_id)
        for _ in range(4):self.h._handle_get_names_response(ET.fromstring('<r/>'),self.h.server.state.pending_id)
        self.assertEqual(self.report()['status'],'complete')
        self.assertEqual(self.report()['groups']['web_users']['fault_code'],'9005')
        for _,body in self.h.sent:
            self.assertNotIn(b'<cwmp:SetParameterValues>',body)
            self.assertNotIn(b'<cwmp:Download>',body)
            self.assertNotIn(b'<cwmp:Upload>',body)

    def test_only_allowed_metadata_read_and_no_password(self):
        self.start()
        root=ET.Element('r')
        for field in ('Username','X_000E50_Role','Password','srp_verifier'):
            node=ET.SubElement(root,'ParameterInfoStruct')
            ET.SubElement(node,'Name').text='Device.Users.User.7.'+field
            ET.SubElement(node,'Writable').text='1'
        self.h._handle_get_names_response(root,self.h.server.state.pending_id)
        body=self.h.sent[-1][1]
        self.assertIn(b'Device.Users.User.7.Username',body)
        self.assertNotIn(b'Password',body)
        self.assertNotIn(b'srp_verifier',body)
        values=ET.Element('r')
        for name,value in (('Username','admin'),('X_000E50_Role','engineer')):
            node=ET.SubElement(values,'ParameterValueStruct')
            ET.SubElement(node,'Name').text='Device.Users.User.7.'+name
            ET.SubElement(node,'Value').text=value
        self.h._handle_get_values_response(values,self.h.server.state.pending_id)
        self.assertEqual(self.report()['groups']['web_users']['status'],'read')
        self.assertEqual(self.report()['groups']['web_users']['parameters']['Device.Users.User.7.X_000E50_Role']['value'],'engineer')

    def test_wrong_id_stops_queries(self):
        self.start()
        self.h._handle_get_names_response(ET.fromstring('<r/>'),'wrong')
        self.assertEqual(self.report()['status'],'failed')
        self.assertEqual(self.h.sent[-1][0],204)

    def test_dropbear_reads_auth_flags_without_password_or_key_material(self):
        self.start()
        for _ in range(4):
            self.h._handle_get_names_response(ET.fromstring('<r/>'), self.h.server.state.pending_id)
        prefix='uci.dropbear.dropbear.@lan.'
        allowed=('enable','Interface','Port','RootLogin','RootPasswordAuth','PasswordAuth')
        root=ET.Element('r')
        for field in (*allowed,'Password','PrivateKey','HostKey'):
            node=ET.SubElement(root,'ParameterInfoStruct')
            ET.SubElement(node,'Name').text=prefix+field
            ET.SubElement(node,'Writable').text='1'
        self.h._handle_get_names_response(root,self.h.server.state.pending_id)
        body=ET.fromstring(self.h.sent[-1][1])
        requested=[node.text for node in body.iter() if node.tag=='string']
        self.assertEqual(set(requested),{prefix+field for field in allowed})
        values=ET.Element('r')
        for field,value in [('enable','1'),('Interface','lan'),('Port','22'),
                            ('RootLogin','1'),('RootPasswordAuth','on'),('PasswordAuth','on')]:
            node=ET.SubElement(values,'ParameterValueStruct')
            ET.SubElement(node,'Name').text=prefix+field
            ET.SubElement(node,'Value').text=value
        self.h._handle_get_values_response(values,self.h.server.state.pending_id)
        report=self.report()
        self.assertEqual(report['status'],'complete')
        self.assertEqual(report['groups']['dropbear_lan']['parameters'][prefix+'RootPasswordAuth']['value'],'on')
        self.assertFalse(any(b'<cwmp:SetParameterValues>' in payload for _,payload in self.h.sent))
