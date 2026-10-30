import ast
import contextlib
import html
import io
import json
import sys
import tempfile
import types
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
BASE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(BASE))
from configure import install
from lab import validate_settings


class ConfigureTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.run=Path(self.temp.name)
        self.traces=[]
        namespace={'html':html}
        tree=ast.parse((BASE/'engines'/'write_probe.py').read_text())
        for n in tree.body:
            if isinstance(n,ast.FunctionDef) and n.name in {'_envelope','_get_parameter_names','_get_parameter_values','_local_name','_find_text'}:
                exec(compile(ast.Module(body=[n],type_ignores=[]),'<helpers>','exec'),namespace)
        engine=types.SimpleNamespace(**{k:v for k,v in namespace.items() if k.startswith('_')})
        engine._trace_cwmp=lambda *args:self.traces.append(args)
        class Handler:
            def _send(self,code,body=b''):
                self.sent.append((code,body))
                engine._trace_cwmp('OUT','test','response',body)
        engine.ACSHandler=Handler
        self.engine=engine

    def tearDown(self):self.temp.cleanup()

    def handler(self,**settings):
        profile={'target':1,'ssh_action':'enable','persistence':'keep','cli_password':'',**settings}
        self.target=profile['target']
        install(self.engine,profile,self.run)
        h=self.engine.ACSHandler();h.sent=[]
        counter=iter(range(100))
        h.server=types.SimpleNamespace(state=types.SimpleNamespace(namespace='urn:dslforum-org:cwmp-1-2',pending_id='initial',next_id=lambda:'id'+str(next(counter))))
        return h

    def baseline(self,h,username='engineer'):
        base=f'Device.Services.X_000E50_AccessManagement.SSH.CliUsers.{self.target}.'
        methods=ET.fromstring('<r><string>GetParameterNames</string><string>GetParameterValues</string><string>SetParameterValues</string></r>')
        h._handle_rpc_methods_response(methods,'initial')
        root=ET.Element('r')
        for name in ['Enable','Access','RebootPersistent','Password']:
            x=ET.SubElement(root,'ParameterInfoStruct');ET.SubElement(x,'Name').text=base+name;ET.SubElement(x,'Writable').text='1'
        h._handle_get_names_response(root,h.server.state.pending_id)
        h._handle_get_values_response(self.values(Username=username,Enable='0',Access='NONE',RebootPersistent='1'),h.server.state.pending_id)

    def values(self,**values):
        root=ET.Element('r')
        for name,value in values.items():
            node=ET.SubElement(root,'ParameterValueStruct')
            ET.SubElement(node,'Name').text=f'Device.Services.X_000E50_AccessManagement.SSH.CliUsers.{self.target}.'+name
            ET.SubElement(node,'Value').text=value
        return root

    def finish(self,h,**values):
        h._handle_set_response(ET.fromstring('<r><Status>1</Status></r>'),h.server.state.pending_id)
        h._handle_get_values_response(self.values(Username='engineer',Enable='1',Access='LAN',RebootPersistent='1',**values),h.server.state.pending_id)

    def test_selected_ssh_write_and_readback(self):
        h=self.handler()
        with contextlib.redirect_stdout(io.StringIO()):self.baseline(h);self.finish(h)
        bodies=[body for _,body in h.sent if b'<cwmp:SetParameterValues>' in body]
        self.assertEqual(len(bodies),1)
        names=[n.text for n in ET.fromstring(bodies[0]).iter() if n.tag=='Name']
        self.assertEqual([x.rsplit('.',1)[-1] for x in names],['Access','Enable'])
        self.assertEqual(json.loads((self.run/'configuration-state.json').read_text())['status'],'verified')

    def test_account_mismatch_refuses_write(self):
        h=self.handler()
        with contextlib.redirect_stdout(io.StringIO()):self.baseline(h,username='root')
        self.assertFalse(any(b'<cwmp:SetParameterValues>' in body for _,body in h.sent))

    def test_superuser_target_is_independent(self):
        h=self.handler(target=2)
        with contextlib.redirect_stdout(io.StringIO()):
            self.baseline(h,username='superuser')
            h._handle_set_response(ET.fromstring('<r><Status>0</Status></r>'),h.server.state.pending_id)
            h._handle_get_values_response(self.values(Username='superuser',Enable='1',Access='LAN',RebootPersistent='1'),h.server.state.pending_id)
        body=next(body for _,body in h.sent if b'<cwmp:SetParameterValues>' in body)
        self.assertIn(b'CliUsers.2.',body)
        self.assertNotIn(b'CliUsers.1.',body)
        self.assertEqual(json.loads((self.run/'configuration-state.json').read_text())['username'],'superuser')

    def test_password_is_not_in_journal_or_trace(self):
        secret='Local-safe-pass_123'
        h=self.handler(cli_password=secret)
        with contextlib.redirect_stdout(io.StringIO()):self.baseline(h);self.finish(h)
        journal=(self.run/'configuration-state.json').read_text()
        self.assertNotIn(secret,journal)
        self.assertEqual(json.loads(journal)['status'],'password_acknowledged')
        self.assertFalse(any(secret.encode() in args[3] for args in self.traces))
        self.assertTrue(any(secret.encode() in body for _,body in h.sent))
        self.assertFalse(any(b'<string>' in body and b'.Password</string>' in body for _,body in h.sent))

    def test_readback_mismatch_is_not_success(self):
        h=self.handler()
        with contextlib.redirect_stdout(io.StringIO()):
            self.baseline(h)
            h._handle_set_response(ET.fromstring('<r><Status>0</Status></r>'),h.server.state.pending_id)
            h._handle_get_values_response(self.values(Username='engineer',Enable='0',Access='NONE',RebootPersistent='1'),h.server.state.pending_id)
        self.assertEqual(json.loads((self.run/'configuration-state.json').read_text())['status'],'unverified')

    def test_configuration_validation(self):
        base={'mode':'configure','iface':'en11','mac':'60:d8:a4:97:16:d9'}
        with self.assertRaises(ValueError):validate_settings(base)
        for password in ["x'; id; #abcde",'short','has newline\n123']:
            with self.assertRaises(ValueError):validate_settings({**base,'cli_password':password})
        settings=validate_settings({**base,'ssh_action':'enable','management_ip':'192.168.50.1','local_ip':'10.20.0.1','peer_ip':'10.20.0.2'})
        self.assertEqual(settings['management_ip'],'192.168.50.1')
        with self.assertRaises(ValueError):validate_settings({**base,'ssh_action':'enable','local_ip':'10.20.0.1','peer_ip':'10.20.0.1'})

    def web_names(self,h,writable=True):
        methods=ET.fromstring('<r><string>GetParameterNames</string><string>GetParameterValues</string><string>SetParameterValues</string></r>')
        h._handle_rpc_methods_response(methods,'initial')
        root=ET.Element('r')
        for index in (2,7):
            for field in ('Username','X_000E50_Role'):
                node=ET.SubElement(root,'ParameterInfoStruct')
                ET.SubElement(node,'Name').text=f'Device.Users.User.{index}.'+field
                ET.SubElement(node,'Writable').text='1' if writable and field!='Username' else '0'
        h._handle_get_names_response(root,h.server.state.pending_id)

    def web_values(self,role='admin',second='guest',admin='admin'):
        root=ET.Element('r')
        for index,username,value in ((2,second,'guest'),(7,admin,role)):
            for field,text in (('Username',username),('X_000E50_Role',value)):
                node=ET.SubElement(root,'ParameterValueStruct')
                ET.SubElement(node,'Name').text=f'Device.Users.User.{index}.'+field
                ET.SubElement(node,'Value').text=text
        return root

    def web_baseline(self,h,**values):
        self.web_names(h)
        h._handle_get_values_response(self.web_values(**values),h.server.state.pending_id)

    def web_finish(self,h,role='engineer',cli=False):
        h._handle_set_response(ET.fromstring('<r><Status>0</Status></r>'),h.server.state.pending_id)
        response=self.web_values(role=role)
        if cli:
            for child in self.values(Username='engineer',Enable='1',Access='LAN',RebootPersistent='1'):response.append(child)
        h._handle_get_values_response(response,h.server.state.pending_id)

    def test_admin_role_only_finds_username_without_assuming_index(self):
        h=self.handler(web_admin_role='engineer',ssh_action='keep')
        with contextlib.redirect_stdout(io.StringIO()):
            self.web_baseline(h)
            self.web_finish(h)
        writes=[body for _,body in h.sent if b'<cwmp:SetParameterValues>' in body]
        self.assertEqual(len(writes),1)
        names=[n.text for n in ET.fromstring(writes[0]).iter() if n.tag=='Name']
        self.assertEqual(names,['Device.Users.User.7.X_000E50_Role'])
        self.assertIn(b'>engineer</Value>',writes[0])
        self.assertNotIn(b'Password',writes[0])
        state=json.loads((self.run/'configuration-state.json').read_text())
        self.assertEqual(state['status'],'verified')
        self.assertEqual(state['webAdmin']['originalRole'],'admin')
        self.assertEqual(state['webAdmin']['verifiedRole'],'engineer')
        self.assertIsNone(state['username'])

    def test_web_admin_can_return_to_admin_role(self):
        h=self.handler(web_admin_role='admin',ssh_action='keep')
        with contextlib.redirect_stdout(io.StringIO()):
            self.web_baseline(h,role='engineer')
            self.web_finish(h,role='admin')
        writes=[body for _,body in h.sent if b'<cwmp:SetParameterValues>' in body]
        self.assertEqual(len(writes),1)
        self.assertIn(b'>admin</Value>',writes[0])
        state=json.loads((self.run/'configuration-state.json').read_text())
        self.assertEqual(state['webAdmin']['verifiedRole'],'admin')
        self.assertEqual(state['status'],'verified')

    def test_combined_role_and_ssh_preflight_before_single_write(self):
        h=self.handler(web_admin_role='engineer')
        with contextlib.redirect_stdout(io.StringIO()):
            self.web_baseline(h)
            self.assertFalse(any(b'<cwmp:SetParameterValues>' in body for _,body in h.sent))
            root=ET.Element('r')
            for field in ('Enable','Access'):
                node=ET.SubElement(root,'ParameterInfoStruct')
                ET.SubElement(node,'Name').text='Device.Services.X_000E50_AccessManagement.SSH.CliUsers.1.'+field
                ET.SubElement(node,'Writable').text='1'
            h._handle_get_names_response(root,h.server.state.pending_id)
            h._handle_get_values_response(self.values(Username='engineer',Enable='0',Access='NONE',RebootPersistent='1'),h.server.state.pending_id)
            self.web_finish(h,cli=True)
        writes=[body for _,body in h.sent if b'<cwmp:SetParameterValues>' in body]
        self.assertEqual(len(writes),1)
        self.assertIn(b'Device.Users.User.7.X_000E50_Role',writes[0])
        self.assertIn(b'CliUsers.1.Enable',writes[0])
        self.assertEqual(json.loads((self.run/'configuration-state.json').read_text())['status'],'verified')

    def test_missing_admin_refuses_all_writes(self):
        h=self.handler(web_admin_role='engineer')
        with contextlib.redirect_stdout(io.StringIO()):self.web_baseline(h,admin='operator')
        self.assertFalse(any(b'<cwmp:SetParameterValues>' in body for _,body in h.sent))

    def test_duplicate_admin_refuses_all_writes(self):
        h=self.handler(web_admin_role='engineer')
        with contextlib.redirect_stdout(io.StringIO()):self.web_baseline(h,second='admin')
        self.assertFalse(any(b'<cwmp:SetParameterValues>' in body for _,body in h.sent))

    def test_readonly_role_refuses_all_writes(self):
        h=self.handler(web_admin_role='engineer')
        with contextlib.redirect_stdout(io.StringIO()):
            self.web_names(h,writable=False)
            h._handle_get_values_response(self.web_values(),h.server.state.pending_id)
        self.assertFalse(any(b'<cwmp:SetParameterValues>' in body for _,body in h.sent))

    def test_role_readback_must_match(self):
        h=self.handler(web_admin_role='engineer',ssh_action='keep')
        with contextlib.redirect_stdout(io.StringIO()):
            self.web_baseline(h)
            self.web_finish(h,role='admin')
        state=json.loads((self.run/'configuration-state.json').read_text())
        self.assertEqual(state['status'],'unverified')
        self.assertNotIn('verifiedRole',state['webAdmin'])

    def test_wrong_response_id_prevents_role_write(self):
        h=self.handler(web_admin_role='engineer',ssh_action='keep')
        with contextlib.redirect_stdout(io.StringIO()):
            self.web_names(h)
            h._handle_get_values_response(self.web_values(),'wrong-id')
        self.assertFalse(any(b'<cwmp:SetParameterValues>' in body for _,body in h.sent))

    def test_role_request_validation(self):
        data={'mode':'configure','iface':'en11','mac':'60:d8:a4:97:16:d9'}
        result=validate_settings({**data,'web_admin_role':'engineer'})
        self.assertEqual(result['web_admin_role'],'engineer')
        self.assertEqual(result['ssh_action'],'keep')
        for role in ('root','superuser','engineer;id'):
            with self.assertRaises(ValueError):validate_settings({**data,'web_admin_role':role})


if __name__=='__main__':unittest.main()
