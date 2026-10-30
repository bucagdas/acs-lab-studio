import unittest

class EngineTests(unittest.TestCase):
    def test_bounded_write_protocol_and_recovery(self):
        import ast,html,json,os,tempfile,types,xml.etree.ElementTree as ET
        from pathlib import Path
        p=Path(__file__).resolve().parents[1]/'engines'/'write_probe.py';t=ast.parse(p.read_text())
        ns=dict(html=html,json=json,os=os,__file__=str(p.resolve()))
        names={'_envelope','_get_parameter_values','_set_probe_value','_local_name','_find_text','_read_probe_journal','_save_probe_journal'}
        for n in t.body:
         if isinstance(n,ast.Assign) and any(isinstance(v,ast.Name) and v.id in ['PROBE_BASE','PROBE_PATH','PROBE_JOURNAL'] for v in n.targets):exec(compile(ast.Module(body=[n],type_ignores=[]),'<test>','exec'),ns)
         if isinstance(n,ast.FunctionDef) and n.name in names:exec(compile(ast.Module(body=[n],type_ignores=[]),'<test>','exec'),ns)
        c=next(n for n in t.body if isinstance(n,ast.ClassDef) and n.name=='ACSHandler')
        methods=[n for n in c.body if isinstance(n,ast.FunctionDef) and n.name in ['_probe_send','_handle_get_values_response','_handle_set_response']]
        fake=ast.ClassDef(name='Probe',bases=[],keywords=[],body=methods,decorator_list=[])
        exec(compile(ast.fix_missing_locations(ast.Module(body=[fake],type_ignores=[])),'<test>','exec'),ns)
        base=ns['PROBE_BASE']
        def response(data):
         return ET.fromstring('<r>'+''.join('<ParameterValueStruct><Name>'+base+k+'</Name><Value>'+v+'</Value></ParameterValueStruct>' for k,v in data.items())+'</r>')
        def instance():
         o=ns['Probe'](); counter=iter(range(1,30)); st=types.SimpleNamespace(stage='await_get_values_response',pending_id='initial',namespace='urn:dslforum-org:cwmp-1-2',next_id=lambda:'t'+str(next(counter)))
         o.server=types.SimpleNamespace(state=st);o.sent=[];o._send=lambda code,body=b'':o.sent.append((code,body));return o,st
        with tempfile.TemporaryDirectory() as d:
         ns['PROBE_JOURNAL']=d+'/journal.json'
         o,st=instance();o._handle_get_values_response(response({'Username':'engineer','Enable':'0','Access':'NONE','RebootPersistent':'1'}),'initial')
         assert st.stage=='probe_toggle'
         o._handle_set_response(ET.fromstring('<r><Status>0</Status></r>'),st.pending_id)
         o._handle_get_values_response(response({'RebootPersistent':'0'}),st.pending_id)
         assert st.stage=='probe_restore'
         o._handle_set_response(ET.fromstring('<r><Status>0</Status></r>'),st.pending_id)
         o._handle_get_values_response(response({'RebootPersistent':'1'}),st.pending_id)
         assert ns['_read_probe_journal']()=={'status':'restored','path':ns['PROBE_PATH'],'original':'1','toggle_verified':True}
         writes=[]
         for code,body in o.sent:
          if not body:continue
          root=ET.fromstring(body)
          if any(n.tag.endswith('SetParameterValues') for n in root.iter()):
           writes.append([(n.tag,n.text) for n in root.iter() if n.tag in ('Name','Value')])
         assert writes==[[('Name',ns['PROBE_PATH']),('Value','0')],[('Name',ns['PROBE_PATH']),('Value','1')]]
         os.unlink(ns['PROBE_JOURNAL']);o,st=instance();o._handle_get_values_response(response({'Username':'engineer','Enable':'1','Access':'LAN','RebootPersistent':'1'}),'initial');assert o.sent==[(204,b'')]
         ns['_save_probe_journal']({'status':'pending','original':'1'});o,st=instance();o._handle_get_values_response(response({'RebootPersistent':'0'}),'initial');assert st.stage=='probe_restore'
        print('PASS: exact 1->0->1 write/readback; no password or access writes; unsafe baseline refused; interrupted attempt restores first.')
