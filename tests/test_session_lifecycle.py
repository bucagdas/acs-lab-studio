import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lab import Lab
from network_recovery import PapLease, recover
from session_runtime import close_servers, install_completion


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        (self.base / '.state').mkdir()
        self.run = self.base / '.runs/test'
        self.run.mkdir(parents=True)
        self.target = self.base / 'host/pap-secrets'
        self.target.parent.mkdir()
        self.lease = PapLease(self.base, self.run, self.target)

    def tearDown(self):
        self.lease.release()
        self.tmp.cleanup()

    def test_restores_existing_bytes_and_mode(self):
        self.target.write_bytes(b'original private bytes\n')
        self.target.chmod(0o640)
        self.lease.prepare(b'temporary\n')
        self.assertEqual(self.target.read_bytes(), b'temporary\n')
        self.lease.restore()
        self.assertEqual(self.target.read_bytes(), b'original private bytes\n')
        self.assertEqual(self.target.stat().st_mode & 0o777, 0o640)
        self.assertFalse(self.lease.record.exists())

    def test_removes_file_only_when_it_was_created_by_the_session(self):
        self.lease.prepare(b'temporary\n')
        self.lease.restore()
        self.assertFalse(self.target.exists())

    def test_external_modification_preserves_both_file_and_recovery(self):
        self.lease.prepare(b'temporary\n')
        self.target.write_bytes(b'changed by another app')
        with self.assertRaises(ValueError): self.lease.restore()
        self.assertEqual(self.target.read_bytes(), b'changed by another app')
        self.assertTrue(self.lease.record.exists())

    def test_stale_journal_after_bytes_restored_is_idempotent(self):
        self.target.write_bytes(b'original')
        self.lease.prepare(b'temporary\n')
        self.target.write_bytes(b'original')
        self.lease.restore()
        self.assertFalse(self.lease.record.exists())

    def test_live_worker_in_another_copy_blocks_recovery(self):
        self.lease.prepare(b'temporary\n')
        with self.assertRaises(ValueError): recover(self.base, self.target)
        self.assertEqual(self.target.read_bytes(), b'temporary\n')

    def test_symlink_is_never_overwritten(self):
        other = self.base / 'other'
        other.write_bytes(b'private')
        self.target.symlink_to(other)
        with self.assertRaises(ValueError): self.lease.prepare(b'temporary\n')
        self.assertEqual(other.read_bytes(), b'private')

    def test_panel_recovery_is_offline_and_rejects_an_active_session(self):
        self.lease.prepare(b'temporary\n')
        self.lease.release()
        lab = Lab(self.base)
        with patch('network_recovery.PAP_PATH', self.target), patch('lab.os.geteuid', return_value=0), patch('lab.recover', lambda base: recover(base, self.target)):
            self.assertTrue(lab.snapshot()['networkRecovery'])
            lab.recover_network()
            self.assertFalse(lab.snapshot()['networkRecovery'])
            lab.process = types.SimpleNamespace(poll=lambda: None)
            with self.assertRaises(ValueError): lab.recover_network()


class CompletionTests(unittest.TestCase):
    def test_stops_only_after_final_response_has_been_sent(self):
        with tempfile.TemporaryDirectory() as folder:
            run = Path(folder); stop = threading.Event(); sent = []
            class Handler:
                def _send(self, code): sent.append((code, stop.is_set()))
            engine = types.SimpleNamespace(ACSHandler=Handler)
            install_completion(engine, 'readonly', run, run, stop)
            handler = Handler()
            handler._send(200)
            self.assertFalse(stop.is_set())
            (run / 'capabilities.json').write_text('{"status":"complete"}')
            handler._send(204)
            self.assertEqual(sent[-1], (204, False))
            self.assertTrue(stop.is_set())

    def test_failed_listener_cleanup_is_bounded(self):
        class Bad:
            def shutdown(self): raise RuntimeError('listener failure')
        self.assertTrue(close_servers([Bad()]))

    def test_no_completion_while_write_restore_is_pending(self):
        with tempfile.TemporaryDirectory() as folder:
            run = Path(folder); stop = threading.Event()
            class Handler:
                server = types.SimpleNamespace(state=types.SimpleNamespace(stage='probe_restore'))
                def _send(self, code): pass
            engine = types.SimpleNamespace(ACSHandler=Handler)
            install_completion(engine, 'write', run, run, stop)
            journal = run / 'write_probe_state.json'
            journal.write_text('{"status":"pending"}')
            h = Handler(); h._send(200)
            self.assertFalse(stop.is_set())
            journal.write_text('{"status":"restored"}')
            h._send(204)
            self.assertTrue(stop.is_set())


class SequentialWorkerTests(unittest.TestCase):
    def test_read_log_write_close_and_restart_without_refresh_under_constant_traffic(self):
        """Real worker child/pipes/controller; fake NIC only, real PAP backup/restore in temp."""
        source = Path(__file__).resolve().parents[1]
        fixture = r'''
import sys, types, threading, json, time
from pathlib import Path
sys.path.insert(0, SOURCE)
import runner
from network_recovery import PapLease
from session_runtime import capture_session
runner.BASE = Path(__file__).parent
runner.os.geteuid = lambda: 0
runner.PapLease = lambda base, run, target: PapLease(base, run, base/'host/pap-secrets')
class Handler:
    server = types.SimpleNamespace(state=types.SimpleNamespace(stage='probe_done'))
    def _send(self, code): pass
class Receiver:
    class RequestHandlerClass:
        def respond(self, code): pass
    def shutdown(self): pass
    def server_close(self): pass
sys.modules['upload_probe'] = types.SimpleNamespace(install=lambda *a: Receiver())
class FakeSniffer:
    def __init__(self, **kwargs): self.running=False; self.callback=kwargs['prn']; self.ready=kwargs['started_callback']
    def start(self):
        self.running=True; self.ready()
        def traffic():
            while self.running:
                self.callback(None);time.sleep(.001)
        self.thread=threading.Thread(target=traffic,daemon=True);self.thread.start()
    def stop(self, join=False): self.running=False
    def join(self, timeout=None): self.thread.join(timeout)
class Bridge:
    def __init__(self,args): self.args=args;self.stop=threading.Event();self.iface=args.iface
    def stop_pppd(self): pass
    def on_packet(self,p): pass
    def run(self):
        engine.ensure_pap_secrets()
        if (runner.BASE/'.cleanup-failure').exists():
            class BadServer:
                def shutdown(self): raise RuntimeError('test cleanup error')
            self.owned_servers.append(BadServer())
        def respond():
            time.sleep(.05)
            if (runner.BASE/'.hold').exists(): return
            run=self.args.run_dir
            if self.args.mode=='readonly':
                (run/'capabilities.json').write_text('{"status":"complete"}')
                print('[acs] read-only diagnostic complete',flush=True)
            elif self.args.mode=='log_upload':
                (run/'upload-probe.json').write_text('{"status":"verified"}')
                print('[lab] LOG_UPLOAD_VERIFIED',flush=True)
            else:
                (runner.BASE/'.state/write_probe_state.json').write_text('{"status":"restored","toggle_verified":true}')
                print('[write-test] WRITE_TEST_PASS_RESTORED',flush=True)
            engine.ACSHandler()._send(204)
        threading.Thread(target=respond,daemon=True).start()
        capture_session(self,FakeSniffer)
engine=types.SimpleNamespace(ACSHandler=Handler,Bridge=Bridge,threading=threading)
runner.importlib.util.spec_from_file_location=lambda *a: types.SimpleNamespace(loader=types.SimpleNamespace(exec_module=lambda m: m.__dict__.update(engine.__dict__)))
runner.importlib.util.module_from_spec=lambda spec: engine
runner.main()
'''.replace('SOURCE', repr(str(source)))
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            (base / 'runner.py').write_text(fixture)
            (base / 'host').mkdir(); target = base / 'host/pap-secrets'
            target.write_bytes(b'original\n')
            lab = Lab(base)
            with patch.object(lab, 'readiness', return_value=[]), patch.object(lab, 'free_ports'), patch('lab.interfaces', return_value=[{'id':'en11'}]):
                for mode in ['readonly', 'log_upload', 'write', 'readonly']:
                    lab.start({'mode':mode,'iface':'en11','mac':'02:00:00:00:00:02'})
                    deadline = time.monotonic()+5
                    while lab.snapshot()['running'] and time.monotonic()<deadline: time.sleep(.01)
                    self.assertFalse(lab.snapshot()['running'], lab.export().decode())
                    self.assertEqual(lab.outcome,'success',lab.export().decode())
                    self.assertEqual(target.read_bytes(),b'original\n')
                    self.assertFalse((base/'.state/pap-recovery.json').exists())
                    self.assertFalse(lab.snapshot()['finishing'])
                    self.assertFalse(lab.snapshot()['networkRecovery'])
                    lab.process.stdout.close()
                (base/'.cleanup-failure').touch()
                lab.start({'mode':'readonly','iface':'en11','mac':'02:00:00:00:00:02'})
                deadline=time.monotonic()+5
                while lab.snapshot()['running'] and time.monotonic()<deadline: time.sleep(.01)
                self.assertEqual(lab.outcome,'failed')
                self.assertEqual(target.read_bytes(),b'original\n')
                self.assertFalse((base/'.state/pap-recovery.json').exists())
                lab.process.stdout.close()
                (base/'.cleanup-failure').unlink()
                (base/'.hold').touch()
                lab.start({'mode':'readonly','iface':'en11','mac':'02:00:00:00:00:02'})
                deadline=time.monotonic()+3
                while not (base/'.state/pap-recovery.json').exists() and time.monotonic()<deadline: time.sleep(.01)
                self.assertTrue((base/'.state/pap-recovery.json').exists())
                lab.stop()
                deadline=time.monotonic()+5
                while lab.snapshot()['running'] and time.monotonic()<deadline: time.sleep(.01)
                self.assertEqual(lab.outcome,'stopped',lab.export().decode())
                self.assertEqual(target.read_bytes(),b'original\n')
                self.assertFalse((base/'.state/pap-recovery.json').exists())
                lab.process.stdout.close()

                    


class ListenerTests(unittest.TestCase):
    def test_tls_handshake_does_not_block_the_accept_loop(self):
        from unittest.mock import Mock
        from host_network import LabHTTPServer
        server = object.__new__(LabHTTPServer)
        server.allowed_peer = '10.116.13.101'
        server.tls_context = Mock()
        connection = Mock()
        with patch('host_network.ThreadingHTTPServer.get_request', return_value=(connection, ('10.116.13.101',1234))):
            server.get_request()
        server.tls_context.wrap_socket.assert_called_once_with(connection, server_side=True, do_handshake_on_connect=False)
        connection.settimeout.assert_called_once_with(15)

    def test_unrelated_client_is_closed_before_tls_or_http(self):
        from unittest.mock import Mock
        from host_network import LabHTTPServer
        server = object.__new__(LabHTTPServer)
        server.allowed_peer = '10.116.13.101'
        server.tls_context = Mock()
        connection = Mock()
        with patch('host_network.ThreadingHTTPServer.get_request', return_value=(connection, ('192.168.1.20',1234))):
            with self.assertRaises(OSError): server.get_request()
        connection.close.assert_called_once()
        server.tls_context.wrap_socket.assert_not_called()


class EveryModeTests(unittest.TestCase):
    def test_each_mode_stops_on_its_own_evidence_without_waiting_for_timeout(self):
        scenarios=[
            ('readonly','capabilities.json',{'status':'running'},{'status':'complete'}),
            ('log_upload','upload-probe.json',{'status':'requested'},{'status':'verified'}),
            ('configure','configuration-state.json',{'status':'acknowledged'},{'status':'verified'}),
            ('configure','configuration-state.json',{'status':'acknowledged'},{'status':'password_acknowledged'}),
            ('sts_probe','sts-probe.json',{'status':'restore_requested'},{'status':'verified'}),
            ('root_password','root-password-transfer.json',{'status':'waiting_transfer','served':True},{'status':'transfer_reported','served':True}),
            ('write','write_probe_state.json',{'status':'pending'},{'status':'restored','toggle_verified':True}),
        ]
        for mode,name,pending,done in scenarios:
            with self.subTest(mode=mode,result=done),tempfile.TemporaryDirectory() as folder:
                run=Path(folder);stop=threading.Event();responses=[]
                class Handler:
                    server=types.SimpleNamespace(state=types.SimpleNamespace(stage='testing'))
                    def _send(self,code):responses.append((code,stop.is_set()))
                engine=types.SimpleNamespace(ACSHandler=Handler)
                install_completion(engine,mode,run,run,stop)
                h=Handler();report=run/name
                report.write_text(json.dumps(pending));h._send(200)
                self.assertFalse(stop.is_set())
                report.write_text(json.dumps(done));h._send(204)
                self.assertEqual(responses[-1],(204,False))
                self.assertTrue(stop.is_set())

    def test_root_download_status_zero_finishes_without_an_extra_transfer_rpc(self):
        import ast
        import xml.etree.ElementTree as ET
        source=Path(__file__).resolve().parents[1]/'root_password.py'
        tree=ast.parse(source.read_text())
        method=next(n for n in ast.walk(tree) if isinstance(n,ast.FunctionDef) and n.name=='_handle_extra_rpc')
        results=[];report={'served':True}
        ns={'report':report,'save':lambda **kw:results.append(kw),'engine':types.SimpleNamespace(_find_text=lambda root,name:root.findtext(name))}
        cls=ast.ClassDef(name='Handler',bases=[],keywords=[],body=[method],decorator_list=[])
        exec(compile(ast.fix_missing_locations(ast.Module(body=[cls],type_ignores=[])),str(source),'exec'),ns)
        h=ns['Handler']();h.server=types.SimpleNamespace(state=types.SimpleNamespace(stage='root_password_response',pending_id='match'))
        sent=[];h._send=lambda status:sent.append(status)
        h.fail=lambda message:self.fail(message)
        self.assertTrue(h._handle_extra_rpc('DownloadResponse','match',ET.fromstring('<r><Status>0</Status></r>')))
        self.assertEqual(results[-1],{'status':'transfer_reported','downloadStatus':'0'})
        self.assertEqual(sent,[204])
