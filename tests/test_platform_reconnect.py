"""Real PTY/HDLC boundaries and WSL restart/startup regressions, without a NIC."""
import ast
import os
from pathlib import Path
import pty
import select
import socket
import subprocess
import sys
import threading
import time
import tty
import types
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from windows import check_backend, launcher
from lab import Lab


def transport(name):
    path = ROOT / 'engines' / name
    tree = ast.parse(path.read_text())
    functions = {'fcs16', 'escape', 'unescape', 'hdlc_encode', 'hdlc_decode'}
    nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in functions]
    cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'Bridge')
    cls.body = [node for node in cls.body if isinstance(node, ast.FunctionDef)
                and node.name in ('read_pty', 'stop_pppd', 'monitor_ppp', 'add_acs_alias')]
    ns = dict(os=os, select=select, time=time, threading=threading, subprocess=subprocess,
              PROTO_LCP=0xc021, PROTO_PAP=0xc023, PROTO_CHAP=0xc223,
              PROTO_IPCP=0x8021, PROTO_IP=0x21, PROTO_IPV6CP=0x8057)
    exec(compile(ast.fix_missing_locations(ast.Module(body=nodes + [cls], type_ignores=[])), str(path), 'exec'), ns)
    return ns['Bridge'](), ns


class ReconnectTests(unittest.TestCase):
    def test_real_pty_fragmented_frames_and_reader_exit_between_connections(self):
        for name in ('readonly.py', 'write_probe.py'):
            with self.subTest(engine=name):
                bridge, ns = transport(name)
                bridge.stop = threading.Event()
                bridge.session = 0x1234
                bridge.pppd_buf = b''
                bridge.log_ppp = Mock()
                for attempt in range(2):
                    master, slave = pty.openpty()
                    tty.setraw(slave)
                    bridge.pty_master = master
                    bridge.pppd = Mock()
                    bridge.pppd.poll.return_value = None
                    sent = threading.Event()
                    bridge.send_pppoe = Mock(side_effect=lambda *a, **k: sent.set())
                    reader = threading.Thread(target=bridge.read_pty, daemon=True)
                    reader.start()
                    try:
                        frame = ns['hdlc_encode'](b'\xc0\x21\x01\x02\x00\x04')
                        os.write(slave, frame[:4])
                        os.write(slave, frame[4:])
                        self.assertTrue(sent.wait(2), 'PTY data was not decoded')
                        bridge.send_pppoe.assert_called_once_with(0, 0x1234, proto=0xc021,
                                                                 payload=b'\x01\x02\x00\x04')
                        # PADT detaches the child without stopping the whole lab.
                        bridge.pppd = bridge.pty_master = None
                        os.close(slave)
                        slave = None
                        reader.join(timeout=1)
                        self.assertFalse(reader.is_alive(), 'Old reader survived a reconnect')
                        self.assertFalse(bridge.stop.is_set())
                    finally:
                        bridge.stop.set()
                        reader.join(timeout=1)
                        os.close(master)
                        if slave is not None:
                            os.close(slave)
                        bridge.stop.clear()

    def test_alias_is_readded_when_named_interface_reappears_without_a_poll_gap(self):
        for name in ('readonly.py', 'write_probe.py'):
            with self.subTest(engine=name):
                bridge, ns = transport(name)
                bridge.args = types.SimpleNamespace(local_ip='10.116.13.100',
                    peer_ip='10.116.13.101', acs_ip='193.192.97.234')
                bridge.ppp_name = 'acs0123456789'
                first, second = object(), object()
                bridge.pppd = first
                bridge.stop = Mock()
                bridge.stop.is_set.side_effect = [False, False, True]
                bridge.stop.wait.side_effect = lambda timeout: setattr(bridge, 'pppd', second)
                ns['find_ppp_interface'] = Mock(return_value=bridge.ppp_name)
                ns['add_acs_alias'] = Mock(return_value=True)
                ns['threading'] = Mock()
                bridge.tap_loop = Mock()
                bridge.monitor_ppp()
                self.assertEqual(ns['add_acs_alias'].call_count, 2)
                self.assertIs(bridge.acs_alias_process, second)

    def test_force_killed_pppd_is_waited_and_only_owned_descriptors_are_closed(self):
        for name in ('readonly.py', 'write_probe.py'):
            with self.subTest(engine=name):
                bridge, ns = transport(name)
                child = Mock()
                child.wait.side_effect = [subprocess.TimeoutExpired('pppd', 2), 0]
                bridge.pppd, bridge.pty_master = child, 123
                bridge.pty_thread = bridge.pppd_thread = None
                bridge.rx_pending = [(0xc021, b'old')]
                with patch.object(os, 'close') as close:
                    bridge.stop_pppd()
                    close.assert_called_once_with(123)
                child.kill.assert_called_once()
                self.assertEqual(child.wait.call_count, 2)
                child.stdout.close.assert_called_once()
                self.assertIsNone(bridge.pppd)
                self.assertIsNone(bridge.pty_master)
                self.assertEqual(bridge.rx_pending, [])


class PortRestartTests(unittest.TestCase):
    def check_ports(self, port):
        real_socket = socket.socket
        class MappedSocket:
            def __init__(self, *args):
                self.raw = real_socket(*args)
            def __getattr__(self, name):
                return getattr(self.raw, name)
            def bind(self, address):
                # Exercise the actual preflight using unprivileged ports.
                self.raw.bind(('127.0.0.1', port if address[1] == 80 else 0))
        with patch('lab.socket.socket', MappedSocket), \
                patch('lab.service_addresses', return_value=['127.0.0.1']), \
                patch('lab.service_address', return_value='127.0.0.1'), \
                patch('lab.prepare_socket'):
            Lab.free_ports()

    def test_closed_http_connection_does_not_block_the_next_test(self):
        with socket.socket() as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(('127.0.0.1', 0))
            port = server.getsockname()[1]
            server.listen()
            with socket.create_connection(('127.0.0.1', port)) as client:
                accepted, _ = server.accept()
                # Server closes first, so its local port enters TIME_WAIT.
                accepted.close()
                self.assertEqual(client.recv(1), b'')
        self.check_ports(port)

    def test_another_live_server_still_blocks_startup(self):
        with socket.socket() as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(('127.0.0.1', 0))
            server.listen()
            with self.assertRaises(ValueError):
                self.check_ports(server.getsockname()[1])


class WSLStartupTests(unittest.TestCase):
    def test_run_refreshes_code_and_loads_drivers_before_checking_backend(self):
        events = []
        with patch.object(launcher.sys, 'platform', 'win32'), \
                patch.object(launcher.sys, 'argv', ['launcher.py']), \
                patch.object(launcher.ctypes, 'windll', types.SimpleNamespace(
                    shell32=types.SimpleNamespace(IsUserAnAdmin=lambda: True)), create=True), \
                patch.object(launcher, 'distribution', return_value='Ubuntu'), \
                patch.object(launcher, 'sync_backend', side_effect=lambda d: events.append('sync')), \
                patch.object(launcher, 'check', side_effect=lambda d, **kw:
                    (events.append(('check', kw)), (['fixture'], []))[1]), \
                patch.object(launcher.socket, 'socket'), \
                patch.object(launcher.subprocess, 'Popen') as child, \
                patch.object(launcher, 'WindowsRelay') as relay:
            relay.return_value.run.side_effect = lambda: events.append('run')
            launcher.main()
        self.assertEqual(events, ['sync', ('check', {'prepare': True}), 'run'])
        self.assertIn('/var/lib/acs-lab-studio/windows/wsl_relay.py', child.call_args.args[0])

    def test_run_preflight_passes_prepare_flag_but_check_only_does_not(self):
        with patch.object(launcher.importlib.util, 'find_spec', return_value=object()), \
                patch.object(launcher.Path, 'is_file', return_value=True), \
                patch.object(launcher, 'adapters', return_value=[dict(name='Ethernet', description='USB', active=True)]), \
                patch.object(launcher.subprocess, 'run', return_value=Mock(returncode=0)) as run:
            launcher.check('Ubuntu', prepare=True)
            self.assertEqual(run.call_args.args[0][-1], '--prepare')
            launcher.check('Ubuntu')
            self.assertNotIn('--prepare', run.call_args.args[0])

    def test_wsl_restart_loads_only_tun_and_ppp_without_installing_packages(self):
        with patch.object(check_backend.platform, 'system', return_value='Linux'), \
                patch.object(check_backend.platform, 'release', return_value='6.6-microsoft-standard-WSL2'), \
                patch.object(check_backend.os, 'geteuid', return_value=0), \
                patch.object(check_backend.subprocess, 'run', return_value=Mock(returncode=0)) as run:
            check_backend.prepare()
        self.assertEqual([call.args[0] for call in run.call_args_list],
                         [['modprobe', 'tun'], ['modprobe', 'ppp_async']])

    def test_driver_failure_stops_startup_and_plain_check_remains_read_only(self):
        with patch.object(check_backend.platform, 'system', return_value='Linux'), \
                patch.object(check_backend.platform, 'release', return_value='6.6-microsoft-standard-WSL2'), \
                patch.object(check_backend.os, 'geteuid', return_value=0), \
                patch.object(check_backend.subprocess, 'run', return_value=Mock(returncode=1)):
            with self.assertRaisesRegex(RuntimeError, 'tun'):
                check_backend.prepare()
        with patch.object(check_backend, 'prepare') as prepare, \
                patch.object(check_backend, 'issues', return_value=[]):
            self.assertEqual(check_backend.main([]), 0)
            prepare.assert_not_called()


if __name__ == '__main__':
    unittest.main()
