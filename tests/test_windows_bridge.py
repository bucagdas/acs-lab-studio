import io
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import threading
import types
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import host_network
import windows_bridge
from windows.capture import Capture, parse_adapters
from windows.launcher import decode_output, wsl_command, WindowsRelay
from windows.protocol import (Channel, FRAME, HELLO, ERROR, SELECT, ACK, HEADER,
                              MAX_RECORD, frame_record, unpack_frame, pppoe_frame)
from windows.stage_backend import stage
from windows.wsl_relay import Relay


GUID = '00112233-4455-6677-8899-aabbccddeeff'
MAC = '02:00:00:00:00:01'


def padi(source='60d8a49716d9'):
    return bytes.fromhex('ffffffffffff' + source + '810000238863110900000000')


class PartialReader(io.BytesIO):
    def read(self, count=-1):
        return super().read(min(count, 2))


class PartialWriter(io.BytesIO):
    def write(self, data):
        return super().write(data[:3])


class WindowsProtocolTests(unittest.TestCase):
    def test_partial_pipe_io_preserves_binary_packets_and_record_boundaries(self):
        writer = PartialWriter()
        channel = Channel(None, writer)
        channel.json(HELLO, {'name': 'USB Ethernet'})
        channel.send(FRAME, frame_record(0, padi()))
        receiver = Channel(PartialReader(writer.getvalue()), None)
        kind, payload = receiver.receive()
        self.assertEqual(kind, HELLO)
        self.assertEqual(json.loads(payload)['name'], 'USB Ethernet')
        kind, payload = receiver.receive()
        self.assertEqual((kind, unpack_frame(payload)), (FRAME, (0, padi())))
        with self.assertRaises(EOFError):
            receiver.receive()

    def test_malformed_magic_size_and_truncation_are_rejected(self):
        for raw in (HEADER.pack(b'NOPE', FRAME, 0), HEADER.pack(b'ACSB', 99, 0),
                    HEADER.pack(b'ACSB', FRAME, MAX_RECORD + 1)):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                Channel(io.BytesIO(raw), None).receive()
        with self.assertRaises(EOFError):
            Channel(io.BytesIO(HEADER.pack(b'ACSB', FRAME, 10) + b'abc'), None).receive()

    def test_only_complete_pppoe_frames_cross_the_pipe(self):
        self.assertTrue(pppoe_frame(padi()))
        self.assertTrue(pppoe_frame(padi()[:12] + padi()[16:]))  # no VLAN
        self.assertFalse(pppoe_frame(padi()[:16] + b'\x08\x00' + b'x' * 28))
        self.assertFalse(pppoe_frame(padi()[:-1]))
        self.assertFalse(pppoe_frame(padi()[:-2] + b'\xff\xff'))
        self.assertFalse(pppoe_frame(padi() + b'x' * 10000))
        with self.assertRaises(ValueError):
            frame_record(64, padi())
        with self.assertRaises(ValueError):
            unpack_frame(b'\0')


class WindowsHostTests(unittest.TestCase):
    def test_real_child_pipes_roundtrip_selection_and_frames_without_network_access(self):
        backend = r'''
import json,sys
sys.path.insert(0,sys.argv[1])
from windows.protocol import *
channel=Channel(sys.stdin.buffer,sys.stdout.buffer)
kind,payload=channel.receive()
assert kind==HELLO and len(json.loads(payload)['adapters'])==1
channel.json(SELECT,{'request':'select','index':0})
kind,payload=channel.receive()
assert kind==ACK and json.loads(payload)['ok']
raw=bytes.fromhex('ffffffffffff020000000001810000238863110900000000')
channel.send(FRAME,frame_record(0,raw))
channel.json(SELECT,{'request':'release','index':None})
kind,payload=channel.receive()
assert kind==ACK and json.loads(payload)['ok']
channel.json(ERROR,{'error':'synthetic-end'})
'''
        process = subprocess.Popen([sys.executable, '-u', '-c', backend, str(Path(__file__).resolve().parents[1])],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
        relay = WindowsRelay(process, [dict(guid=GUID, mac=MAC)], 8890)
        relay.capture = Mock()
        try:
            with self.assertRaisesRegex(RuntimeError, 'synthetic-end'):
                relay.run()
            self.assertEqual([call.args[0] for call in relay.capture.select.call_args_list], [0, None])
            self.assertEqual(relay.capture.send.call_args.args[0], 0)
            relay.capture.close.assert_called_once()
            self.assertEqual(process.returncode, 0, process.stderr.read().decode())
        finally:
            if process.poll() is None:
                process.kill(); process.wait()
            process.stdout.close(); process.stderr.close()

    def test_usb_and_builtin_cards_share_the_same_inventory_path(self):
        cards = parse_adapters(json.dumps([
            dict(InterfaceGuid=GUID, MacAddress=MAC.replace(':', '-'), Status='Up',
                 Name='Ethernet USB', InterfaceDescription='USB-C Ethernet'),
            dict(InterfaceGuid='10112233-4455-6677-8899-aabbccddeeff', MacAddress='02-00-00-00-00-02',
                 Status='Disconnected', Name='Ethernet', InterfaceDescription='Built-in Ethernet'),
        ]))
        self.assertEqual(len(cards), 2)
        self.assertTrue(cards[0]['active'])
        self.assertFalse(cards[1]['active'])
        self.assertEqual(cards[0]['mac'], MAC)

    def test_invalid_or_duplicate_mac_inventory_does_not_become_a_card(self):
        item = dict(InterfaceGuid=GUID, MacAddress='00-00-00-00-00-00', Status='Up')
        self.assertEqual(parse_adapters(json.dumps(item)), [])
        item['MacAddress'] = MAC
        self.assertEqual(len(parse_adapters(json.dumps([item, item]))), 1)

    def test_windows_utf16_distro_output_and_arguments_remain_literal(self):
        self.assertEqual(decode_output('Ubuntu\r\nDebian\r\n'.encode('utf-16')), 'Ubuntu\r\nDebian')
        self.assertEqual(decode_output('Ubuntu\n'.encode('utf-16-le')), 'Ubuntu')
        self.assertEqual(decode_output('Ubuntu\n'.encode()), 'Ubuntu')
        command = wsl_command('Ubuntu 24.04', 'sh', '/mnt/c/ACS Lab/setup.sh', '/mnt/c/a;echo bad')
        self.assertEqual(command[-1], '/mnt/c/a;echo bad')
        self.assertEqual(command[2], 'Ubuntu 24.04')

    def test_capture_is_lazy_and_transmission_requires_selected_physical_source(self):
        channel = Mock()
        capture = Capture([dict(guid=GUID, mac=MAC)], channel)
        self.assertIsNone(capture.capture)
        capture.send(0, padi())
        module = types.ModuleType('scapy.all')
        module.conf = Mock(); module.Ether = Mock(side_effect=lambda raw: raw)
        with patch.dict(sys.modules, {'scapy': types.ModuleType('scapy'), 'scapy.all': module}), \
                patch('windows.capture.threading.Thread'):
            capture.select(0)
            module.conf.L2listen.assert_called_once()
            self.assertIn('NPF_{' + GUID.upper() + '}', module.conf.L2listen.call_args.kwargs['iface'])
            capture.send(0, padi())  # router source may not be injected as host
            module.conf.L2socket.return_value.send.assert_not_called()
            outbound = padi(MAC.replace(':', ''))
            capture.send(0, outbound)
            module.conf.L2socket.return_value.send.assert_called_once_with(outbound)
            capture.close()
        self.assertIsNone(capture.index)

    def test_capture_forwards_only_pppoe_and_suppresses_own_transmissions(self):
        channel, stop = Mock(), threading.Event()
        capture = Capture([dict(guid=GUID, mac=MAC)], channel)
        def sniff(**options):
            for raw in (padi(), padi(MAC.replace(':', '')), b'ordinary ip traffic'):
                options['prn'](raw)
            stop.set()
        module = types.ModuleType('scapy.all'); module.sniff = sniff
        with patch.dict(sys.modules, {'scapy': types.ModuleType('scapy'), 'scapy.all': module}):
            capture._receive(0, Mock(), stop)
        channel.send.assert_called_once_with(FRAME, frame_record(0, padi()))


class LinuxRelayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.cards = [dict(guid=GUID, mac=MAC, name='Ethernet USB', description='USB Ethernet', active=False)]
        self.relay = Relay(Mock(), self.cards, self.temp.name)
        self.relay.items = [{'id': 'aw1234560', 'name': 'Ethernet USB', 'guid': GUID, 'mac': MAC, 'active': False}]
        self.relay.save()

    def tearDown(self):
        self.temp.cleanup()

    def test_wsl_inventory_exposes_windows_physical_cards_not_the_nat_adapter(self):
        with patch.dict(os.environ, {'ACS_WINDOWS_BRIDGE_STATE': str(self.relay.state)}), \
                patch('host_network.platform.system', return_value='Linux'), \
                patch('host_network._ip_json') as query:
            self.assertEqual(host_network.interfaces()[0]['displayName'], 'Ethernet USB')
            self.assertEqual(host_network.host_info()['name'], 'Windows / WSL 2')
            query.assert_not_called()
            with patch('windows_bridge.refresh'):
                self.assertFalse(host_network.interface_details('aw1234560')['active'])
            query.assert_not_called()

    def test_missing_bridge_inventory_never_falls_back_to_wsl_virtual_ethernet(self):
        with patch.dict(os.environ, {'ACS_WINDOWS_BRIDGE_STATE': str(Path(self.temp.name) / 'missing')}), \
                patch('host_network.platform.system', return_value='Linux'), \
                patch('host_network._ip_json') as query:
            self.assertEqual(host_network.interfaces(), [])
            query.assert_not_called()

    def test_control_lease_stops_selected_capture_before_releasing_lock(self):
        handler = self.relay.control_handler().__new__(self.relay.control_handler())
        handler.rfile = io.BytesIO(b'{"op":"select","iface":"aw1234560"}\n')
        handler.wfile = io.BytesIO()
        handler.connection = Mock(); handler.connection.recv.return_value = b'R'
        self.relay.request = Mock(return_value={'ok': True})
        handler.handle()
        self.assertEqual(self.relay.request.call_args_list[0].kwargs, {'index': 0})
        self.assertEqual(self.relay.request.call_args_list[-1].kwargs, {'index': None})
        self.assertIsNone(self.relay.active)
        self.assertFalse(self.relay.selection.locked())
        self.assertEqual(len(handler.wfile.getvalue().splitlines()), 2)

    def test_pipe_frames_inject_only_into_the_currently_selected_tap(self):
        buffer = io.BytesIO(); sender = Channel(None, buffer)
        sender.send(FRAME, frame_record(0, padi()))
        sender.send(FRAME, frame_record(1, padi()))
        self.relay.channel = Channel(io.BytesIO(buffer.getvalue()), io.BytesIO())
        self.relay.taps = [101, 102]; self.relay.active = 1
        with patch('windows.wsl_relay.os.write') as write:
            self.relay.read_windows()
            write.assert_called_once_with(102, padi())

    def test_stop_refuses_inflight_write_but_does_not_report_success(self):
        self.relay.lab = Mock(); self.relay.lab.stop.side_effect = ValueError('write pending')
        self.relay.stop_gracefully({'request': 'r'})
        self.assertFalse(self.relay.stop.is_set())
        self.assertFalse(self.relay.channel.json.call_args.args[1]['ok'])

    def test_staging_preserves_private_runs_and_recovery_journals(self):
        source, target = Path(self.temp.name) / 'source', Path(self.temp.name) / 'target'
        for folder in ('engines', 'static', 'windows', '.runs', '.state'):
            (source / folder).mkdir(parents=True)
        (source / 'app.py').write_text('new version')
        (source / '.state/secret').write_text('must not be copied')
        (source / 'static/app.js').write_text('new frontend')
        (target / '.runs').mkdir(parents=True)
        (target / '.state').mkdir()
        (target / '.runs/prior.log').write_text('old record')
        (target / '.state/write_probe_state.json').write_text('pending recovery')
        stage(source, target)
        self.assertEqual((target / 'app.py').read_text(), 'new version')
        self.assertEqual((target / '.state/write_probe_state.json').read_text(), 'pending recovery')
        self.assertEqual((target / '.runs/prior.log').read_text(), 'old record')
        self.assertFalse((target / '.state/secret').exists())


if __name__ == '__main__':
    unittest.main()
