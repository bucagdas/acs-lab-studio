import sys
import tempfile
import threading
import types
import unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from discovery import parse_padi, discover
from lab import Lab


def frame(tags=(), code=9):
    raw = bytes.fromhex('ffffffffffff60d8a49716d9')
    for vlan in tags:
        raw += b'\x81\x00' + vlan.to_bytes(2, 'big')
    return raw + b'\x88\x63\x11' + bytes([code]) + b'\0\0\0\0'


class DiscoveryTests(unittest.TestCase):
    def test_tagged_and_untagged(self):
        tagged = parse_padi(frame((35,)))
        self.assertEqual(tagged['mac'], '60:d8:a4:97:16:d9')
        self.assertEqual(tagged['vlan'], 35)
        self.assertTrue(tagged['selectable'])
        self.assertIsNone(parse_padi(frame())['vlan'])

    def test_reject_non_padi_and_truncated(self):
        self.assertIsNone(parse_padi(frame(code=7)))
        for size in range(len(frame((35,)))):
            self.assertIsNone(parse_padi(frame((35,))[:size]))
        self.assertIsNone(parse_padi(frame()[:-2] + b'\0\x04'))

    def test_qinq_and_reserved_vlan_not_selectable(self):
        self.assertFalse(parse_padi(frame((35, 100)))['selectable'])
        self.assertFalse(parse_padi(frame((4095,)))['selectable'])

    def test_preview_and_invalid_interface_block_capture(self):
        with tempfile.TemporaryDirectory() as folder:
            lab = Lab(Path(folder), preview=True)
            with self.assertRaises(ValueError):
                lab.discover({'iface': 'en11'})
            with patch.object(lab, 'readiness', return_value=[]), patch('lab.interfaces', return_value=[]):
                with self.assertRaises(ValueError):
                    lab.discover({'iface': 'en11;id'})

    def test_capture_result_and_running_guard(self):
        with tempfile.TemporaryDirectory() as folder:
            lab = Lab(Path(folder))
            with patch.object(lab, 'readiness', return_value=[]), patch('lab.interfaces', return_value=[{'id':'en11'}]), patch('discovery.discover', return_value=[parse_padi(frame((35,)))]) as capture:
                lab.discover({'iface':'en11'})
                lab.discovery_thread.join(timeout=2)
                self.assertEqual(lab.discovery['candidates'][0]['vlan'],35)
                self.assertFalse(lab.discovery['running'])
                capture.assert_called_once_with('en11',lab.discovery_cancel)
                from unittest.mock import Mock
                lab.process = Mock()
                lab.process.poll.return_value = None
                with self.assertRaises(ValueError):
                    lab.discover({'iface':'en11'})
                capture.assert_called_once()

    def fake_capture(self, sniff):
        from unittest.mock import Mock
        socket = Mock()
        module = types.ModuleType('scapy.all')
        module.conf = Mock()
        module.conf.L2listen.return_value = socket
        module.sniff = sniff
        return socket, patch.dict(sys.modules, {'scapy': types.ModuleType('scapy'), 'scapy.all': module})

    def test_waits_until_first_padi_and_closes_socket(self):
        calls = []
        def sniff(**kwargs):
            calls.append(kwargs)
            if len(calls)==15:
                kwargs['prn'](frame((35,)))
                self.assertTrue(kwargs['stop_filter'](frame((35,))))
        socket, context = self.fake_capture(sniff)
        with context:
            result = discover('en11',threading.Event())
        self.assertEqual(len(calls),15)  # passes the previous 12-second limit
        self.assertEqual(result[0]['vlan'],35)
        socket.close.assert_called_once()

    def test_cancel_without_packets(self):
        cancel = threading.Event()
        def sniff(**kwargs):cancel.set()
        socket, context = self.fake_capture(sniff)
        with context:self.assertEqual(discover('en11',cancel),[])
        socket.close.assert_called_once()

    def test_background_cancel_and_concurrent_discovery_guard(self):
        with tempfile.TemporaryDirectory() as folder:
            lab=Lab(Path(folder))
            def waiting(iface,cancel):
                cancel.wait(2)
                return []
            with patch.object(lab,'readiness',return_value=[]), patch('lab.interfaces',return_value=[{'id':'en11'}]), patch('discovery.discover',side_effect=waiting):
                lab.discover({'iface':'en11'})
                self.assertTrue(lab.snapshot()['discovery']['running'])
                with self.assertRaises(ValueError):lab.discover({'iface':'en11'})
                with self.assertRaises(ValueError):lab.start({'mode':'readonly','iface':'en11','mac':'60:d8:a4:97:16:d9'})
                lab.stop_discovery()
                lab.discovery_thread.join(timeout=2)
                self.assertFalse(lab.discovery['running'])
                self.assertTrue(lab.discovery['cancelled'])


if __name__ == '__main__':
    unittest.main()
