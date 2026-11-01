import ast
import contextlib
import io
from pathlib import Path
import socket
import struct
import sys
import tempfile
import threading
import types
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lab import Lab, public_line


ROOT = Path(__file__).resolve().parents[1]


def run_dns(engine, *, qtype=1, send_failure=False):
    # Execute the shipped resolver method with real DNS bytes and a fake socket.
    # No host adapter, privilege or installed Scapy is needed for this boundary.
    tree = ast.parse((ROOT / 'engines' / (engine + '.py')).read_text())
    bridge = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'Bridge')
    method = next(node for node in bridge.body if isinstance(node, ast.FunctionDef) and node.name == 'dns_loop')
    question = b'\x04acs3\x04turk\x03net\0' + struct.pack('!HH', qtype, 1)
    request = struct.pack('!HHHHHH', 123, 0x0100, 1, 0, 0, 0) + question
    stop = threading.Event()

    class Socket:
        def __init__(self):
            self.received = False
            self.answers = []

        def setsockopt(self, *args): pass
        def bind(self, *args): pass
        def settimeout(self, *args): pass
        def close(self): pass

        def recvfrom(self, *args):
            if not self.received:
                self.received = True
                return request, ('10.116.13.101', 54321)
            stop.set()
            raise socket.timeout()

        def sendto(self, data, addr):
            if send_failure:
                raise OSError('synthetic send failure')
            self.answers.append((data, addr))

    sock = Socket()
    namespace = dict(socket=types.SimpleNamespace(
        socket=lambda *args: sock, AF_INET=socket.AF_INET, SOCK_DGRAM=socket.SOCK_DGRAM,
        SOL_SOCKET=socket.SOL_SOCKET, SO_REUSEADDR=socket.SO_REUSEADDR,
        timeout=socket.timeout, inet_aton=socket.inet_aton), struct=struct,
        prepare_socket=lambda value: None, service_address=lambda ip: ip)
    exec(compile(ast.Module(body=[method], type_ignores=[]), '<actual resolver method>', 'exec'), namespace)
    instance = types.SimpleNamespace(args=types.SimpleNamespace(
        local_ip='10.116.13.100', peer_ip='10.116.13.101', acs_ip='193.192.97.234'))
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        namespace['dns_loop'](instance, stop)
    return sock.answers, output.getvalue()


class NetworkDiagnosticsTests(unittest.TestCase):
    def test_both_resolvers_report_the_ip_actually_encoded_in_the_dns_answer(self):
        for engine in ('readonly', 'write_probe'):
            with self.subTest(engine=engine):
                answers, log = run_dns(engine)
                self.assertEqual(len(answers), 1)
                response, recipient = answers[0]
                self.assertEqual(recipient, ('10.116.13.101', 54321))
                self.assertEqual(struct.unpack('!HHHHHH', response[:12]), (123, 0x8180, 1, 1, 0, 0))
                wire_address = socket.inet_ntoa(response[-4:])
                self.assertEqual(wire_address, '193.192.97.234')
                self.assertIn('acs3.turk.net type=1 -> ' + wire_address, log)
                self.assertNotIn('type=1 -> 10.116.13.100', log)

    def test_aaaa_no_address_and_failed_sends_are_not_reported_as_success(self):
        for engine in ('readonly', 'write_probe'):
            with self.subTest(engine=engine):
                answers, log = run_dns(engine, qtype=28)
                self.assertEqual(struct.unpack('!H', answers[0][0][6:8])[0], 0)
                self.assertIn('type=28 -> no-answer', log)
                answers, log = run_dns(engine, send_failure=True)
                self.assertEqual(answers, [])
                self.assertIn('[dns] response failed:', log)
                self.assertNotIn('type=1 ->', log)

    def test_export_contains_ip_and_acs_dns_evidence_but_no_ppp_credentials(self):
        with tempfile.TemporaryDirectory() as folder:
            lab = Lab(Path(folder), preview=True)
            lab.settings = {'mode': 'readonly'}
            lab.outcome = 'running'
            for line in (
                '[pppd] local  IP address 10.116.13.100',
                '[pppd] remote IP address 10.116.13.101',
                '[pppd] PAP Authenticate-Request password=fixture-secret',
                '[dns] acs3.turk.net type=1 -> 193.192.97.234',
                '[dns] private-device.example type=1 -> 10.116.13.100',
            ):
                lab.consume(line)
            report = lab.export().decode()
            self.assertEqual(lab.steps['link'], 'done')
            self.assertIn('Bilgisayar PPP IP: 10.116.13.100', report)
            self.assertIn('Router PPP IP: 10.116.13.101', report)
            self.assertIn('ACS DNS yanıtı: tür=1 adres=193.192.97.234', report)
            self.assertNotIn('fixture-secret', report)
            self.assertNotIn('private-device.example', report)

    def test_unrecognized_ppp_output_and_malformed_diagnostics_remain_hidden(self):
        for line in (
            '[pppd] local IP address 999.1.1.1',
            '[pppd] local IP address 10.116.13.100 password=fixture-secret',
            '[pppd] sent [PAP AuthReq user="fixture"]',
            '[dns] acs3.turk.net type=1 -> 999.1.1.1',
            '[dns] acs3.turk.net type=1 -> 193.192.97.234 password=fixture-secret',
        ):
            self.assertIsNone(public_line(line), line)


if __name__ == '__main__':
    unittest.main()
