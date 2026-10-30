import ast
import socket
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import host_network as host
from lab import Lab, validate_settings


class HostNetworkTests(unittest.TestCase):
    def test_linux_interface_names_and_invalid_inputs(self):
        with patch('host_network.platform.system', return_value='Linux'):
            for name in ('eth0', 'enp3s0', 'enx3c18a0bedc36'):
                with self.subTest(name=name):
                    self.assertEqual(validate_settings({'mode': 'readonly', 'iface': name,
                                     'mac': '02:00:00:00:00:01'})['iface'], name)
            for name in ('-i', 'lo', 'enp3s0;id', '../../etc', 'a' * 16, None, 'eth0\n'):
                with self.subTest(name=name):
                    self.assertFalse(host.valid_interface_name(name))

    def test_macos_interface_names_are_unchanged(self):
        with patch('host_network.platform.system', return_value='Darwin'):
            self.assertTrue(host.valid_interface_name('en11'))
            self.assertFalse(host.valid_interface_name('enp3s0'))

    def test_linux_lists_physical_ethernet_including_disconnected_usb(self):
        links = [dict(ifname=name, link_type=kind, flags=flags, **extra)
                 for name, kind, flags, extra in [
                     ('lo', 'loopback', [], {}), ('enp3s0', 'ether', ['LOWER_UP'], {}),
                     ('enx3c18a0bedc36', 'ether', [], {}), ('wlp2s0', 'ether', ['LOWER_UP'], {}),
                     ('docker0', 'ether', [], {'linkinfo': {'info_kind': 'bridge'}}),
                     ('veth123', 'ether', [], {}),
                     ('enp3s0.35', 'ether', [], {'linkinfo': {'info_kind': 'vlan'}})]]
        with tempfile.TemporaryDirectory() as folder:
            net = Path(folder)
            for name in ('enp3s0', 'enx3c18a0bedc36', 'wlp2s0', 'docker0', 'enp3s0.35'):
                (net / name / 'device').mkdir(parents=True)
            (net / 'wlp2s0' / 'phy80211').mkdir()
            with patch('host_network.platform.system', return_value='Linux'), \
                    patch.object(host, 'SYS_NET', net), patch.object(host, '_ip_json', return_value=links):
                devices = host.interfaces()
        self.assertEqual([d['id'] for d in devices], ['enp3s0', 'enx3c18a0bedc36'])
        self.assertIn('aktif', devices[0]['name'])
        self.assertIn('pasif', devices[1]['name'])

    def test_linux_link_details_use_carrier_not_administrative_up(self):
        for flags, expected in [(['UP'], False), (['UP', 'LOWER_UP'], True)]:
            entry = dict(ifname='enp3s0', flags=flags, operstate='DOWN', address='02:00:00:00:00:01')
            with patch('host_network.platform.system', return_value='Linux'), \
                    patch.object(host, 'interfaces', return_value=[{'id': 'enp3s0'}]), \
                    patch.object(host, '_ip_json', return_value=[entry]) as query:
                details = host.interface_details('enp3s0')
                self.assertEqual(details['active'], expected)
                query.assert_called_once_with('link', 'show', 'dev', 'enp3s0')

    def test_macos_adapter_inventory_regression(self):
        text = ('Hardware Port: Lenovo USB-C Hub\nDevice: en11\nEthernet Address: 02:00:00:00:00:01\n\n'
                'Hardware Port: Wi-Fi\nDevice: en0\nEthernet Address: 02:00:00:00:00:02\n')
        with patch('host_network.platform.system', return_value='Darwin'), \
                patch.object(host, '_run', return_value=text):
            self.assertEqual(host.interfaces(), [{'id': 'en11', 'name': 'Lenovo USB-C Hub'}])

    def test_missing_kernel_ppp_or_tools_gives_actionable_reason(self):
        with tempfile.TemporaryDirectory() as folder:
            with patch('host_network.platform.system', return_value='Linux'), \
                    patch.object(host, 'PPP_DEVICE', Path(folder) / 'not-present'), \
                    patch('host_network.shutil.which', side_effect=lambda c: None if c == 'ip' else '/usr/sbin/' + c):
                reasons = host.dependency_issues()
                self.assertTrue(any('ip' in reason for reason in reasons))
                self.assertTrue(any('/dev/ppp' in reason for reason in reasons))

    def test_linux_pppd_keeps_default_route_and_owns_named_interface(self):
        with patch('host_network.platform.system', return_value='Linux'):
            cmd = host.pppd_command('/dev/pts/4', '10.116.13.100', '10.116.13.101', 'acs0123456789')
            self.assertEqual(cmd[cmd.index('ifname') + 1], 'acs0123456789')
            self.assertEqual(cmd[cmd.index('logfd') + 1], '1')
            self.assertIn('nodefaultroute', cmd)
            self.assertIn('noproxyarp', cmd)
            self.assertNotIn('defaultroute', cmd)
            self.assertNotIn('usepeerdns', cmd)
            with self.assertRaises(ValueError):
                host.pppd_command('/dev/pts/4', '10.116.13.100', '10.116.13.101', 'ppp0')

    def test_macos_pppd_profile_stays_compatible(self):
        with patch('host_network.platform.system', return_value='Darwin'):
            cmd = host.pppd_command('/dev/ttys001', '10.116.13.100', '10.116.13.101')
        self.assertEqual(cmd[:8], ['pppd', '/dev/ttys001', '115200', 'nodetach', 'local', 'noauth', '+pap', 'refuse-chap'])
        self.assertNotIn('ifname', cmd)
        self.assertNotIn('logfd', cmd)

    def test_linux_monitor_refuses_foreign_name_or_address_pair(self):
        local, peer, name = '10.116.13.100', '10.116.13.101', 'acs0123456789'
        entry = dict(ifname=name, flags=['POINTOPOINT'],
                     addr_info=[dict(family='inet', local=local, peer=peer + '/32')])
        with patch('host_network.platform.system', return_value='Linux'), \
                patch.object(host, '_ip_json', return_value=[entry]):
            self.assertEqual(host.find_ppp_interface(local, peer, name), name)
            self.assertIsNone(host.find_ppp_interface(local, peer, 'acs9876543210'))
            self.assertIsNone(host.find_ppp_interface(local, '10.0.0.1', name))
            self.assertIsNone(host.find_ppp_interface(local, peer))
            entry['flags'] = ['UP']
            self.assertIsNone(host.find_ppp_interface(local, peer, name))

    def test_macos_monitor_requires_ppp_and_exact_peer(self):
        output = ('en11: flags=UP\n\tinet 10.116.13.100 netmask 0xffffffff\n'
                  'ppp0: flags=POINTOPOINT\n\tinet 10.116.13.100 --> 10.116.13.101 netmask 0xff000000\n')
        with patch('host_network.platform.system', return_value='Darwin'), \
                patch.object(host, '_run', return_value=output):
            self.assertEqual(host.find_ppp_interface('10.116.13.100', '10.116.13.101'), 'ppp0')
            self.assertIsNone(host.find_ppp_interface('10.116.13.100', '10.116.13.10'))

    def test_linux_alias_add_never_replaces_existing_addresses(self):
        with patch('host_network.platform.system', return_value='Linux'), \
                patch.object(host, '_ip_json', return_value=[{'addr_info': [{'local': '10.116.13.100'}]}]), \
                patch.object(host, '_run', return_value='') as run:
            self.assertTrue(host.add_acs_alias('acs0123456789', '193.192.97.234'))
            run.assert_called_once_with(['ip', 'address', 'add', '193.192.97.234/32', 'dev', 'acs0123456789'], timeout=4)
        with patch('host_network.platform.system', return_value='Linux'), \
                patch.object(host, '_ip_json', return_value=[{'addr_info': [{'local': '193.192.97.234'}]}]), \
                patch.object(host, '_run') as run:
            self.assertTrue(host.add_acs_alias('acs0123456789', '193.192.97.234'))
            run.assert_not_called()

    def test_linux_freebind_is_per_socket_and_listeners_use_test_ips(self):
        with patch('host_network.platform.system', return_value='Linux'):
            sock = Mock()
            host.prepare_socket(sock)
            sock.setsockopt.assert_called_once_with(socket.IPPROTO_IP, getattr(socket, 'IP_FREEBIND', 15), 1)
            self.assertEqual(host.service_addresses('10.116.13.100', '193.192.97.234'), ['10.116.13.100', '193.192.97.234'])
            self.assertEqual(host.service_addresses('10.116.13.100', '10.116.13.100'), ['10.116.13.100'])
        with patch('host_network.platform.system', return_value='Darwin'):
            sock = Mock()
            host.prepare_socket(sock)
            sock.setsockopt.assert_not_called()
            self.assertEqual(host.service_addresses('10.116.13.100', '193.192.97.234'), ['0.0.0.0'])

    def test_linux_preflight_checks_same_endpoints_as_engine_not_loopback_dns(self):
        sockets = []
        def make_socket(*args):
            sock = Mock(); sockets.append(sock); return sock
        with patch('host_network.platform.system', return_value='Linux'), \
                patch('lab.socket.socket', side_effect=make_socket):
            Lab.free_ports()
        bindings = [sock.bind.call_args.args[0] for sock in sockets]
        self.assertIn(('10.116.13.100', 53), bindings)
        self.assertIn(('193.192.97.234', 80), bindings)
        self.assertNotIn(('0.0.0.0', 53), bindings)
        for sock in sockets:
            sock.close.assert_called_once()

    def test_different_os_metadata_and_windows_not_supported_yet(self):
        for system, name, launcher in [('Darwin', 'macOS', 'Baslat.command'), ('Linux', 'Linux', 'Baslat.sh')]:
            with patch('host_network.platform.system', return_value=system):
                info = host.host_info()
                self.assertEqual((info['name'], info['launcher']), (name, launcher))
                self.assertTrue(info['supported'])
        with patch('host_network.platform.system', return_value='Windows'):
            self.assertFalse(host.host_info()['supported'])
            self.assertTrue(host.dependency_issues())


class EngineTransportTests(unittest.TestCase):
    def test_alias_is_retried_after_failure_and_readded_after_reconnect(self):
        for name in ('readonly.py', 'write_probe.py'):
            with self.subTest(engine=name):
                path = Path(__file__).resolve().parents[1] / 'engines' / name
                tree = ast.parse(path.read_text())
                cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'Bridge')
                cls.body = [node for node in cls.body if isinstance(node, ast.FunctionDef)
                            and node.name in ('monitor_ppp', 'add_acs_alias')]
                stop = Mock(); stop.is_set.return_value = False
                waits = []
                def wait(timeout):
                    waits.append(timeout)
                    if len(waits) == 4:
                        stop.is_set.return_value = True
                stop.wait.side_effect = wait
                add = Mock(side_effect=[False, True, True])
                find = Mock(side_effect=['acs0123456789', 'acs0123456789', None, 'acs0123456789'])
                ns = dict(threading=Mock(), add_acs_alias=add, find_ppp_interface=find)
                exec(compile(ast.fix_missing_locations(ast.Module(body=[cls], type_ignores=[])), str(path), 'exec'), ns)
                bridge = ns['Bridge']()
                bridge.stop = stop; bridge.ppp_name = 'acs0123456789'; bridge.tap_loop = Mock()
                bridge.args = types.SimpleNamespace(local_ip='10.116.13.100', peer_ip='10.116.13.101', acs_ip='193.192.97.234')
                bridge.monitor_ppp()
                self.assertEqual(add.call_count, 3)
                self.assertEqual(bridge.acs_alias_iface, 'acs0123456789')

    def test_both_engines_start_linux_pppd_and_clean_up_only_owned_child(self):
        for name in ('readonly.py', 'write_probe.py'):
            with self.subTest(engine=name):
                path = Path(__file__).resolve().parents[1] / 'engines' / name
                tree = ast.parse(path.read_text())
                cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'Bridge')
                methods = [node for node in cls.body if isinstance(node, ast.FunctionDef)
                           and node.name in ('start_pppd', 'stop_pppd')]
                cls.body = methods
                ns = dict(ensure_pap_secrets=Mock(), pty=Mock(), os=Mock(), subprocess=Mock(),
                          threading=Mock(), pppd_command=host.pppd_command)
                ns['pty'].openpty.return_value = (101, 102)
                ns['os'].ttyname.return_value = '/dev/pts/4'
                exec(compile(ast.fix_missing_locations(ast.Module(body=[cls], type_ignores=[])), str(path), 'exec'), ns)
                bridge = ns['Bridge']()
                bridge.args = types.SimpleNamespace(local_ip='10.116.13.100', peer_ip='10.116.13.101')
                bridge.ppp_name = 'acs0123456789'; bridge.pppd_buf = b''; bridge.rx_pending = []
                bridge.pppd_reader = Mock(); bridge.read_pty = Mock()
                with patch('host_network.platform.system', return_value='Linux'):
                    bridge.start_pppd()
                cmd = ns['subprocess'].Popen.call_args.args[0]
                self.assertIn('acs0123456789', cmd)
                child = bridge.pppd
                bridge.stop_pppd()
                child.terminate.assert_called_once()
                child.wait.assert_called_once_with(timeout=2)
                self.assertIsNone(bridge.pppd)


if __name__ == '__main__':
    unittest.main()
