"""Host-specific network operations; shared by discovery, UI and both engines.

Linux uses iproute2 and the kernel PPP driver. Ethernet frames still travel
through Scapy; only this run's PPP interface receives the temporary ACS alias.
"""
import json
import platform
import re
import shutil
import socket
import subprocess
from http.server import ThreadingHTTPServer
from pathlib import Path
import windows_bridge

SYS_NET = Path('/sys/class/net')
PPP_DEVICE = Path('/dev/ppp')


def service_address(ip):
    # Leave the proven macOS listener behavior intact. On Linux avoid the
    # loopback DNS/NTP services commonly installed by desktop distributions.
    return ip if platform.system() == 'Linux' else '0.0.0.0'


def service_addresses(local_ip, acs_ip):
    return list(dict.fromkeys([service_address(local_ip), service_address(acs_ip)]))


def prepare_socket(sock):
    if platform.system() == 'Linux':
        # Linux IP_FREEBIND permits binding before IPCP creates the PPP link.
        # It changes only this socket, not a system-wide sysctl.
        sock.setsockopt(socket.IPPROTO_IP, getattr(socket, 'IP_FREEBIND', 15), 1)


class LabHTTPServer(ThreadingHTTPServer):
    def server_bind(self):
        prepare_socket(self.socket)
        super().server_bind()


def host_info():
    system = platform.system()
    if system == 'Linux' and windows_bridge.enabled():
        return {'system': 'Linux', 'name': 'Windows / WSL 2', 'supported': True,
                'launcher': 'Baslat.cmd', 'liveTestPending': True}
    return {'system': system, 'name': {'Darwin': 'macOS', 'Linux': 'Linux',
                                     'Windows': 'Windows'}.get(system, system),
            'supported': system in ('Darwin', 'Linux'),
            'launcher': 'Baslat.sh' if system == 'Linux' else 'Baslat.command',
            'liveTestPending': system == 'Linux'}


def valid_interface_name(name):
    if not isinstance(name, str):
        return False
    if platform.system() == 'Darwin':
        return re.fullmatch(r'en\d{1,3}', name) is not None
    if platform.system() == 'Linux':
        return (re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,14}', name) is not None
                and name != 'lo')
    return False


def _run(command, timeout=5):
    result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise OSError('Ağ komutu başarısız: ' + command[0])
    return result.stdout


def _ip_json(*args):
    data = json.loads(_run(['ip', '-j', *args]))
    if not isinstance(data, list):
        raise ValueError('iproute2 yanıtı geçersiz.')
    return data


def _link_active(entry):
    return 'LOWER_UP' in entry.get('flags', []) or entry.get('operstate') == 'UP'


def interfaces():
    try:
        if platform.system() == 'Darwin':
            text = _run(['networksetup', '-listallhardwareports'])
            result = []
            for block in text.split('\n\n'):
                name = re.search(r'Hardware Port: (.+)', block)
                device = re.search(r'Device: (en\d+)', block)
                if name and device and name[1] != 'Wi-Fi':
                    result.append({'id': device[1], 'name': name[1]})
            return result
        if platform.system() == 'Linux':
            if windows_bridge.enabled():
                return [{'id': item['id'], 'name': item['name'], 'displayName': item['name']}
                        for item in windows_bridge.inventory()['adapters']]
            result = []
            for entry in _ip_json('-details', 'link', 'show'):
                name = entry.get('ifname', '')
                if not valid_interface_name(name) or entry.get('link_type') != 'ether':
                    continue
                device = SYS_NET / name
                # Only physical Ethernet: exclude Wi-Fi and software interfaces
                # such as bridges, VLAN children, Docker veths and VPN devices.
                if (not (device / 'device').exists() or (device / 'wireless').exists()
                        or (device / 'phy80211').exists()
                        or entry.get('linkinfo', {}).get('info_kind')):
                    continue
                status = 'bağlantı aktif' if _link_active(entry) else 'bağlantı pasif'
                result.append({'id': name, 'name': 'Ethernet · ' + status})
            return sorted(result, key=lambda item: item['id'])
    except (OSError, ValueError, subprocess.TimeoutExpired):
        pass
    return []


def interface_details(name):
    if name not in {item['id'] for item in interfaces()}:
        raise ValueError('Bu bilgisayarda böyle bir Ethernet adaptörü yok.')
    try:
        if windows_bridge.enabled():
            windows_bridge.refresh()
            entry = next(item for item in windows_bridge.inventory()['adapters'] if item['id'] == name)
            return {'iface': name, 'active': entry['active'], 'mac': entry['mac'],
                    'label': entry['name'],
                    'note': 'Bu cihazın fiziksel Ethernet adaptörü. Router adresi keşifle belirlenir.'}
        if platform.system() == 'Linux':
            entries = _ip_json('link', 'show', 'dev', name)
            entry = next(item for item in entries if item.get('ifname') == name)
            active, mac = _link_active(entry), entry.get('address', '')
        else:
            text = _run(['ifconfig', name])
            address = re.search(r'ether\s+([0-9a-f:]+)', text)
            active = bool(re.search(r'status:\s+active', text))
            mac = address[1] if address else ''
    except (OSError, ValueError, StopIteration, subprocess.TimeoutExpired) as exc:
        raise ValueError('Adaptör durumu okunamadı.') from exc
    return {'iface': name, 'active': active, 'mac': mac,
            'note': 'Gösterilen adres bu cihazın Ethernet adaptörüne aittir. Router’ın adresi keşifle belirlenir.'}


def dependency_issues():
    system = platform.system()
    if system not in ('Darwin', 'Linux'):
        return ['Bu ağ motoru macOS/Linux üzerinde çalışır. Windows için Baslat.cmd ile WSL 2 köprüsünü kullanın.']
    commands = ['pppd', 'openssl'] + (['ip'] if system == 'Linux' else ['networksetup', 'ifconfig'])
    missing = [name for name in commands if shutil.which(name) is None]
    reasons = ['Eksik sistem araçları: ' + ', '.join(missing) + '. Kurulum için README’ye bakın.'] if missing else []
    if system == 'Linux' and not PPP_DEVICE.exists():
        reasons.append('Linux PPP aygıtı /dev/ppp bulunamadı. ppp_generic ve ppp_async modüllerini yükleyip yeniden deneyin; README’ye bakın.')
    return reasons


def pppd_command(tty, local_ip, peer_ip, interface=None):
    system = platform.system()
    if system not in ('Darwin', 'Linux'):
        raise RuntimeError('Desteklenmeyen PPP işletim sistemi.')
    command = [
        'pppd', tty, '115200', 'nodetach', 'local', 'noauth', '+pap',
        'refuse-chap', 'refuse-mschap', 'refuse-mschap-v2', 'refuse-eap',
        f'{local_ip}:{peer_ip}', 'ms-dns', local_ip,
        'mtu', '1400', 'mru', '1400',
        'noaccomp', 'nopcomp', 'novj', 'nobsdcomp', 'nodeflate',
        'noipv6', 'asyncmap', '0', 'nodefaultroute', 'noipdefault', 'debug',
    ]
    if system == 'Linux':
        # A unique name also lets the monitor refuse unrelated PPP links.
        if not interface or re.fullmatch(r'acs[0-9a-f]{10}', interface) is None:
            raise ValueError('Oturuma özel Linux PPP arayüz adı gerekli.')
        command += ['ifname', interface, 'logfd', '1', 'noproxyarp']
    return command


def find_ppp_interface(local_ip, peer_ip, expected=None):
    """Locate only a PPP link with the exact local/remote address pair."""
    try:
        if platform.system() == 'Linux':
            if not expected:
                return None
            for entry in _ip_json('-4', 'addr', 'show'):
                if entry.get('ifname') != expected or 'POINTOPOINT' not in entry.get('flags', []):
                    continue
                for address in entry.get('addr_info', []):
                    if (address.get('family') == 'inet' and address.get('local') == local_ip
                            and address.get('peer', '').split('/')[0] == peer_ip):
                        return expected
        elif platform.system() == 'Darwin':
            for block in re.split(r'\n(?=\S+:)', _run(['ifconfig'], timeout=2)):
                name = block.split(':', 1)[0]
                if (re.fullmatch(r'ppp\d+', name)
                        and re.search(r'\binet\s+' + re.escape(local_ip) + r'\s+-->\s+'
                                      + re.escape(peer_ip) + r'(?:\s|$)', block)):
                    return name
    except (OSError, ValueError, subprocess.TimeoutExpired):
        pass
    return None


def add_acs_alias(iface, ip):
    """Add an address, never replace other addresses or the default route."""
    try:
        if platform.system() == 'Linux':
            for entry in _ip_json('-4', 'addr', 'show', 'dev', iface):
                if any(address.get('local') == ip for address in entry.get('addr_info', [])):
                    return True
            _run(['ip', 'address', 'add', ip + '/32', 'dev', iface], timeout=4)
            return True
        if platform.system() == 'Darwin':
            for command in (['ifconfig', iface, 'alias', ip, '255.255.255.255'],
                            ['ifconfig', iface, 'alias', ip]):
                try:
                    _run(command, timeout=4)
                    return True
                except (OSError, subprocess.TimeoutExpired):
                    continue
    except (OSError, ValueError, subprocess.TimeoutExpired):
        pass
    return False


def firewall_status():
    if platform.system() == 'Darwin':
        try:
            state = _run(['/usr/libexec/ApplicationFirewall/socketfilterfw', '--getglobalstate']).strip()
            return 'macOS firewall left unchanged: ' + (state or 'state unavailable')
        except (OSError, subprocess.TimeoutExpired):
            return 'macOS firewall left unchanged (state unavailable)'
    return 'Linux firewall left unchanged; allow the isolated PPP test traffic if filtered.'
