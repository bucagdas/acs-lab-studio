"""Capture/inject PPPoE on one selected Windows physical Ethernet adapter."""
import base64
import json
import re
import subprocess
import threading
import uuid
from .protocol import FRAME, ERROR, frame_record, pppoe_frame

ADAPTER_SCRIPT = r"""+[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
Get-NetAdapter -Physical | Where-Object { $_.NdisMedium -eq 0 -and $_.NdisPhysicalMedium -in @(0,14) } |
Select-Object Name,InterfaceDescription,InterfaceGuid,MacAddress,Status |
ConvertTo-Json -Compress
"""


def parse_adapters(text):
    data = json.loads(text.lstrip('\ufeff') or '[]')
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        raise ValueError('Windows adaptör listesi geçersiz.')
    result, seen = [], set()
    for item in data:
        guid = str(uuid.UUID(str(item['InterfaceGuid']).strip('{}')))
        mac = str(item.get('MacAddress', '')).replace('-', ':').lower()
        if (not re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', mac)
                or int(mac[:2], 16) & 1 or mac == '00:00:00:00:00:00' or guid in seen):
            continue
        seen.add(guid)
        result.append({'guid': guid, 'mac': mac, 'active': item.get('Status') == 'Up',
                       'name': str(item.get('Name', 'Ethernet'))[:128],
                       'description': str(item.get('InterfaceDescription', 'Ethernet'))[:256]})
    if len(result) > 64:
        raise ValueError('En fazla 64 fiziksel Ethernet adaptörü desteklenir.')
    return result


def adapters():
    encoded = base64.b64encode(ADAPTER_SCRIPT.encode('utf-16-le')).decode('ascii')
    result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive',
                             '-EncodedCommand', encoded], capture_output=True, timeout=20)
    if result.returncode:
        raise RuntimeError('Windows Ethernet adaptörleri okunamadı.')
    return parse_adapters(result.stdout.decode('utf-8-sig'))


class Capture:
    def __init__(self, cards, channel):
        self.cards, self.channel = cards, channel
        self.index = None
        self.capture = self.sender = self.thread = None
        self.stop = threading.Event()

    def select(self, index):
        self.close()
        if index is None:
            return
        if type(index) is not int or not 0 <= index < len(self.cards):
            raise ValueError('Windows adaptör seçimi geçersiz.')
        from scapy.all import conf
        card = self.cards[index]
        iface = '\\Device\\NPF_{' + card['guid'].upper() + '}'
        # Npcap receives all VLAN frames into the BPF path; the callback below
        # forwards only PPPoE, never unrelated IP or Wi-Fi traffic.
        packet_filter = 'ether proto 0x8863 or ether proto 0x8864 or ether proto 0x8100 or ether proto 0x88a8'
        try:
            self.capture = conf.L2listen(iface=iface, filter=packet_filter)
            self.sender = conf.L2socket(iface=iface)
        except Exception:
            self.close()
            raise RuntimeError('Seçilen Ethernet adaptörü Npcap ile açılamadı.')
        self.index = index
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._receive, args=(index, self.capture, self.stop), daemon=True)
        self.thread.start()

    def _receive(self, index, capture, stop):
        from scapy.all import sniff
        own_mac = bytes.fromhex(self.cards[index]['mac'].replace(':', ''))
        def packet(value):
            raw = bytes(value)
            if not stop.is_set() and pppoe_frame(raw) and raw[6:12] != own_mac:
                self.channel.send(FRAME, frame_record(index, raw))
        try:
            while not stop.is_set():
                sniff(opened_socket=capture, timeout=0.5, store=False, prn=packet)
        except Exception:
            if not stop.is_set():
                # Capture loss aborts the binary link, rather than pretending
                # the physical interface still works until the test times out.
                self.channel.json(ERROR, {'error': 'Windows paket dinleme bağlantısı kesildi.'})

    def send(self, index, raw):
        if index != self.index or self.sender is None:
            return
        own_mac = bytes.fromhex(self.cards[index]['mac'].replace(':', ''))
        if pppoe_frame(raw) and raw[6:12] == own_mac:
            from scapy.all import Ether
            self.sender.send(Ether(raw))

    def close(self):
        self.stop.set()
        if self.thread is not None:
            self.thread.join(timeout=2)
        for item in (self.capture, self.sender):
            if item is not None:
                item.close()
        self.capture = self.sender = self.thread = None
        self.index = None
