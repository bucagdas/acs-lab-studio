"""Bounded binary records over wsl.exe stdin/stdout, never a network tunnel."""
import json
import struct
import threading

HELLO, FRAME, SELECT, ACK, STATUS, READY, STOP, ERROR = range(1, 9)
HEADER = struct.Struct('!4sBI')
MAX_RECORD = 65536
MAX_FRAME = 9216


def read_exact(stream, count):
    chunks = bytearray()
    while len(chunks) < count:
        part = stream.read(count - len(chunks))
        if not part:
            raise EOFError('Windows paket bağlantısı kapandı.')
        chunks.extend(part)
    return bytes(chunks)


class Channel:
    def __init__(self, reader, writer):
        self.reader, self.writer = reader, writer
        self.lock = threading.Lock()

    def receive(self):
        magic, kind, size = HEADER.unpack(read_exact(self.reader, HEADER.size))
        if magic != b'ACSB' or kind not in range(1, 9) or size > MAX_RECORD:
            raise ValueError('Geçersiz Windows paket kaydı.')
        return kind, read_exact(self.reader, size)

    def send(self, kind, data=b''):
        if kind not in range(1, 9) or len(data) > MAX_RECORD:
            raise ValueError('Paket kaydı sınırı aşıldı.')
        with self.lock:
            remaining = memoryview(HEADER.pack(b'ACSB', kind, len(data)) + data)
            while remaining:
                written = self.writer.write(remaining)
                if not written:
                    raise BrokenPipeError('Windows paket kanalı yazılamadı.')
                remaining = remaining[written:]
            self.writer.flush()

    def json(self, kind, value):
        self.send(kind, json.dumps(value, ensure_ascii=True).encode('ascii'))


def pppoe_frame(raw):
    """Reject other Ethernet traffic, truncation and more than two VLAN tags."""
    if not 20 <= len(raw) <= MAX_FRAME:
        return False
    kind = int.from_bytes(raw[12:14], 'big')
    offset = 14
    for _ in range(2):
        if kind not in (0x8100, 0x88a8):
            break
        if len(raw) < offset + 4:
            return False
        kind = int.from_bytes(raw[offset + 2:offset + 4], 'big')
        offset += 4
    if kind not in (0x8863, 0x8864) or len(raw) < offset + 6:
        return False
    return (raw[offset] == 0x11 and
            offset + 6 + int.from_bytes(raw[offset + 4:offset + 6], 'big') <= len(raw))


def frame_record(index, raw):
    if not 0 <= index < 64 or not pppoe_frame(raw):
        raise ValueError('Geçersiz Ethernet PPPoE paketi.')
    return struct.pack('!H', index) + raw


def unpack_frame(payload):
    if len(payload) < 2:
        raise ValueError('Eksik Ethernet kaydı.')
    index = int.from_bytes(payload[:2], 'big')
    raw = payload[2:]
    if index >= 64 or not pppoe_frame(raw):
        raise ValueError('Geçersiz Ethernet PPPoE paketi.')
    return index, raw
