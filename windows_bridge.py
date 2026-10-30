"""Linux-side inventory and leases for a Windows-owned Ethernet adapter."""
import contextlib
import json
import os
import socket
from pathlib import Path


def enabled():
    return bool(os.environ.get('ACS_WINDOWS_BRIDGE_STATE'))


def inventory():
    path = os.environ.get('ACS_WINDOWS_BRIDGE_STATE')
    if not path:
        return None
    try:
        state = json.loads(Path(path).read_text())
        if not isinstance(state.get('adapters'), list) or not state.get('control'):
            raise ValueError('Eksik köprü bilgisi.')
        return state
    except (OSError, ValueError, TypeError) as exc:
        raise ValueError('Windows paket köprüsüne ulaşılamadı.') from exc


def _connect(request):
    state = inventory()
    stream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    stream.settimeout(15)
    try:
        stream.connect(state['control'])
        stream.sendall(json.dumps(request).encode() + b'\n')
        # Read exactly one bounded JSON line; the socket stays open as a lease.
        data = bytearray()
        while not data.endswith(b'\n'):
            part = stream.recv(1)
            if not part or len(data) >= 16384:
                raise ValueError('Windows köprü yanıtı eksik.')
            data.extend(part)
        result = json.loads(data)
        if not result.get('ok'):
            raise ValueError(result.get('error', 'Windows adaptörü açılamadı.'))
        return stream, result
    except Exception:
        stream.close()
        raise


def refresh():
    stream, result = _connect({'op': 'status'})
    stream.close()
    return result


@contextlib.contextmanager
def selected_interface(iface):
    if not enabled():
        yield
        return
    state = inventory()
    if iface not in {item['id'] for item in state['adapters']}:
        raise ValueError('Windows Ethernet adaptörü bulunamadı.')
    stream, _ = _connect({'op': 'select', 'iface': iface})
    try:
        yield
    finally:
        # Releasing the private lease stops capture of this physical adapter.
        try:
            stream.sendall(b'R')
            response = bytearray()
            while not response.endswith(b'\n') and len(response) < 16384:
                part = stream.recv(1)
                if not part:
                    break
                response.extend(part)
        except OSError:
            pass
        stream.close()
