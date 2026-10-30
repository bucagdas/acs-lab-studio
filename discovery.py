"""Cancellable passive PPPoE PADI discovery; never transmits or saves packets."""


def parse_padi(raw):
    if len(raw) < 20:
        return None
    source = raw[6:12]
    if source[0] & 1 or source == b'\0' * 6:
        return None
    kind = int.from_bytes(raw[12:14], 'big')
    offset, vlans = 14, []
    while kind in (0x8100, 0x88a8):
        if len(vlans) >= 2 or len(raw) < offset + 4:
            return None
        vlans.append(int.from_bytes(raw[offset:offset+2], 'big') & 0xfff)
        kind = int.from_bytes(raw[offset+2:offset+4], 'big')
        offset += 4
    if kind != 0x8863 or len(raw) < offset + 6:
        return None
    header = raw[offset:offset+6]
    if header[:4] != b'\x11\x09\x00\x00':
        return None
    if len(raw) < offset + 6 + int.from_bytes(header[4:6], 'big'):
        return None
    vlan = vlans[0] if len(vlans) == 1 else None
    return {'mac': ':'.join(f'{byte:02x}' for byte in source), 'vlans': vlans,
            'vlan': vlan, 'selectable': len(vlans) <= 1 and (vlan is None or 1 <= vlan <= 4094)}


def discover(iface, cancel):
    from scapy.all import conf, sniff
    from windows_bridge import selected_interface
    found = []

    def receive(packet):
        item = parse_padi(bytes(packet))
        if item is not None and not found:
            found.append(dict(item, packets=1))

    # Keep one socket open across short waits; cancellation also works without traffic.
    capture = conf.L2listen(iface=iface)
    try:
        with selected_interface(iface):
            while not cancel.is_set() and not found:
                sniff(opened_socket=capture, timeout=1, store=False, prn=receive,
                      stop_filter=lambda packet: bool(found) or cancel.is_set())
    finally:
        capture.close()
    return found
