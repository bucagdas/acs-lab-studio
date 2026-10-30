"""Stop a completed RPC session independently of background packet traffic."""
import json
import threading


def terminal_result(mode, run, state_dir):
    names = {'readonly': 'capabilities.json', 'log_upload': 'upload-probe.json',
             'configure': 'configuration-state.json', 'sts_probe': 'sts-probe.json',
             'root_password': 'root-password-transfer.json'}
    try:
        if mode == 'write':
            report = json.loads((state_dir / 'write_probe_state.json').read_text())
            return report.get('status') == 'restored'
        report = json.loads((run / names[mode]).read_text())
        status = report.get('status')
        if mode == 'root_password':
            return status == 'failed' or (status == 'transfer_reported' and report.get('served') is True)
        completed = {
            'readonly': {'complete', 'failed', 'unsupported'},
            'log_upload': {'verified', 'failed'},
            'configure': {'verified', 'password_acknowledged', 'unverified'},
            'sts_probe': {'verified', 'failed'},
        }
        return status in completed.get(mode, set())
    except (OSError, ValueError, KeyError):
        return False


def install_completion(engine, mode, run, state_dir, stop, receiver=None):
    def completed():
        if terminal_result(mode, run, state_dir):
            stop.set()
    original = engine.ACSHandler._send
    def send(handler, *args, **kwargs):
        result = original(handler, *args, **kwargs)
        completed()  # The final RPC response has been sent before stopping.
        if mode == 'write' and getattr(handler.server.state, 'stage', '') in ('probe_done', 'probe_refused', 'complete_fault'):
            stop.set()
        return result
    engine.ACSHandler._send = send
    if receiver is not None and hasattr(receiver.RequestHandlerClass, 'respond'):
        original_response = receiver.RequestHandlerClass.respond
        def respond(handler, *args, **kwargs):
            result = original_response(handler, *args, **kwargs)
            completed()
            return result
        receiver.RequestHandlerClass.respond = respond


def capture_session(bridge, sniffer_factory):
    ready = threading.Event()
    sniffer = sniffer_factory(iface=bridge.iface, prn=bridge.on_packet, store=False,
                              started_callback=ready.set)
    try:
        sniffer.start()
        if not ready.wait(5):
            sniffer.join(timeout=0)  # Surface a packet-socket startup exception.
            raise RuntimeError('Paket dinleyicisi başlatılamadı.')
        bridge.stop.wait(bridge.args.timeout)
    finally:
        bridge.stop.set()
        if ready.is_set() and sniffer.running:
            sniffer.stop(join=False)
        sniffer.join(timeout=3)


def close_servers(servers):
    errors = []
    for server in servers:
        def close(server=server):
            try:
                server.shutdown()
                server.server_close()
            except Exception:
                errors.append('HTTP dinleyicisi kapatılamadı.')
        thread = threading.Thread(target=close, daemon=True)
        thread.start()
        thread.join(timeout=3)
        if thread.is_alive():
            errors.append('HTTP kapanış süresi aşıldı.')
    return errors
