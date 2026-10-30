#!/usr/bin/env python3
"""Privileged, fixed-profile worker for a single isolated CPE."""
import argparse
import importlib.util
import json
import os
import signal
import sys
from pathlib import Path
from windows_bridge import selected_interface
from network_recovery import PapLease
from session_runtime import install_completion, close_servers

BASE = Path(__file__).resolve().parent


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--mode', choices=['readonly', 'write','configure','log_upload','sts_probe','root_password'], required=True)
    p.add_argument('--iface', required=True)
    p.add_argument('--peer-mac', required=True)
    p.add_argument('--vlan', type=int, required=True)
    p.add_argument('--duration', type=int, required=True)
    p.add_argument('--run-dir', type=Path, required=True)
    args = p.parse_args()
    profile=json.loads(sys.stdin.readline(16384))
    if os.geteuid() != 0:
        raise SystemExit('Network worker requires sudo.')
    run = args.run_dir.resolve()
    run.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.umask(0o077)
    module_path = BASE/'engines'/('readonly.py' if args.mode in ('readonly','log_upload','sts_probe','root_password') else 'write_probe.py')
    spec = importlib.util.spec_from_file_location('acs_engine', module_path)
    engine = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(engine)
    engine.LOG_PATH = str(run/'engine.log')
    engine.CWMP_TRACE_PATH = str(run/'cwmp-private.log')
    engine.ACS_KEY_PATH = str(run/'temporary-acs.key')
    engine.ACS_CERT_PATH = str(run/'temporary-acs.crt')
    engine.PROBE_JOURNAL = str(BASE/'.state'/'write_probe_state.json')
    if args.mode=='configure':
        from configure import install
        install(engine,profile,run)
    elif args.mode=='readonly':
        from capabilities import install
        install(engine,run)
    bridge = None
    pap_path = Path('/etc/ppp/pap-secrets')
    modified = False
    temporary = ('* * "" '+profile.get('peer_ip','10.116.13.101')+'\n').encode()
    pap = PapLease(BASE, run, pap_path)
    timers = []
    upload_receiver = None
    original_timer = engine.threading.Timer
    def managed_timer(*a, **kw):
        timer = original_timer(*a, **kw)
        timer.daemon = True
        timers.append(timer)
        return timer
    engine.threading.Timer = managed_timer

    def managed_pap():
        nonlocal modified
        if not modified:
            pap.prepare(temporary)
            modified = True
        return str(pap_path)

    engine.ensure_pap_secrets = managed_pap

    def stop(signum, frame):
        raise KeyboardInterrupt()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    args.local_ip = profile.get('local_ip','10.116.13.100')
    args.peer_ip = profile.get('peer_ip','10.116.13.101')
    args.acs_ip = profile.get('acs_ip','193.192.97.234')
    args.timeout = args.duration
    args.max_runtime = args.duration + 30
    args.no_pppd = False
    try:
        if args.mode=='log_upload':
            from upload_probe import install
            upload_receiver=install(engine,run,args.peer_ip,args.local_ip)
        elif args.mode=='root_password':
            from root_password import install
            upload_receiver=install(engine,profile,run,args.peer_ip,args.local_ip)
        elif args.mode=='sts_probe':
            from sts_probe import install
            upload_receiver=install(engine,run,BASE/'.state',args.peer_ip,args.local_ip)
        bridge = engine.Bridge(args)
        bridge.owned_servers = []
        bridge.owned_captures = []
        install_completion(engine, args.mode, run, BASE/'.state', bridge.stop, upload_receiver)
        # Graceful duration handling is provided by sniff(timeout), not os._exit.
        def hard_stop():
            os.kill(os.getpid(), signal.SIGTERM)
        bridge.hard_stop = hard_stop
        with selected_interface(args.iface):
            bridge.run()
    except KeyboardInterrupt:
        print('[lab] Stop requested; cleaning up owned network processes', flush=True)
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        failures = []
        for timer in timers:
            timer.cancel()
        try:
            if bridge is not None:
                bridge.stop.set()
                try:
                    bridge.stop_pppd()
                except Exception:
                    failures.append('PPP süreci kapatılamadı.')
                try:
                    if getattr(bridge, 'tx_sock', None) is not None:
                        bridge.tx_sock.close()
                except Exception:
                    failures.append('Ethernet göndericisi kapatılamadı.')
                for capture in bridge.owned_captures:
                    try:
                        if capture.poll() is None:
                            capture.terminate()
                            try:
                                capture.wait(timeout=2)
                            except Exception:
                                capture.kill()
                                capture.wait(timeout=2)
                    except Exception:
                        failures.append('Paket kaydı kapatılamadı.')
            servers = list(getattr(bridge, 'owned_servers', []))
            if upload_receiver is not None:
                servers.append(upload_receiver)
            failures.extend(close_servers(servers))
        finally:
            # A failed listener or child cleanup must never skip PAP restore.
            try:
                if modified or pap.record.exists() and pap.lock is not None:
                    pap.restore()
                    print('[lab] Temporary PAP configuration restored', flush=True)
            except Exception:
                failures.append('Geçici PAP ayarı geri alınamadı; ağ kurtarma kaydı korundu.')
            finally:
                pap.release()
        if failures:
            print('[lab] NETWORK_CLEANUP_FAILED: ' + ' '.join(failures), flush=True)
        else:
            print('[lab] NETWORK_CLEANUP_COMPLETE', flush=True)
        print('[lab] Worker finished', flush=True)


if __name__ == '__main__':
    main()
