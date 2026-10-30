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
    prior = None
    modified = False
    temporary = ('* * "" '+profile.get('peer_ip','10.116.13.101')+'\n').encode()
    recovery = BASE/'.state'/'pap-recovery.json'
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
        nonlocal prior, modified
        if not modified:
            if pap_path.is_symlink():
                raise RuntimeError('PAP file is a symlink; refusing replacement')
            pap_path.parent.mkdir(parents=True, exist_ok=True)
            if pap_path.exists():
                stat = pap_path.stat()
                prior = (pap_path.read_bytes(), stat.st_mode & 0o777, stat.st_uid, stat.st_gid)
            # Keep a crash recovery snapshot in the private run directory.
            (run/'pap-existed').write_text('yes' if prior else 'no')
            if prior:
                (run/'pap-original').write_bytes(prior[0])
            recovery.write_text(json.dumps({'run':str(run), 'existed':bool(prior),
                                           'mode':prior[1] if prior else 0o600,
                                           'uid':prior[2] if prior else 0,
                                           'gid':prior[3] if prior else 0,
                                           'temporary':temporary.decode()}))
            fd = os.open(pap_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, 'wb') as f:
                f.write(temporary)
            os.chmod(pap_path, 0o600)
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
        if upload_receiver is not None:
            upload_receiver.shutdown()
            upload_receiver.server_close()
        for timer in timers:
            timer.cancel()
        if bridge is not None:
            bridge.stop.set()
            for server in getattr(bridge, 'owned_servers', []):
                server.shutdown()
                server.server_close()
            bridge.stop_pppd()
            for capture in bridge.owned_captures:
                if capture.poll() is None:
                    capture.terminate()
                    try:
                        capture.wait(timeout=2)
                    except Exception:
                        capture.kill()
        if modified:
            if pap_path.exists() and pap_path.read_bytes() == temporary:
                if prior:
                    pap_path.write_bytes(prior[0])
                    os.chmod(pap_path, prior[1])
                    os.chown(pap_path, prior[2], prior[3])
                else:
                    pap_path.unlink()
                recovery.unlink(missing_ok=True)
                print('[lab] Temporary PAP configuration restored', flush=True)
            else:
                print('[lab] PAP file changed externally; restore skipped. Private recovery snapshot retained.', flush=True)
        print('[lab] Worker finished', flush=True)


if __name__ == '__main__':
    main()
