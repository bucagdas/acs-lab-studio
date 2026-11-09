"""Read-only WSL preflight. Does not capture, create interfaces or install."""
import argparse
import importlib.util
import os
from pathlib import Path
import platform
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from host_network import dependency_issues


def prepare():
    """Reload only the required WSL drivers after its VM has restarted."""
    if platform.system() != 'Linux' or 'wsl2' not in platform.release().lower() or os.geteuid() != 0:
        raise RuntimeError('Sürücü hazırlığı WSL 2 root oturumu gerektirir.')
    for module in ('tun', 'ppp_async'):
        try:
            result = subprocess.run(['modprobe', module], capture_output=True, timeout=10)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RuntimeError('WSL sürücüsü yüklenemedi: ' + module + '. WINDOWS.md dosyasına bakın.') from exc
        if result.returncode:
            raise RuntimeError('WSL çekirdeğinde sürücü yüklenemedi: ' + module + '. WINDOWS.md dosyasına bakın.')


def issues():
    result = dependency_issues()
    if platform.system() != 'Linux' or 'wsl2' not in platform.release().lower():
        result.append('Windows arka ucu WSL 2 gerektirir.')
    if not Path('/dev/net/tun').exists():
        result.append('WSL TUN/TAP sürücüsü yok; tun modülünü kontrol edin.')
    if not Path('/sys/module/ppp_async').exists():
        result.append('WSL ppp_async modülü yüklü değil; Kurulum.cmd çalıştırın.')
    if importlib.util.find_spec('scapy') is None:
        result.append('WSL Python ortamında Scapy yok.')
    return result


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--prepare', action='store_true')
    args = parser.parse_args(argv)
    if args.prepare:
        try:
            prepare()
        except RuntimeError as exc:
            print('WSL: ' + str(exc))
            return 1
    problems = issues()
    for item in problems:
        print('WSL: ' + item)
    if not problems:
        print('WSL PPP/TAP ve Python bağımlılıkları hazır. Canlı bağlantı henüz sınanmadı.')
    return 1 if problems else 0


if __name__ == '__main__':
    raise SystemExit(main())
