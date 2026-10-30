"""Read-only WSL preflight. Does not capture, create interfaces or install."""
import importlib.util
from pathlib import Path
import platform
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from host_network import dependency_issues


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


if __name__ == '__main__':
    problems = issues()
    for item in problems:
        print('WSL: ' + item)
    if not problems:
        print('WSL PPP/TAP ve Python bağımlılıkları hazır. Canlı bağlantı henüz sınanmadı.')
    raise SystemExit(1 if problems else 0)
