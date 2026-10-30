#!/bin/sh
set -eu
case "$(uname -r)" in
    *WSL2*|*wsl2*) ;;
    *) echo 'WSL 2 gerekli.' >&2; exit 1 ;;
esac
if [ "$(id -u)" -ne 0 ]; then
    echo 'WSL kurulumu root olarak başlatılmalı.' >&2
    exit 1
fi
if ! command -v apt-get >/dev/null 2>&1; then
    echo 'Otomatik hazırlık Ubuntu/Debian içindir. WINDOWS.md dosyasına bakın.' >&2
    exit 1
fi
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y python3 python3-venv ppp iproute2 kmod openssl tcpdump
# PPP and TUN are the only WSL kernel drivers needed. Physical NIC drivers
# stay on Windows, so both USB and built-in Ethernet use the same path.
modprobe tun
modprobe ppp_async
python3 "$1/windows/stage_backend.py" "$1"
/var/lib/acs-lab-studio/.venv/bin/python3 /var/lib/acs-lab-studio/windows/check_backend.py
