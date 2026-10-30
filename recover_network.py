#!/usr/bin/env python3
"""Restore only the PAP file owned by an inactive ACS Lab session."""
import fcntl
import os
from pathlib import Path
from network_recovery import recover


def main():
    if os.geteuid() != 0:
        raise SystemExit('Çalıştırma: sudo python3 recover_network.py')
    base = Path(__file__).resolve().parent
    with (base / '.state/app.lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SystemExit('Studio açık. Panelde Ağ ayarını kurtar düğmesini kullanın veya önce uygulamayı kapatın.')
        try:
            restored = recover(base)
        except (OSError, ValueError) as exc:
            raise SystemExit(str(exc))
    print('Geçici ağ ayarı geri alındı.' if restored else 'Bekleyen ağ kurtarma kaydı yok.')


if __name__ == '__main__':
    main()
