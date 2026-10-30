#!/usr/bin/env python3
"""Restore only a PAP file left by this tool after a crash."""
import json
import os
from pathlib import Path

base=Path(__file__).resolve().parent
if os.geteuid()!=0:
    raise SystemExit('Çalıştırma: sudo python3 recover_network.py')
state=base/'.state'/'pap-recovery.json'
if not state.exists():
    raise SystemExit('Bekleyen PAP kurtarma kaydı yok.')
record=json.loads(state.read_text())
run=Path(record['run']).resolve()
if run.parent != (base/'.runs').resolve():
    raise SystemExit('Kurtarma kaydı geçersiz; otomatik işlem yapılmadı.')
target=Path('/etc/ppp/pap-secrets')
temporary=record.get('temporary','* * "" 10.116.13.101\n').encode()
if target.is_symlink() or (target.exists() and target.read_bytes()!=temporary):
    raise SystemExit('Sistem PAP dosyası dışarıdan değişmiş. Otomatik üzerine yazılmadı; özel yedeği inceleyin.')
if record['existed']:
    target.write_bytes((run/'pap-original').read_bytes())
    os.chmod(target,record['mode'])
    os.chown(target,record['uid'],record['gid'])
elif target.exists():
    target.unlink()
state.unlink()
print('Bu aracın geçici PAP ayarı geri alındı.')
