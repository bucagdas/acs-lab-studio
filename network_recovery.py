"""Owned, crash-safe PAP changes; never overwrite an external modification."""
import fcntl
import json
import os
from pathlib import Path

PAP_PATH = Path('/etc/ppp/pap-secrets')


def atomic_write(path, data, mode=0o600):
    tmp = path.with_name(path.name + '.tmp')
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(tmp, mode)
    os.replace(tmp, path)


class PapLease:
    def __init__(self, base, run=None, target=PAP_PATH):
        self.base, self.run, self.target = Path(base), run, Path(target)
        self.record = self.base / '.state/pap-recovery.json'
        self.lock = None

    def acquire(self):
        if self.lock is not None:
            return
        self.target.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.target.parent / '.acs-lab-pap.lock', os.O_RDWR | os.O_CREAT, 0o600)
        self.lock = os.fdopen(fd, 'r+b')
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            self.release()
            raise ValueError('Başka bir ACS ağ oturumu çalışıyor; kapanmasını bekleyin.')

    def release(self):
        if self.lock:
            self.lock.close()
            self.lock = None

    def prepare(self, temporary):
        self.acquire()
        if self.record.exists():
            raise ValueError('Bekleyen ağ kurtarma kaydı var; önce kurtarmayı tamamlayın.')
        if self.target.is_symlink():
            raise ValueError('PAP yolu sembolik bağlantı; değiştirilmedi.')
        prior = self.target.read_bytes() if self.target.exists() else None
        stat = self.target.stat() if prior is not None else None
        run = Path(self.run).resolve()
        if run.parent != (self.base / '.runs').resolve():
            raise ValueError('Geçersiz oturum dizini.')
        if prior is not None:
            atomic_write(run / 'pap-original', prior)
        atomic_write(run / 'pap-existed', b'yes' if prior is not None else b'no')
        data = dict(run=str(run), existed=prior is not None,
                    mode=(stat.st_mode & 0o777) if stat else 0o600,
                    uid=stat.st_uid if stat else os.geteuid(),
                    gid=stat.st_gid if stat else os.getegid(), temporary=temporary.decode())
        atomic_write(self.record, json.dumps(data).encode())
        atomic_write(self.target, temporary)
        return str(self.target)

    def restore(self):
        self.acquire()
        if not self.record.exists():
            return False
        try:
            record = json.loads(self.record.read_text())
            run = Path(record['run']).resolve()
            if run.parent != (self.base / '.runs').resolve() or type(record['existed']) is not bool:
                raise ValueError('Geçersiz kurtarma kaydı.')
            original = (run / 'pap-original').read_bytes() if record['existed'] else None
            temporary = record.get('temporary', '* * "" 10.116.13.101\n').encode()
            if self.target.is_symlink():
                raise ValueError('PAP yolu sembolik bağlantı; değiştirilmedi.')
            current = self.target.read_bytes() if self.target.exists() else None
            if current == original:
                # A prior cleanup may have restored the bytes before crashing.
                if original is not None:
                    os.chmod(self.target, int(record['mode']))
                    os.chown(self.target, int(record['uid']), int(record['gid']))
                self.record.unlink()
                return True
            if current != temporary:
                raise ValueError('Sistem PAP dosyası dışarıdan değişmiş; üzerine yazılmadı.')
            if original is None:
                self.target.unlink()
            else:
                atomic_write(self.target, original, int(record['mode']))
                os.chown(self.target, int(record['uid']), int(record['gid']))
            self.record.unlink()
            return True
        except (KeyError, TypeError, json.JSONDecodeError) as exc:
            raise ValueError('Ağ kurtarma kaydı okunamıyor; özel yedek korundu.') from exc


def recover(base, target=PAP_PATH):
    lease = PapLease(base, target=target)
    try:
        return lease.restore()
    finally:
        lease.release()
