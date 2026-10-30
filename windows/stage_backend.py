"""Stage runtime code on WSL's Linux filesystem; preserve sessions/recovery."""
import fcntl
import os
from pathlib import Path
import shutil
import subprocess
import sys
import venv


def stage(source, target):
    source, target = Path(source).resolve(), Path(target).resolve()
    target.mkdir(parents=True, exist_ok=True, mode=0o700)
    state = target / '.state'
    state.mkdir(exist_ok=True, mode=0o700)
    with (state / 'app.lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('Önce çalışan ACS Lab Studio oturumunu kapatın.')
        for file in [*source.glob('*.py'), source / 'requirements.txt', source / 'README.md', source / 'WINDOWS.md']:
            if file.is_file() and not file.is_symlink():
                shutil.copyfile(file, target / file.name)
        for name in ('engines', 'static', 'windows'):
            destination = target / name
            destination.mkdir(exist_ok=True)
            for file in source.joinpath(name).iterdir():
                if file.is_file() and not file.is_symlink() and file.suffix in ('.py', '.html', '.css', '.js', '.sh'):
                    shutil.copyfile(file, destination / file.name)


def main():
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise SystemExit('WSL root oturumu gerekli.')
    source = Path(sys.argv[1]).resolve()
    target = Path('/var/lib/acs-lab-studio')
    stage(source, target)
    environment = target / '.venv'
    if not (environment / 'bin/python3').exists():
        venv.EnvBuilder(with_pip=True).create(environment)
    subprocess.run([str(environment / 'bin/python3'), '-m', 'pip', 'install',
                    '-r', str(target / 'requirements.txt')], check=True)


if __name__ == '__main__':
    main()
