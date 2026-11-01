"""Stage runtime code on WSL's Linux filesystem; preserve sessions/recovery."""
import argparse
import fcntl
import os
from pathlib import Path
import shutil
import subprocess
import sys
import venv

TARGET = Path('/var/lib/acs-lab-studio')


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
        for file in [*source.glob('*.py'), source / 'requirements.txt', source / 'README.md', source / 'WINDOWS.md', source / 'LICENSE']:
            if file.is_file() and not file.is_symlink():
                shutil.copyfile(file, target / file.name)
        for name in ('engines', 'static', 'windows'):
            destination = target / name
            destination.mkdir(exist_ok=True)
            for file in source.joinpath(name).iterdir():
                if file.is_file() and not file.is_symlink() and file.suffix in ('.py', '.html', '.css', '.js', '.sh'):
                    shutil.copyfile(file, destination / file.name)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--copy-only', action='store_true', help='Copy code without installing dependencies')
    parser.add_argument('source', type=Path)
    args = parser.parse_args(argv)
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise SystemExit('WSL root oturumu gerekli.')
    target = TARGET
    stage(args.source, target)
    if args.copy_only:
        return
    environment = target / '.venv'
    if not (environment / 'bin/python3').exists():
        venv.EnvBuilder(with_pip=True).create(environment)
    subprocess.run([str(environment / 'bin/python3'), '-m', 'pip', 'install',
                    '-r', str(target / 'requirements.txt')], check=True)


if __name__ == '__main__':
    main()
