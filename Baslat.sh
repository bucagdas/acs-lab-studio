#!/bin/sh
set -eu
cd "$(dirname "$0")"
case "$(uname -s)" in
    Darwin|Linux) ;;
    *) echo 'Windows için Baslat.cmd kullanın.' >&2; exit 1 ;;
esac
# Linux distributions often keep pppd/ip under sbin.
PATH="$PATH:/usr/local/sbin:/usr/sbin:/sbin"
export PATH
if [ -x .venv/bin/python3 ]; then
    ACS_PYTHON="$PWD/.venv/bin/python3"
else
    ACS_PYTHON=$(command -v python3) || {
        echo 'Python 3.9 veya üzerini kurun; README’ye bakın.' >&2
        exit 1
    }
fi
if [ "$(id -u)" -eq 0 ]; then
    exec "$ACS_PYTHON" app.py "$@"
fi
exec sudo "$ACS_PYTHON" app.py "$@"
