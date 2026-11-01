"""Optional real parser check; runnable alone on native Windows Python."""
import base64
from pathlib import Path
import shutil
import subprocess
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from windows.capture import ADAPTER_SCRIPT


POWERSHELL = shutil.which('powershell.exe') or shutil.which('pwsh')


class PowerShellSyntaxTests(unittest.TestCase):
    @unittest.skipUnless(POWERSHELL, 'Real PowerShell parser is not installed on this host')
    def test_adapter_inventory_parses_without_running_commands(self):
        encoded = base64.b64encode(ADAPTER_SCRIPT.encode('utf-16-le')).decode('ascii')
        # ParseInput does not execute Get-NetAdapter or change an adapter.
        script = '''$source = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('%s'))
$tokens = $null
$errors = $null
[System.Management.Automation.Language.Parser]::ParseInput($source, [ref]$tokens, [ref]$errors) | Out-Null
if ($errors.Count -gt 0) { $errors | ForEach-Object { $_.Message }; exit 1 }
''' % encoded
        command = base64.b64encode(script.encode('utf-16-le')).decode('ascii')
        result = subprocess.run([POWERSHELL, '-NoProfile', '-NonInteractive', '-EncodedCommand', command],
                                capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
