import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import types
from lab import validate_settings
from root_password import build_payload, install, validate_sts_layout, root_shell_service
import test_configure


class RootAccessTests(unittest.TestCase):
    def settings(self, enable=False):
        return {'root_password':'LocalTest_pass123','root_enable_lan_ssh':enable}

    def test_password_only_does_not_change_or_start_ssh(self):
        body=build_payload(self.settings()).decode()
        self.assertIn('|chpasswd',body)
        self.assertNotIn('uci',body)
        self.assertNotIn('dropbear',body)
        self.assertNotIn(root_shell_service(),body)

    def test_lan_option_targets_only_the_existing_lan_section(self):
        body=build_payload(self.settings(True)).decode()
        for option in ['enable=1','RootLogin=1','RootPasswordAuth=1','PasswordAuth=1']:
            self.assertIn('dropbear.lan.'+option,body)
        self.assertIn('set dropbear.lan.Interface=lan',body)
        self.assertIn('/etc/init.d/dropbear restart',body)
        self.assertNotIn('dropbear.wan',body)
        self.assertNotIn('dropbear.public_lan',body)

    def test_flags_and_password_are_strictly_validated(self):
        base={'mode':'root_password','iface':'en11','mac':'02:00:00:00:00:02','root_password_ack':True,'root_password':'LocalTest_pass123','root_password_confirm':'LocalTest_pass123'}
        self.assertFalse(validate_settings(base)['root_enable_lan_ssh'])
        self.assertTrue(validate_settings({**base,'root_enable_lan_ssh':True})['root_enable_lan_ssh'])
        for flag in ['1',1,None,{}]:
            with self.subTest(flag=flag),self.assertRaises(ValueError):validate_settings({**base,'root_enable_lan_ssh':flag})
        for bad in ['safe;touch /tmp/x', 'safe$(id)123456', 'line\nbreak123456']:
            with self.assertRaises(ValueError):build_payload({'root_password':bad,'root_enable_lan_ssh':True})

    def test_old_nested_service_path_is_rejected_before_any_transfer(self):
        old=b'reboot off\n/etc/init.d/x;echo${IFS}root:fixture|chpasswd&&/etc/init.d/dropbear${IFS}restart\n'
        with self.assertRaises(ValueError):validate_sts_layout(old)
        for enabled in [False,True]:
            body=build_payload(self.settings(enabled))
            self.assertEqual(validate_sts_layout(body),body)
        with self.assertRaises(ValueError):validate_sts_layout(b'/etc/init.d/dropbear arbitrary-action\n')

    def test_native_sts_services_execute_against_stubs_without_touching_host_network(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);log=root/'calls'
            passwd=root/'passwd'
            passwd.write_text('root:x:0:0:root:/root:/bin/restricted_shell\nengineer:x:1001:1001:engineer:/home/engineer:/bin/restricted_shell\n')
            sed_args = "-i ''" if sys.platform == 'darwin' else '-i'
            scripts={
                'chpasswd':'#!/bin/sh\nread -r entry\n[ "$entry" = root:LocalTest_pass123 ]\n',
                'uci':'#!/bin/sh\necho "uci $*" >> "$CALLS"\n',
                'logger':'#!/bin/sh\necho "logger $*" >> "$CALLS"\n',
                'dropbear':'#!/bin/sh\necho "dropbear $*" >> "$CALLS"\n',
                # Run real sed/grep against a temporary passwd fixture only.
                'sed': '#!/bin/sh\n[ "$1" = -i ] && [ "$3" = /etc/passwd ] || exit 90\nexec /usr/bin/sed '+sed_args+' "$2" "$PASSWD_FIXTURE"\n',
                'grep': '#!/bin/sh\n[ "$1" = -q ] && [ "$3" = /etc/passwd ] || exit 90\nexec /usr/bin/grep "$1" "$2" "$PASSWD_FIXTURE"\n',
            }
            for name,body in scripts.items():
                p=root/name;p.write_text(body);p.chmod(0o700)
            settings=[];services=[]
            for line in build_payload(self.settings(True)).decode().splitlines():
                if line.startswith('set '):settings.append('uci '+line)
                elif line.startswith('/etc/init.d/x;'):services.append(line.split(';',1)[1])
                elif line.startswith('/etc/init.d/dropbear '):services.append(line.replace('/etc/init.d/dropbear',str(root/'dropbear')))
            # STS commits native configuration before executing queued services.
            body='\n'.join(settings+['uci commit dropbear']+services)
            env={**os.environ,'PATH':str(root)+':/usr/bin:/bin','CALLS':str(log),'PASSWD_FIXTURE':str(passwd)}
            subprocess.run(['/bin/sh','-c',body],env=env,check=True,timeout=3,capture_output=True)
            transcript=log.read_text()
            self.assertIn('uci set dropbear.lan.enable=1',transcript)
            self.assertIn('dropbear restart',transcript)
            self.assertIn('CHPASS_OK',transcript)
            self.assertIn('ROOT_SHELL_READY',transcript)
            self.assertEqual(passwd.read_text(),'root:x:0:0:root:/root:/bin/ash\nengineer:x:1001:1001:engineer:/home/engineer:/bin/restricted_shell\n')
            self.assertLess(transcript.index('uci commit dropbear'),transcript.index('CHPASS_OK'))
            self.assertLess(transcript.index('CHPASS_OK'),transcript.index('dropbear restart'))
            self.assertLess(transcript.index('ROOT_SHELL_READY'),transcript.index('dropbear restart'))
            # The shell change is idempotent, and a missing root record must fail.
            shell_command=root_shell_service().split(';',1)[1]
            subprocess.run(['/bin/sh','-c',shell_command],env=env,check=True,timeout=3,capture_output=True)
            passwd.write_text('engineer:x:1001:1001:engineer:/home/engineer:/bin/restricted_shell\n')
            failed=subprocess.run(['/bin/sh','-c',shell_command],env=env,timeout=3,capture_output=True)
            self.assertEqual(failed.returncode,1)
            self.assertIn('ROOT_SHELL_FAILED',log.read_text())
            self.assertEqual(passwd.read_text(),'engineer:x:1001:1001:engineer:/home/engineer:/bin/restricted_shell\n')

    def test_report_records_request_but_never_claims_ssh_is_open(self):
        fixture=test_configure.ConfigureTests();fixture.setUp()
        try:
            server=types.SimpleNamespace(daemon_threads=False,serve_forever=lambda:None)
            settings=self.settings(True)
            with patch('root_password.ThreadingHTTPServer',return_value=server):
                install(fixture.engine,settings,fixture.run,'10.116.13.101','10.116.13.100')
            report=(fixture.run/'root-password-transfer.json').read_text()
            self.assertTrue(json.loads(report)['lanSshRequested'])
            self.assertEqual(json.loads(report)['status'],'waiting')
            self.assertNotIn('LocalTest_pass123',report)
            self.assertEqual(settings['root_password'],'')
        finally:fixture.tearDown()
