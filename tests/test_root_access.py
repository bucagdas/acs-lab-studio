import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import types
from lab import validate_settings
from root_password import build_payload, install
import test_configure


class RootAccessTests(unittest.TestCase):
    def settings(self, enable=False):
        return {'root_password':'LocalTest_pass123','root_enable_lan_ssh':enable}

    def test_password_only_does_not_change_or_start_ssh(self):
        body=build_payload(self.settings()).decode()
        self.assertIn('|chpasswd',body)
        self.assertNotIn('uci',body)
        self.assertNotIn('dropbear',body)

    def test_lan_option_targets_only_the_existing_lan_section(self):
        body=build_payload(self.settings(True)).decode()
        for option in ['enable=1','RootLogin=1','RootPasswordAuth=on','PasswordAuth=on']:
            self.assertIn('dropbear.lan.'+option,body)
        self.assertIn('dropbear.lan.Interface|grep${IFS}-qx${IFS}lan',body)
        self.assertIn('/etc/init.d/dropbear${IFS}restart',body)
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

    def test_fixed_script_executes_against_stub_services_without_touching_host_network(self):
        for lan in ['lan','wan']:
            with self.subTest(interface=lan),tempfile.TemporaryDirectory() as folder:
                root=Path(folder);log=root/'calls'
                scripts={
                    'chpasswd':'#!/bin/sh\nread -r entry\n[ "$entry" = root:LocalTest_pass123 ]\n',
                    'uci':'#!/bin/sh\necho "uci $*" >> "$CALLS"\ncase "$*" in "-q get dropbear.lan") echo dropbear;; "-q get dropbear.lan.Interface") echo "$LAN_INTERFACE";; esac\n',
                    'logger':'#!/bin/sh\necho "logger $*" >> "$CALLS"\n',
                    'dropbear':'#!/bin/sh\necho "dropbear $*" >> "$CALLS"\n',
                }
                for name,body in scripts.items():
                    p=root/name;p.write_text(body);p.chmod(0o700)
                body=build_payload(self.settings(True)).decode().split('/etc/init.d/x;',1)[1]
                body=body.replace('/etc/init.d/dropbear',str(root/'dropbear'))
                env={**os.environ,'PATH':str(root)+':/usr/bin:/bin','CALLS':str(log),'LAN_INTERFACE':lan}
                subprocess.run(['/bin/sh','-c',body],env=env,check=True,timeout=3,capture_output=True)
                transcript=log.read_text()
                if lan=='lan':
                    self.assertIn('uci set dropbear.lan.enable=1',transcript)
                    self.assertIn('dropbear restart',transcript)
                    self.assertIn('ROOT_ACCESS_REQUEST_OK',transcript)
                else:
                    self.assertNotIn('uci set',transcript)
                    self.assertNotIn('dropbear restart',transcript)
                    self.assertIn('SETUP_FAIL',transcript)

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
