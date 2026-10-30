import json
import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from lab import Lab, public_line, validate_settings


class FakeProcess:
    def __init__(self): self.signals=[]
    def poll(self): return None
    def send_signal(self, value): self.signals.append(value)


class LabTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.lab=Lab(Path(self.temp.name),preview=True)
        self.lab.settings={'mode':'write'}
    def tearDown(self):self.temp.cleanup()

    def journal(self,status='pending',verified=False):
        self.lab.journal.write_text(json.dumps({'status':status,'toggle_verified':verified,'original':'1'}))

    def test_evidence_required_for_success(self):
        self.lab.consume('[acs] received RPC=GetParameterValuesResponse namespace=test')
        self.assertNotEqual(self.lab.outcome,'success')
        self.journal()
        self.lab.consume('[write-test] WRITE_TEST_PASS_RESTORED')
        self.assertNotEqual(self.lab.outcome,'success')
        self.journal('restored',True)
        self.lab.consume('[write-test] WRITE_TEST_PASS_RESTORED')
        self.assertEqual(self.lab.outcome,'success')
        self.assertEqual(self.lab.steps['restore'],'done')

    def test_pending_write_cannot_be_stopped(self):
        self.lab.process=FakeProcess()
        self.lab.outcome='running'
        self.journal()
        self.assertFalse(self.lab.snapshot()['canStop'])
        with self.assertRaises(ValueError):self.lab.stop()
        self.assertFalse(self.lab.process.signals)

    def test_stop_safe_before_session_or_after_restore(self):
        self.lab.process=FakeProcess()
        self.lab.outcome='running'
        self.lab.stop()
        self.assertEqual(len(self.lab.process.signals),1)
        self.lab.process.signals=[]
        self.lab.outcome='running';self.lab.steps['inform']='done'
        with self.assertRaises(ValueError):self.lab.stop()
        self.journal('restored',True);self.lab.outcome='success'
        # Completed sessions can still be closed gracefully if their worker is alive.
        self.lab.stop();self.assertEqual(len(self.lab.process.signals),1)

    def test_readonly_finish_and_redaction(self):
        self.lab.settings={'mode':'readonly'}
        self.lab.consume('[acs] read-only diagnostic complete (8 value(s)); no SetParameterValues sent')
        self.assertEqual(self.lab.outcome,'success')
        self.assertIsNone(public_line('[pppd] PAP password=secret'))
        self.assertIsNone(public_line('[acs] Authorization: Basic secret'))
        self.assertIsNone(public_line('[acs] Password value: secret'))
        self.assertIsNone(public_line('  <soap:Body>secret'))
        self.assertNotIn('CP123',public_line('[acs] Inform from CP123; CWMP namespace=test'))

    def test_root_transfer_failure_is_visible_without_exposing_payload(self):
        line=public_line('[root-password] ROOT_PASSWORD_TRANSFER_FAILED: kod=9010')
        self.assertIn('9010',line)
        self.assertIn('başarısız',line)
        self.assertIsNone(public_line('[root-password] payload root:private-value'))
        self.assertIsNone(public_line('[root-password] password=private-value'))

    def test_parameter_readbacks_and_cursor(self):
        self.lab.consume("[acs] current value Device.Services.X_000E50_AccessManagement.SSH.CliUsers.1.Username = 'engineer'")
        first=self.lab.snapshot()
        self.assertEqual(first['values']['1.Username'],'engineer')
        self.assertFalse(self.lab.snapshot(first['cursor'])['events'])
        self.lab.consume("[write-test] changed value readback='0' verified=True; restoring original now")
        self.assertEqual(self.lab.snapshot()['values']['writeReadback'],'0')

    def test_corrupt_journal_is_not_treated_as_restored(self):
        self.lab.journal.write_text('{bad json')
        self.assertTrue(self.lab.snapshot()['pending'])
        self.assertEqual(self.lab.snapshot()['outcome'],'needs_restore')

    def test_preview_never_starts_network(self):
        self.assertTrue(any('Önizleme' in reason for reason in self.lab.readiness()))
        with self.assertRaises(ValueError):self.lab.start({'mode':'readonly','iface':'en11','mac':'60:d8:a4:97:16:d9'})
        self.assertIsNone(self.lab.process)

    def test_input_validation(self):
        good={'mode':'write','iface':'en11','mac':'60:d8:a4:97:16:d9','vlan':35,'duration':300}
        self.assertEqual(validate_settings(good),good)
        for change in [{'mode':'shell'},{'iface':'en11;id'},{'mac':'ff:ff:ff:ff:ff:ff'},
                       {'vlan':True},{'duration':0},{'duration':901}]:
            with self.subTest(change=change),self.assertRaises(ValueError):validate_settings(dict(good,**change))


if __name__=='__main__':unittest.main()
