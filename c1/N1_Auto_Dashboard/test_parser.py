import unittest
import tempfile
from pathlib import Path
from n1_core import parse_nfc_text, dataset_status, preliminary_assessment

NTAG = '''Filetype: Flipper NFC device
Version: 4
Device type: NTAG215
UID: 04 03 72 FD A0 31 02
ATQA: 00 44
SAK: 00
Pages total: 135
Pages read: 135
Page 0: 04 03 72 FD
Page 1: A0 31 02 89
Page 2: 1A 48 00 00
Page 3: E1 10 3E 00
Page 4: 03 11 D1 01
Page 5: 0D 54 02 65
Page 6: 6E 4E 31 5F
Page 7: 74 65 73 74
Page 8: 5F 30 33 FE
Page 130: 00 00 00 00
Page 131: 00 00 00 FF
'''

class TestParser(unittest.TestCase):
    def test_fields_and_ndef(self):
        x=parse_nfc_text(NTAG, 'test')
        self.assertEqual(x['uid'], '04 03 72 FD A0 31 02')
        self.assertEqual(x['uid_length'], 7)
        self.assertEqual(x['device_type'], 'NTAG215')
        self.assertEqual(x['ndef'][0]['value'], 'N1_test_03')
        self.assertEqual(x['factors']['Authentication']['value'], 'AUTH0 disabled')
    def test_incomplete_not_invented(self):
        x=parse_nfc_text('Filetype: Flipper NFC device\nDevice type: NTAG215\nUID: 04 03 72 FD A0 31 02\n')
        self.assertEqual(x['factors']['UID writable']['value'], 'Unverified')
        self.assertEqual(x['factors']['Authentication']['value'], 'Unknown')
    def test_real_trial_classification(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp) / 'Datasets'
            folder.mkdir()
            (folder / 'configs.csv').write_text('config_id,uid_writable\nC1,UNKNOWN\n')
            (folder / 'attacks.csv').write_text(
                'config_id,tier,repeat_no,compromised,time_to_compromise,censored\n'
                'C1,T2,1,1,15.18,0\n'
                'C1,T2,2,1,24.3,0\n'
                'C1,T2,3,1,,0\n'
            )
            summary = dataset_status(Path(tmp))
            self.assertEqual((summary['total'], summary['complete'], summary['events'], summary['censored']), (3,2,2,0))
    def test_preliminary_screening_observed_writable(self):
        card = parse_nfc_text(NTAG)
        report = preliminary_assessment(card)
        self.assertEqual(report['calibrated_score'], None)
        self.assertEqual(report['status'], 'CONFIGURATION REVIEW ADVISED')
        self.assertTrue(any(f['title'].startswith('NDEF write') and f['category'] == 'review' for f in report['findings']))
        self.assertTrue(any(f['title'].startswith('NTAG authentication') and f['category'] == 'review' for f in report['findings']))
        self.assertTrue(any(f['category'] == 'unknown' for f in report['findings']))

    def test_preliminary_screening_incomplete_never_safe(self):
        card = parse_nfc_text('Filetype: Flipper NFC device\nDevice type: NTAG215\nUID: 04 03 72 FD A0 31 02\n')
        report = preliminary_assessment(card)
        self.assertEqual(report['status'], 'EVIDENCE REVIEW')
        self.assertGreater(report['unknown_count'], 0)
        self.assertNotIn('SAFE', report['status'])
        self.assertIsNone(report['calibrated_score'])

    def test_reject_garbage(self):
        with self.assertRaises(ValueError): parse_nfc_text('random words only')

if __name__=='__main__': unittest.main()
