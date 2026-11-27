import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from modules.discovery import parse_identity_payload
from modules.security import REVIEW_STATUSES, SURFACES, SecurityAssessment
from reports.report import ReportGenerator
from test_discovery import identity_payload


class SecurityTests(unittest.TestCase):
    def test_catalog_unique_and_unassessed(self):
        catalog = SecurityAssessment().catalog()
        self.assertEqual(len({entry['identifier'] for entry in catalog}), len(SURFACES))
        self.assertTrue(all(entry['status'] == 'Not assessed' for entry in catalog))
        self.assertGreaterEqual(len(catalog), 14)

    def test_review_requires_evidence(self):
        assessment = SecurityAssessment()
        for status in REVIEW_STATUSES[1:]:
            with self.subTest(status=status), self.assertRaises(ValueError):
                assessment.record_review('EIP-01', status, ' ')
        for identifier, status in (('invalid', 'Not assessed'), ('EIP-01', 'Secure')):
            with self.assertRaises(ValueError):
                assessment.record_review(identifier, status, 'Notes')
        with self.assertRaises(ValueError):
            assessment.record_review('EIP-01', 'Needs review', 'x' * 10001)
        assessment.record_review('EIP-01', 'Needs review', 'ACL review pending')
        self.assertEqual(assessment.catalog()[0]['evidence'], 'ACL review pending')

    def test_observations_do_not_claim_vulnerability(self):
        assessment = SecurityAssessment()
        self.assertEqual(assessment.observations([]), [])
        result = assessment.observations(parse_identity_payload(identity_payload()))
        self.assertIn('not a confirmed vulnerability', result[0]['classification'])
        self.assertIn('Does not establish', result[0]['limits'])
        self.assertEqual(assessment.catalog()[0]['status'], 'Not assessed')

    def test_pdf_and_json_reports_and_sample_label(self):
        generator = ReportGenerator()
        report = generator.build('192.0.2.10', 'Lab / ticket 123', False, 'sample',
                                 'Synthetic data', parse_identity_payload(identity_payload()),
                                 SecurityAssessment())
        with tempfile.TemporaryDirectory() as directory:
            pdf_path = Path(directory) / 'report.pdf'
            generator.save(str(pdf_path), report)
            self.assertTrue(pdf_path.read_bytes().startswith(b'%PDF-'))
            json_path = Path(directory) / 'reports' / 'ethernetip' / 'report.json'
            generator.save(str(json_path), report)
            self.assertEqual(json.loads(json_path.read_text(encoding='utf-8')), report)
        with patch('reports.pdf.SimpleDocTemplate') as document:
            generator.save('report.pdf', report)
        story = document.return_value.build.call_args.args[0]
        content = '\n'.join(item.getPlainText() for item in story if hasattr(item, 'getPlainText'))
        self.assertIn('SYNTHETIC SAMPLE DATA', content)
        self.assertIn('Lab PLC', content)
        self.assertIn('No timed live operation is recorded', content)
        self.assertIn('ETH-ENUM-001', content)
        self.assertIn('ETH-LOG-004', content)
        self.assertIn('Abbreviations', content)
        self.assertIn('CIP: Common Industrial Protocol', content)
        self.assertEqual(report['scope']['mode'], 'sample')
        self.assertFalse(report['scope']['authorization_attested'])
        self.assertEqual(len(report['attack_surface_reviews']), len(SURFACES))

    def test_pdf_suite_contains_times_results_and_packet_evidence(self):
        from modules.live_tests import LiveTestRunner
        from test_live_tests import DeviceSocket

        with patch('core.connection.socket.create_connection', return_value=DeviceSocket()), patch(
            'threading.Event.wait', return_value=False
        ):
            run = LiveTestRunner().run('192.0.2.10', 'Lab / ticket', True, case_id='CIP-01')
        generator = ReportGenerator()
        report = generator.build('192.0.2.10', 'Lab / ticket', True, 'live', run['outcome'],
                                 [], SecurityAssessment(), run['started_at_utc'], live_run=run)
        with patch('reports.pdf.SimpleDocTemplate') as document:
            generator.save('report.pdf', report)
        story = document.return_value.build.call_args.args[0]
        content = '\n'.join(item.getPlainText() for item in story if hasattr(item, 'getPlainText'))
        self.assertIn(run['started_at_utc'], content)
        self.assertIn(run['completed_at_utc'], content)
        self.assertIn('CIP-01 - Identity instance 1 / vendor_id', content)
        self.assertIn('Status: observed', content)
        self.assertIn('Status: not_run', content)
        self.assertIn('ETH-ENUM-001', content)
        self.assertIn('partial_live_read_only', content)
        self.assertIn(run['evidence_sha256'], content)
        self.assertIn(run['exchanges'][0]['request_hex'], content)

    def test_report_rejects_unsupported_extension(self):
        with self.assertRaisesRegex(ValueError, 'pdf or .json extension'):
            ReportGenerator().save('report.txt', {})

    def test_pdf_preserves_unsupported_unicode_as_escaped_text(self):
        report = ReportGenerator().build('192.0.2.10', 'Lab \u0915 / ticket', False, 'sample',
                                         'Synthetic data', [], SecurityAssessment())
        with patch('reports.pdf.SimpleDocTemplate') as document:
            ReportGenerator().save('report.pdf', report)
        story = document.return_value.build.call_args.args[0]
        content = '\n'.join(item.getPlainText() for item in story if hasattr(item, 'getPlainText'))
        self.assertIn(r'Lab \u0915 / ticket', content)
        self.assertIn('Unicode escapes', content)

    def test_report_scope_validation(self):
        for target, operator, authorized, mode in (
            ('example.com', 'Lab', True, 'live'),
            ('192.0.2.10', '', True, 'live'),
            ('192.0.2.10', 'Lab', False, 'live'),
            ('192.0.2.10', 'Lab', True, 'invalid'),
        ):
            with self.subTest(mode=mode, target=target), self.assertRaises(ValueError):
                ReportGenerator().build(target, operator, authorized, mode, 'test', [], SecurityAssessment())

    def test_suite_evidence_cannot_be_relabelled(self):
        run = {'target': '192.0.2.10', 'operator': 'Lab', 'authorization_attested': True}
        for target, operator, mode in (('192.0.2.11', 'Lab', 'live'),
                                       ('192.0.2.10', 'Other ticket', 'live'),
                                       ('192.0.2.10', 'Lab', 'sample')):
            with self.assertRaisesRegex(ValueError, 'match'):
                ReportGenerator().build(target, operator, True, mode, 'Test', [], SecurityAssessment(), live_run=run)


if __name__ == '__main__':
    unittest.main()