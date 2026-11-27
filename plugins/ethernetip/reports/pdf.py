import json
import textwrap
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer


ABBREVIATIONS = (
    ('ACD', 'Address Conflict Detection'),
    ('ACL', 'Access Control List'),
    ('CIP', 'Common Industrial Protocol'),
    ('CISA', 'Cybersecurity and Infrastructure Security Agency'),
    ('CLI', 'Command-line interface'),
    ('CPF', 'Common Packet Format'),
    ('CVE', 'Common Vulnerabilities and Exposures'),
    ('DoS', 'Denial of Service'),
    ('DTLS', 'Datagram Transport Layer Security'),
    ('EDS', 'Electronic Data Sheet'),
    ('EIP / ENIP / EtherNet/IP', 'EtherNet Industrial Protocol'),
    ('FUZ', 'Fuzz test identifier'),
    ('HTTP / HTTPS', 'Hypertext Transfer Protocol / HTTP Secure'),
    ('ICS / OT', 'Industrial Control Systems / Operational Technology'),
    ('IEC', 'International Electrotechnical Commission'),
    ('I/O', 'Input / Output'),
    ('IP / IPv4', 'Internet Protocol / Internet Protocol version 4'),
    ('IT', 'Information Technology'),
    ('JSON', 'JavaScript Object Notation'),
    ('NIST', 'National Institute of Standards and Technology'),
    ('ODVA', 'ODVA, the industrial automation standards organization'),
    ('PDF', 'Portable Document Format'),
    ('PLC', 'Programmable Logic Controller'),
    ('SHA-256', 'Secure Hash Algorithm, 256-bit'),
    ('SNMP', 'Simple Network Management Protocol'),
    ('SRS', 'System Requirements Specification'),
    ('SSH', 'Secure Shell'),
    ('TCP / UDP', 'Transmission Control Protocol / User Datagram Protocol'),
    ('TLS', 'Transport Layer Security'),
    ('UTC', 'Coordinated Universal Time'),
    ('VLAN', 'Virtual Local Area Network'),
)


def _value(value) -> str:
    if value is None:
        return 'Not available'
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, ensure_ascii=True, sort_keys=True)
    if isinstance(value, bool):
        return 'Yes' if value else 'No'
    return ''.join(
        f'\\u{ord(char):04x}' if ord(char) < 32 and char != '\n'
        else char.encode('cp1252', 'backslashreplace').decode('cp1252')
        for char in str(value)
    )


def _footer(canvas, document) -> None:
    canvas.saveState()
    canvas.setFont('Helvetica', 8)
    canvas.drawRightString(A4[0] - 18 * mm, 12 * mm, f'Page {document.page}')
    canvas.restoreState()


def save_pdf(path: str, report: dict) -> None:
    styles = getSampleStyleSheet()
    styles['Title'].textColor = colors.HexColor('#075c73')
    styles['Title'].alignment = TA_CENTER
    styles['Heading1'].textColor = colors.HexColor('#075c73')
    styles['BodyText'].spaceAfter = 4
    document = SimpleDocTemplate(path, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm,
                                 topMargin=16 * mm, bottomMargin=18 * mm)
    story = []

    def text(value, style='BodyText'):
        content = escape(_value(value)).replace('\n', '<br/>')
        story.append(Paragraph(content or ' ', styles[style]))

    def heading(value):
        text(value, 'Heading1')

    def field(name, value):
        text(f'{name}: {_value(value)}')

    def fields(values, omitted=()):
        for key, value in values.items():
            if key not in omitted:
                field(key.replace('_', ' ').capitalize(), value)

    text('EtherNet/IP Assessment Report', 'Title')
    text('Observations are not automatic security, vulnerability, or compliance verdicts.')
    text('Characters outside the report font are shown as Unicode escapes to preserve their values.')
    scope = report['scope']
    run = report['live_test_run']

    heading('Assessment and timestamps')
    field('Generated at (UTC)', report['generated_at_utc'])
    field('Start (UTC)', run.get('started_at_utc') if run else scope.get('observed_at_utc'))
    field('Stop after completion or cleanup (UTC)', run.get('completed_at_utc') if run else scope.get('completed_at_utc'))
    if not run and not scope.get('observed_at_utc'):
        text('No timed live operation is recorded for this assessment.')
    fields(scope, omitted=('observed_at_utc', 'completed_at_utc'))
    if scope['mode'] == 'sample':
        text('SYNTHETIC SAMPLE DATA: not evidence from a real device.')

    heading('Device details')
    if not report['identities']:
        text('No device identity was obtained; device details are unavailable.')
    for index, identity in enumerate(report['identities'], 1):
        text(f'Device identity {index}', 'Heading2')
        fields(identity)
    if run and run.get('attribute_values'):
        text('Identity attributes obtained by CIP reads', 'Heading2')
        fields(run['attribute_values'])

    heading('Test results')
    if not run:
        text('No live test suite results are available for this assessment.')
    else:
        field('Suite', run['suite'])
        field('Run outcome', run['outcome'])
        field('Stop reason', run.get('stop_reason'))
        field('Duration (ms)', run.get('elapsed_ms'))
        field('Selected cases', run.get('selected_cases') or run.get('selected_case') or 'Full suite')
        field('Supporting cases', run.get('supporting_cases', []))
        if 'fuzz_authorization_attested' in run:
            field('Fuzz authorization attested', run['fuzz_authorization_attested'])
        field('Limits', run.get('limits'))
        for result in run['test_results']:
            text(f"{result['id']} - {result['title']}", 'Heading2')
            field('Status', result['status'])
            field('Detail', result['detail'])
            fields(result, omitted=('id', 'title', 'status', 'detail'))
        if run.get('consistency_observations'):
            text('Identity consistency observations', 'Heading2')
            for item in run['consistency_observations']:
                fields(item)
                story.append(Spacer(1, 3 * mm))

    heading('Spreadsheet cases and coverage')
    text('Coverage describes what is implemented, not a pass/fail result. Related runnable '
         'tests may cover only part of a spreadsheet case.')
    results = {item['id']: item['status'] for item in run['test_results']} if run else {}
    for item in report['coverage_matrix']:
        if not item.get('source'):
            continue
        text(f"{item['id']} - {item['area']}", 'Heading2')
        field('Coverage', item['coverage'])
        field('Category', item['category'])
        field('SRS mapping', item['srs_mapping'])
        field('EtherNet/IP object', item['cip_object'])
        field('Related runnable tests', item['related_live_tests'])
        if item['related_live_tests']:
            field('Related test statuses', {key: results.get(key, 'not_run') for key in item['related_live_tests']})
        field('Limitations', item['limits'])

    heading('Other coverage and limitations')
    for item in report['coverage_matrix']:
        if not item.get('source'):
            text(f"{item['id']} - {item['area']}: {item['coverage']} | {item['limits']}")
    for limitation in report['limitations']:
        text(limitation)

    heading('Observations and developer review candidates')
    if not report['observations'] and not report['developer_review_candidates']:
        text('None recorded. This does not establish that the target is secure.')
    for item in report['observations'] + report['developer_review_candidates']:
        fields(item)
        story.append(Spacer(1, 3 * mm))

    heading('Attack surface reviews')
    for item in report['attack_surface_reviews']:
        text(f"{item['identifier']} - {item['title']}", 'Heading2')
        fields(item, omitted=('identifier', 'title'))

    heading('Packet evidence')
    if not run or not run['exchanges']:
        text('No packet exchange evidence was recorded.')
    else:
        field('Evidence SHA-256', run.get('evidence_sha256'))
        text('The digest is not a digital signature. Packet bytes are sensitive evidence.')
        for index, exchange in enumerate(run['exchanges']):
            text(f'Exchange {index}', 'Heading2')
            for key, value in exchange.items():
                if key in ('request_hex', 'response_hex') and value:
                    text(f"{key.replace('_', ' ').capitalize()}:")
                    for part in textwrap.wrap(value, width=96):
                        text(part)
                else:
                    field(key.replace('_', ' ').capitalize(), value)

    heading('Reproduction and references')
    fields(report['reproduction'])
    fields(report['references'])

    heading('Abbreviations')
    for abbreviation, meaning in ABBREVIATIONS:
        field(abbreviation, meaning)

    document.build(story, onFirstPage=_footer, onLaterPages=_footer)
