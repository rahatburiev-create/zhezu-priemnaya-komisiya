"""Real-server intake/payment/receipt checks, isolated from the shipped database."""
import base64
import concurrent.futures
import copy
from decimal import Decimal
import hashlib
import http.client
import json
import os
import pathlib
import secrets
import shutil
import socket
import subprocess
import tempfile
import time
import uuid

ROOT = pathlib.Path(__file__).resolve().parents[1]
COMMAND = ['node', str(ROOT / 'server.js')]
passed = 0


def check(condition, label):
    global passed
    if not condition:
        raise AssertionError(label)
    passed += 1


class Server:
    def __init__(self, folder):
        self.folder = pathlib.Path(folder)
        self.db = self.folder / 'database.txt'
        self.log = open(self.folder / 'server.log', 'w', encoding='utf8')
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            self.port = sock.getsockname()[1]
        self.origin = 'http://127.0.0.1:' + str(self.port)
        self.process = None

    def request(self, route, method='GET', data=None, cookie='', origin=True,
                raw=None, content_type='application/json'):
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=25)
        headers = {}
        if origin:
            headers['Origin'] = self.origin if origin is True else origin
        if cookie:
            headers['Cookie'] = cookie
        payload = raw if raw is not None else (
            json.dumps(data, ensure_ascii=False).encode('utf8') if data is not None else None)
        if payload is not None:
            headers['Content-Type'] = content_type
        connection.request(method, route, payload, headers)
        response = connection.getresponse()
        result = response.read()
        status = response.status
        response_headers = {key.lower(): value for key, value in response.getheaders()}
        connection.close()
        if 'application/json' in response_headers.get('content-type', ''):
            result = json.loads(result)
        return status, result, response_headers

    def start(self):
        self.process = subprocess.Popen(COMMAND + ['--db', str(self.db), '--port', str(self.port)],
                                        stdout=self.log, stderr=self.log)
        for _ in range(120):
            try:
                if self.request('/api/auth/me')[0] == 200:
                    return
            except OSError:
                pass
            if self.process.poll() is not None:
                self.log.flush()
                raise RuntimeError('Server failed: ' + (self.folder / 'server.log').read_text())
            time.sleep(.05)
        raise RuntimeError('Server startup timeout')

    def stop(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            self.process.wait(timeout=15)
        self.process = None

    def restart(self):
        self.stop()
        self.start()

    def close(self):
        self.stop()
        self.log.close()


def cookie(headers):
    return headers['set-cookie'].split(';')[0]


def expect(response, status, label):
    check(response[0] == status, label + ': ' + repr(response[:2]))
    return response[1]


def seed_legacy_database(target):
    """A pre-upgrade record makes compatibility observable, with no real people."""
    source = json.loads((ROOT / 'database.txt').read_text(encoding='utf-8-sig'))
    fixture = {
        'version': 1,
        'programs': source['programs'],
        'users': [], 'sessions': [], 'tasks': [],
        'applicants': [{
            'id': str(uuid.uuid4()), 'userId': '', 'name': 'Legacy Test Applicant',
            'phone': '', 'email': 'legacy@example.invalid', 'program': '',
            'level': 'Бакалавриат', 'message': 'Before intake upgrade',
            'score': None, 'status': 'review',
            'docs': [True, False, True, False, True], 'note': 'Keep this legacy note',
            'consentAt': '2026-01-01T10:00:00.000Z',
            'createdAt': '2026-01-01T10:00:00.000Z',
            'updatedAt': '2026-01-01T10:00:00.000Z',
        }],
    }
    target.write_text(json.dumps(fixture, ensure_ascii=False, indent=2), encoding='utf8')
    return fixture['applicants'][0]


def bootstrap(server, password):
    result = subprocess.run(COMMAND + ['--setup-admin', '--db', str(server.db),
                                      '--login', 'intake.admin', '--password-stdin'],
                            input=password + '\n', text=True, capture_output=True, timeout=30)
    check(result.returncode == 0, 'bootstrap administrator: ' + result.stderr)


# Contract-specific cases below are intentionally real HTTP calls, never mocks.

def money(value):
    return Decimal(str(value)).quantize(Decimal('.01'))


def small_pdf():
    objects = [b'<< /Type /Catalog /Pages 2 0 R >>',
               b'<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
               b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] >>']
    result = b'%PDF-1.4\n'
    offsets = [0]
    for index, content in enumerate(objects, 1):
        offsets.append(len(result))
        result += str(index).encode() + b' 0 obj\n' + content + b'\nendobj\n'
    xref = len(result)
    result += b'xref\n0 4\n0000000000 65535 f \n'
    result += b''.join(('%010d 00000 n \n' % offset).encode() for offset in offsets[1:])
    return result + b'trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n' + str(xref).encode() + b'\n%%EOF\n'


def run():
    with tempfile.TemporaryDirectory(prefix='zhezu-intake-check-') as folder:
        server = Server(folder)
        legacy = seed_legacy_database(server.db)
        password = secrets.token_urlsafe(24)
        bootstrap(server, password)
        server.start()
        try:
            request = server.request
            response = request('/api/auth/login', 'POST', {'login': 'intake.admin', 'password': password})
            admin_user = expect(response, 200, 'administrator login')['user']
            admin = cookie(response[2])

            response = request('/api/auth/register', 'POST', {'login': 'intake.student', 'name': 'Intake Student', 'password': password})
            student = cookie(response[2])
            check(response[0] == 201 and response[1]['user']['role'] == 'student', 'student account without admin role')

            def applicants():
                return expect(request('/api/admin/applicants', cookie=admin), 200, 'read applicant registry')['applicants']

            def get_applicant(applicant_id):
                return next(item for item in applicants() if item['id'] == applicant_id)

            def create_applicant(name, **extra):
                response = request('/api/admin/applicants', 'POST', {
                    'name': name, 'phone': '', 'email': 'fixture@example.invalid',
                    'program': '', **extra,
                }, admin)
                return expect(response, 201, 'create applicant: ' + name)['applicant']

            def patch_applicant(applicant_id, fields, status=200, label='update applicant'):
                result = expect(request('/api/admin/applicants/' + applicant_id, 'PATCH', fields, admin), status, label)
                return result.get('applicant', result)

            migrated = get_applicant(legacy['id'])
            check(migrated['note'] == legacy['note'] and migrated['status'] == 'review', 'legacy notes and status survive migration')
            check(migrated['docs'] == legacy['docs'], 'legacy five-slot checklist remains compatible')
            check(migrated['funding'] == 'undecided', 'legacy funding is undecided, never invented')
            check(isinstance(migrated['documents'], list) and len(migrated['documents']) >= 6, 'legacy record receives full document checklist')
            migrated_received = {item['id'] for item in migrated['documents'] if item['received']}
            check({'statement', 'education', 'photos'}.issubset(migrated_received), 'legacy received documents retain their meaning')
            check(not migrated.get('payments'), 'legacy upgrade does not invent financial payments')

            grant = create_applicant('Grant Fixture', funding='grant', tuitionTotal=0)
            paid = create_applicant('Paid Fixture', funding='paid', tuitionTotal=300000,
                                    contractNumber='TEST-2026-1', contractDate='2026-08-01',
                                    academicYear='2026/2027', group='TEST-A',
                                    applicationNumber='APP-1', applicationDate='2026-08-02',
                                    enrollmentOrder='ORDER-1', enrollmentDate='2026-08-20',
                                    birthDate='2008-04-15', priorEducation='Test school', admissionBasis='After school')
            check(grant['funding'] == 'grant' and paid['funding'] == 'paid', 'grant and paid segmentation persists')
            check(any(d['id'] == 'grant_certificate' and d['required'] for d in grant['documents']), 'grant checklist requires award certificate')
            check(any(d['id'] == 'contract' and d['required'] for d in paid['documents']), 'paid checklist requires contract')
            check(any(d['id'] == 'medical075' and d['required'] for d in paid['documents']), 'medical certificate included in full required package')
            check(any(d['required'] and not d['received'] for d in paid['documents']), 'missing required documents are observable')
            check(paid['contractNumber'] == 'TEST-2026-1' and paid['applicationNumber'] == 'APP-1', 'intake and contract details retained')

            complete_documents = [{**item, 'received': True, 'receivedAt': '2026-08-21', 'note': 'Checked fixture'} for item in paid['documents']]
            paid = patch_applicant(paid['id'], {'documents': complete_documents}, label='save full document package')
            check(all(item['received'] for item in paid['documents'] if item['required']), 'required package can be marked complete')
            check(all(item['receivedAt'] == '2026-08-21' for item in paid['documents']), 'received dates retained per document')
            check(paid['docs'] == [True] * 5, 'new document package synchronizes compatible old checklist')
            invalid_documents = copy.deepcopy(paid['documents'])
            invalid_documents[0]['receivedAt'] = '2026-02-31'
            patch_applicant(paid['id'], {'documents': invalid_documents}, 400, 'impossible document date rejected')
            patch_applicant(paid['id'], {'funding': 'admin'}, 400, 'unknown funding rejected')

            plan = [
                {'id': 'first', 'label': 'First installment', 'dueDate': '2026-09-01', 'amount': 100000},
                {'id': 'second', 'label': 'Second installment', 'dueDate': '2027-01-01', 'amount': 100000},
                {'id': 'third', 'label': 'Third installment', 'dueDate': '', 'amount': 100000},
            ]
            paid = patch_applicant(paid['id'], {'installmentPlan': plan}, label='save exact tuition installment plan')
            check(len(paid['installmentPlan']) == 3, 'three installment rows retained')
            check(sum(money(item['amount']) for item in paid['installmentPlan']) == money(300000), 'installment sum equals tuition exactly')
            bad = copy.deepcopy(plan); bad[2]['amount'] = 99999.99
            patch_applicant(paid['id'], {'installmentPlan': bad}, 400, 'inexact installment sum rejected')
            bad = copy.deepcopy(plan); bad[0]['amount'] = -100
            patch_applicant(paid['id'], {'installmentPlan': bad}, 400, 'negative installment rejected')
            bad = copy.deepcopy(plan); bad[0]['amount'] = 100000.001
            patch_applicant(paid['id'], {'installmentPlan': bad}, 400, 'installment excess decimal places rejected')
            bad = copy.deepcopy(plan); bad[0]['dueDate'] = '2026-02-31'
            patch_applicant(paid['id'], {'installmentPlan': bad}, 400, 'impossible installment date rejected')
            bad = copy.deepcopy(plan); bad[1]['id'] = 'first'
            patch_applicant(paid['id'], {'installmentPlan': bad}, 400, 'duplicate installment identifiers rejected')

            def add_payment(amount, status=201, **extra):
                response = request('/api/admin/applicants/' + paid['id'] + '/payments', 'POST', {
                    'amount': amount, 'paidAt': '2026-08-25', 'method': 'transfer',
                    'reference': 'TEST-REF', 'note': 'Automated fixture', **extra,
                }, admin)
                return expect(response, status, 'record payment ' + repr(amount))

            for invalid in [0, -1, 10.001, '1.001', 'not money']:
                add_payment(invalid, 400)
            add_payment(100, 400, paidAt='2026-02-31')
            add_payment(100, 400, method='unsupported')
            add_payment(100, 400, role='admin')

            first = add_payment(100000)
            payment_one = first['payment']
            summary = first['applicant']['financialSummary']
            check(money(summary['tuitionTotal']) == money(300000), 'tuition total is 300000')
            check(money(summary['paid']) == money(100000) and money(summary['balance']) == money(200000), 'partial payment leaves exact 200000 balance')
            check(money(summary['percent']) == Decimal('33.33'), '100000 divided by 300000 rounds to 33.33 percent')
            check(money(summary['installments'][0]['paid']) == money(100000), 'unassigned payment allocates to first installment')
            check(sum(money(item['balance']) for item in summary['installments']) == money(summary['balance']), 'installment balances agree with tuition balance')
            check(payment_one['createdBy'] == admin_user['id'] and payment_one['createdByName'], 'payment records authenticated author')
            check(payment_one['amountMinor'] == 10000000, 'money persisted as exact minor units')
            check(summary['missingReceiptCount'] == 1, 'missing receipt count for active payment')

            pdf = small_pdf()
            png = base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jBM0AAAAASUVORK5CYII=')

            def upload(payment_id, payload=pdf, filename='fixture.pdf', mime='application/pdf', actor=admin, **extra):
                return request('/api/admin/payments/' + payment_id + '/receipt', 'POST', {
                    'filename': filename, 'mimeType': mime,
                    'contentBase64': base64.b64encode(payload).decode('ascii'), **extra,
                }, actor)

            for actor, expected in [('', 401), (student, 403)]:
                expect(upload(payment_one['id'], actor=actor), expected, 'receipt upload requires administrator')
                expect(request('/api/admin/applicants', cookie=actor), expected, 'financial metadata requires administrator')
                expect(request('/api/admin/applicants/' + paid['id'] + '/payments', 'POST', {'amount': 1}, actor), expected, 'payment mutation requires administrator')

            expect(upload(payment_one['id'], filename='../escape.pdf'), 400, 'receipt path traversal filename rejected')
            expect(upload(payment_one['id'], filename='fixture.exe'), 400, 'receipt executable extension rejected')
            expect(upload(payment_one['id'], payload=b'not a pdf'), 400, 'receipt signature required')
            expect(upload(payment_one['id'], payload=png, filename='spoof.pdf'), 400, 'receipt MIME and signature mismatch rejected')
            expect(upload(payment_one['id'], storagePath='../escape'), 400, 'receipt private storage path injection rejected')
            check(upload(payment_one['id'], payload=b'%PDF-1.4\n' + b'A' * (5 * 1024 * 1024) + b'\n%%EOF')[0] in (400, 413), 'receipt larger than five MiB rejected')

            uploaded = expect(upload(payment_one['id']), 201, 'valid PDF receipt saved')
            receipt_one = uploaded['receipt']
            receipt_url = receipt_one['url']
            check(receipt_one['filename'] == 'fixture.pdf' and receipt_one['size'] == len(pdf), 'receipt metadata records original safe name and size')
            check(uploaded['applicant']['financialSummary']['missingReceiptCount'] == 0, 'receipt clears missing confirmation count')
            status, downloaded, headers = request(receipt_url, cookie=admin)
            check(status == 200 and downloaded == pdf, 'administrator downloads exact private PDF bytes')
            check(headers.get('content-type', '').startswith('application/pdf') and 'attachment' in headers.get('content-disposition', ''), 'receipt sent as typed attachment')
            check('no-store' in headers.get('cache-control', ''), 'private receipt forbids caching')
            check('cookie' in headers.get('vary', '').lower(), 'receipt response varies by authenticated cookie')
            for actor, expected in [('', 401), (student, 403)]:
                expect(request(receipt_url, cookie=actor), expected, 'receipt download requires administrator')
            for path in ['/receipts/' + receipt_one['id'] + '.pdf', '/database.txt', '/../receipts/' + receipt_one['id'] + '.pdf', '/api/admin/receipts/%2e%2e%2fdatabase.txt']:
                check(request(path, cookie=admin)[0] in (400, 404, 405), 'private path blocked: ' + path)
            expect(upload(payment_one['id']), 409, 'receipt cannot silently overwrite existing confirmation')

            second = add_payment(150000)
            payment_two = second['payment']
            check(money(second['applicant']['financialSummary']['paid']) == money(250000), 'multiple payments aggregate exactly')
            check(money(second['applicant']['financialSummary']['balance']) == money(50000), 'multiple payments leave correct balance')
            uploaded_png = expect(upload(payment_two['id'], png, 'fixture.png', 'image/png'), 201, 'valid PNG receipt saved')
            png_url = uploaded_png['receipt']['url']
            check(request(png_url, cookie=admin)[1] == png, 'PNG private download matches uploaded bytes')
            third = add_payment(50000)
            check(money(third['applicant']['financialSummary']['balance']) == money(0) and money(third['applicant']['financialSummary']['percent']) == money(100), 'separate payments can settle full tuition')
            check(all(money(item['balance']) == money(0) for item in third['applicant']['financialSummary']['installments']), 'fully paid tuition does not leave a false overdue installment')
            fourth = add_payment(25000)
            payment_four = fourth['payment']
            check(money(fourth['applicant']['financialSummary']['overpayment']) == money(25000) and money(fourth['applicant']['financialSummary']['balance']) == money(0), 'overpayment tracked separately from zero balance')

            payment_path = '/api/admin/payments/' + payment_four['id']
            expect(request(payment_path, 'PATCH', {'voided': True, 'voidReason': ''}, admin), 400, 'cancellation requires reason')
            expect(request(payment_path, 'PATCH', {'voided': True, 'voidReason': 'Test reason'}, student), 403, 'student cannot cancel ledger entries')
            expect(request(payment_path, 'PATCH', {'amount': 1}, admin), 400, 'posted payment amount cannot be silently edited')
            cancelled = expect(request(payment_path, 'PATCH', {'voided': True, 'voidReason': 'Duplicate fixture payment'}, admin), 200, 'cancel overpayment with reason')
            voided = cancelled['payment']
            check(voided['voided'] is True and voided['voidReason'] == 'Duplicate fixture payment', 'cancelled row remains with reason')
            check(voided['voidedBy'] == admin_user['id'] and voided['voidedAt'], 'cancellation records authenticated actor and time')
            check(money(cancelled['applicant']['financialSummary']['paid']) == money(300000), 'cancelled payment excluded from active sum')
            check(len(cancelled['applicant']['payments']) == 4, 'cancellation never deletes original ledger row')
            check(len(cancelled['applicant']['audit']) > 0 and any(item.get('actorId') == admin_user['id'] and item.get('paymentId') == payment_four['id'] for item in cancelled['applicant']['audit']), 'financial audit records actor and payment linkage')
            expect(request('/api/admin/applicants/' + paid['id'], 'DELETE', {}, admin), 409, 'cannot delete applicant with financial ledger')
            patch_applicant(paid['id'], {'funding': 'grant', 'tuitionTotal': 0, 'installmentPlan': []}, 409, 'cannot erase paid segment after financial ledger')

            response = request('/api/inquiries', 'POST', {
                'name': 'Student Own Fixture', 'phone': '', 'email': 'student@example.invalid',
                'program': '', 'message': 'Private student fixture', 'consent': True,
            }, student)
            own_id = expect(response, 201, 'student creates own inquiry')['reference']
            patch_applicant(own_id, {'funding': 'paid', 'tuitionTotal': 2000, 'note': 'Internal financial note'})
            own = expect(request('/api/my/applications', cookie=student), 200, 'student can read own limited application')['applications']
            check(len(own) == 1 and own[0]['id'] == own_id, 'student never receives another applicant financial record')
            check(not any(field in own[0] for field in ['payments', 'audit', 'note', 'userId', 'receipts']), 'student response excludes internal finance metadata')

            server.restart()
            check(request('/api/auth/me', cookie=admin)[1]['user']['id'] == admin_user['id'], 'authenticated session survives restart')
            restarted = get_applicant(paid['id'])
            check(len(restarted['payments']) == 4 and next(item for item in restarted['payments'] if item['id'] == payment_four['id'])['voided'], 'ledger and cancellation survive restart')
            check(money(restarted['financialSummary']['paid']) == money(300000), 'financial summary recomputed after restart')
            check(request(receipt_url, cookie=admin)[1] == pdf and request(png_url, cookie=admin)[1] == png, 'both attachments persist across restart')
            for item in restarted['payments']:
                if not item.get('voided'):
                    expect(request('/api/admin/payments/' + item['id'], 'PATCH', {
                        'voided': True, 'voidReason': 'Close disposable fixture ledger',
                    }, admin), 200, 'cancel fixture ledger row without deletion')
            all_voided = get_applicant(paid['id'])
            check(len(all_voided['payments']) == 4 and all(item.get('voided') for item in all_voided['payments']), 'fully cancelled ledger still retains every entry')
            check(money(all_voided['financialSummary']['paid']) == money(0) and money(all_voided['financialSummary']['balance']) == money(300000), 'fully cancelled ledger restores exact tuition balance')
            expect(request('/api/admin/applicants/' + paid['id'], 'DELETE', {}, admin), 409, 'financial history prevents deletion even when all payments cancelled')
            check(request(receipt_url, cookie=admin)[1] == pdf, 'cancelling a payment retains its confirmation document')
            corrected = patch_applicant(paid['id'], {'funding': 'grant', 'tuitionTotal': 0, 'installmentPlan': []}, label='correct funding after all payments have been cancelled')
            check(corrected['funding'] == 'grant' and len(corrected['payments']) == 4 and all(item['voided'] for item in corrected['payments']), 'funding correction retains the complete cancelled ledger')
            check(any(item['id'] == 'grant_certificate' and item['required'] for item in corrected['documents']), 'corrected grant record receives applicable document requirement')
            expect(request('/api/admin/applicants/' + paid['id'], 'DELETE', {}, admin), 409, 'funding correction does not remove financial history protection')
            private_folder = pathlib.Path(folder) / 'receipts'
            check(private_folder.is_dir() and len([p for p in private_folder.rglob('*') if p.is_file()]) == 2, 'exactly two successful receipts stored outside public folder')
            saved = json.loads(server.db.read_text(encoding='utf8'))
            check(len(saved['payments']) == 4 and len(saved['receipts']) == 2 and len(saved['audit']) > 0, 'text database persists ledger, receipts and audit')
            check(password not in server.db.read_text(encoding='utf8'), 'no cleartext password enters financial database')

            # An employee accidentally editing Notepad while the server is open
            # must never have those edits silently replaced by a cached copy.
            legacy_on_disk = next(item for item in saved['applicants'] if item['id'] == legacy['id'])
            legacy_on_disk['note'] = 'Manual Notepad edit while the server is open'
            externally_edited = (json.dumps(saved, ensure_ascii=False, indent=2) + '\n').encode('utf8')
            server.db.write_bytes(externally_edited)
            expect(request('/api/admin/applicants/' + legacy['id'], 'PATCH', {'note': 'Must not overwrite Notepad'}, admin), 409, 'concurrent external Notepad edit blocks application save')
            check(server.db.read_bytes() == externally_edited, 'external file edits remain byte-for-byte intact after rejected save')
            check(get_applicant(legacy['id'])['note'] == legacy['note'], 'rejected mutation is rolled back in memory')
            server.restart()
            check(get_applicant(legacy['id'])['note'] == legacy_on_disk['note'], 'restart loads the actual Notepad changes')
            persisted = server.db.read_bytes()
            server.db.unlink()
            expect(request('/api/admin/applicants/' + legacy['id'], 'PATCH', {'note': 'Must not recreate missing file'}, admin), 409, 'externally removed database blocks writes')
            check(not server.db.exists(), 'missing database is never silently recreated from stale memory')
            server.stop()
            server.db.write_bytes(persisted)
        finally:
            server.close()


if __name__ == '__main__':
    run()
    print('PASS:', passed, 'intake, financial ledger and private receipt checks using temporary fixtures')
