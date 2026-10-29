import contextlib
import io
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from bluetooth_claim_audit import __version__
from bluetooth_claim_audit.audit import audit, claims, evidence, main
from bluetooth_claim_audit.phrases import BLUETOOTH, NOBLUETOOTH
from tests.cases import GOOD, BAD

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / 'tests' / 'fixtures'


class AuditTests(unittest.TestCase):
    def project(self, doc, code=None, filename='app.py'):
        temp = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(temp.cleanup)
        path = Path(temp.name)
        (path / 'README.md').write_text(doc)
        if code is not None:
            file = path / filename
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text(code)
        return path

    def test_fixtures(self):
        for name, severity, rule in [('good', None, None), ('bad', 'HIGH', 'documented-bluetooth-claim-false'), ('testonly', 'MEDIUM', 'documented-bluetooth-claim-false'), ('no-bluetooth', 'HIGH', 'documented-no-bluetooth-claim-false')]:
            with self.subTest(name=name):
                result = audit(FIXTURES / name)
                self.assertEqual(len(result['findings']), int(severity is not None))
                if severity:
                    self.assertEqual(result['findings'][0]['severity'], severity)
                    self.assertEqual(result['findings'][0]['rule'], rule)
                self.assertEqual(result['verdict'], 'FAIL' if severity == 'HIGH' else 'PASS')
        self.assertEqual(audit(FIXTURES / 'testonly', fail_on='MEDIUM')['verdict'], 'FAIL')

    def test_self_audit(self):
        self.assertEqual(claims((ROOT / 'README.md').read_text()), (False, False))
        self.assertEqual(audit(ROOT)['findings'], [])

    def test_env_never_opened(self):
        original = io.open
        def guarded(file, *args, **kwargs):
            if isinstance(file, (str, Path)) and Path(file).name == '.env':
                self.fail('Environment marker opened')
            return original(file, *args, **kwargs)
        with patch('io.open', guarded):
            self.assertTrue((FIXTURES / '.env').exists())
            audit(ROOT)
            audit(FIXTURES)

    def test_normalization(self):
        self.assertEqual(claims("This CONNECTS-TO\nBLUETOOTH devices."), (True, False))
        self.assertEqual(claims("It doesn't connect via bluetooth."), (False, True))
        self.assertEqual(claims('xconnect via bluetoothx'), (False, False))
        self.assertEqual(claims('connect via\n\nbluetooth'), (False, False))

    def test_fences_inline(self):
        for fence in ('```', '~~~~'):
            self.assertEqual(claims(fence+'text\n'+BLUETOOTH[0]+'\n'+fence), (False, False))
        self.assertEqual(claims('`'+BLUETOOTH[0]+'`'), (True, False))

    def test_nonclaims(self):
        for text in ['bluetooth', 'turn on bluetooth on your phone first', 'enable bluetooth on your phone before starting', 'plays audio over bluetooth', 'listens through bluetooth headphones', 'USB link and TCP file export']:
            self.assertEqual(audit(self.project(text))['findings'], [])
            self.assertEqual(audit(self.project(text, GOOD[0]))['findings'], [])

    def test_no_source(self):
        self.assertEqual(audit(self.project(BLUETOOTH[0]))['findings'][0]['severity'], 'HIGH')
        self.assertEqual(audit(self.project(NOBLUETOOTH[0]))['findings'], [])

    def test_two_families_maximum(self):
        path = self.project('\n\n'.join(BLUETOOTH + NOBLUETOOTH))
        self.assertEqual(len(audit(path)['findings']), 1)
        (path / 'app.py').write_text(GOOD[0])
        self.assertEqual(len(audit(path)['findings']), 1)
        self.assertEqual(audit(path)['findings'][0]['rule'], 'documented-no-bluetooth-claim-false')

    def test_scopes(self):
        for filename in ['tests/device.py', 'test_device.py', 'device_test.py']:
            result = audit(self.project(BLUETOOTH[0], GOOD[0], filename))
            self.assertEqual(result['findings'][0]['severity'], 'MEDIUM')
        for filename in ['docs/device.py', 'examples/device.py', 'fixtures/device.py']:
            self.assertEqual(audit(self.project(BLUETOOTH[0], GOOD[0], filename))['findings'][0]['severity'], 'HIGH')

    def test_docs_and_ignore(self):
        path = self.project('overview')
        (path / 'nested/docs').mkdir(parents=True)
        (path / 'nested/docs/claim.md').write_text(BLUETOOTH[0])
        self.assertEqual(audit(path)['verdict'], 'FAIL')
        self.assertEqual(audit(path, ['nested/docs/*.md'])['verdict'], 'PASS')
        self.assertEqual(audit(path, ['nested'])['verdict'], 'PASS')

    def test_symlinks(self):
        path = self.project(BLUETOOTH[0])
        (path / 'app.py').symlink_to(FIXTURES / 'good/app.py')
        (path / 'linked').symlink_to(FIXTURES / 'good', target_is_directory=True)
        self.assertEqual(audit(path)['verdict'], 'FAIL')

    def test_cross_module(self):
        path = self.project(BLUETOOTH[0], 'from bleak import BleakClient\nc=BleakClient(address)')
        (path / 'second.py').write_text('c.connect(address)')
        self.assertEqual(audit(path)['verdict'], 'FAIL')

    def test_syntax_warning(self):
        result = audit(self.project(BLUETOOTH[0], 'invalid !!!'))
        self.assertEqual(result['verdict'], 'FAIL')
        self.assertEqual(len(result['warnings']), 1)

    def test_cli(self):
        for argv, expected in [(['--version'], 0), (['/absent/path'], 1), ([], 1), ([str(FIXTURES/'bad'), '--fail-on', 'LOW'], 1)]:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                try:
                    code = main(argv)
                except SystemExit as error:
                    code = error.code
            self.assertEqual(code, expected)
        for name, threshold, code in [('good','HIGH',0),('bad','HIGH',2),('testonly','HIGH',0),('testonly','MEDIUM',2),('no-bluetooth','HIGH',2)]:
            proc = subprocess.run([sys.executable, '-m', 'bluetooth_claim_audit', str(FIXTURES/name), '--json', '--fail-on', threshold], capture_output=True, text=True)
            self.assertEqual(proc.returncode, code, proc.stderr)
            self.assertIn(json.loads(proc.stdout)['verdict'], ('PASS','FAIL'))
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main([str(FIXTURES/'bad'), '--ignore', 'README.md', '--verbose']), 0)
        self.assertIn('documents', output.getvalue())

    def test_packaging(self):
        self.assertEqual(__version__, '0.1.0')
        config = (ROOT/'pyproject.toml').read_text()
        self.assertIn('bluetooth-claim-audit = "bluetooth_claim_audit.audit:main"', config)
        self.assertIn('requires-python = ">=3.9"', config)
        self.assertIn('MIT License', (ROOT/'LICENSE').read_text())
        self.assertIn('recursive-include tests', (ROOT/'MANIFEST.in').read_text())
        for file in list((ROOT/'bluetooth_claim_audit').glob('*.py')) + [ROOT/'README.md']:
            text = file.read_text()
            self.assertIsNone(re.search(r'(?<![\w-])python\s+(?:-m|[^\s]*\.py)', text))
            self.assertIsNone(re.search(r'(?:AKIA[0-9A-Z]{16}|-----BEGIN PRIVATE KEY-----)', text))


def add_case(name, function):
    function.__name__ = name
    setattr(AuditTests, name, function)

for index, source in enumerate(GOOD):
    def check(self, source=source):
        self.assertTrue(evidence(source))
        self.assertEqual(audit(self.project(BLUETOOTH[0], source))['findings'], [])
    add_case('test_good_route_%02d' % index, check)
for index, source in enumerate(BAD):
    def check(self, source=source):
        self.assertFalse(evidence(source))
        result = audit(self.project(BLUETOOTH[0], source))
        self.assertEqual(result['verdict'], 'FAIL')
        self.assertEqual([(f['rule'], f['severity']) for f in result['findings']], [('documented-bluetooth-claim-false', 'HIGH')])
    add_case('test_bad_route_%02d' % index, check)
for index, phrase in enumerate(BLUETOOTH):
    def check(self, phrase=phrase):
        self.assertEqual(claims(phrase), (True, False))
        self.assertEqual(audit(self.project(phrase))['verdict'], 'FAIL')
    add_case('test_positive_phrase_%02d' % index, check)
for index, phrase in enumerate(NOBLUETOOTH):
    def check(self, phrase=phrase):
        self.assertEqual(claims(phrase), (False, True))
        self.assertEqual(audit(self.project(phrase))['findings'], [])
        result = audit(self.project(phrase, GOOD[0]))
        self.assertEqual([(f['rule'], f['severity']) for f in result['findings']], [('documented-no-bluetooth-claim-false', 'HIGH')])
    add_case('test_negative_phrase_%02d' % index, check)
