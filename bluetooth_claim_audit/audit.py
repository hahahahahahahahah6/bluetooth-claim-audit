"""Documentation matching and module-local static provider evidence."""
import argparse
import ast
import fnmatch
import json
import os
from pathlib import Path
import re
import sys

from . import __version__
from .phrases import BLUETOOTH, NOBLUETOOTH


def normalize(text):
    return re.sub(r'\s+', ' ', text.lower().replace("n't", ' not').replace('-', ' '))


def claims(text):
    paragraphs = []
    lines = []
    fence = None
    for line in text.splitlines():
        match = re.match(r'^\s{0,3}(`{3,}|~{3,})(.*)$', line)
        if fence:
            if match and match[1][0] == fence[0] and len(match[1]) >= len(fence) and not match[2].strip():
                fence = None
            continue
        if match:
            fence = match[1]
            paragraphs.append(' '.join(lines)); lines = []
        elif not line.strip():
            paragraphs.append(' '.join(lines)); lines = []
        else:
            lines.append(line)
    paragraphs.append(' '.join(lines))
    positive = negative = False
    for paragraph in paragraphs:
        value = normalize(paragraph)
        for phrase in sorted(NOBLUETOOTH, key=len, reverse=True):
            value, count = re.subn(r'\b' + re.escape(phrase) + r'\b', ' ', value)
            negative |= bool(count)
        positive |= any(re.search(r'\b' + re.escape(p) + r'\b', value) for p in BLUETOOTH)
    return bool(positive), bool(negative)


def evidence(source):
    tree = ast.parse(source)
    aliases = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                aliases[item.asname or item.name.split('.')[0]] = item.name if item.asname else item.name.split('.')[0]
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            for item in node.names:
                aliases[item.asname or item.name] = node.module + '.' + item.name

    def path(node):
        if isinstance(node, ast.Name):
            return aliases.get(node.id, node.id if node.id == 'self' else '')
        if isinstance(node, ast.Attribute):
            base = path(node.value)
            return base + '.' + node.attr if base else ''
        return ''

    def provider(node, module, name):
        value = path(node)
        return value.startswith(module + '.') and value.split('.')[-1] == name

    def constructed(node):
        if not isinstance(node, ast.Call):
            return None
        for module, name, kind in [('bleak', 'BleakClient', 'bleak'), ('bleak', 'BleakScanner', 'scanner'), ('bluetooth', 'BluetoothSocket', 'pybluez'), ('bluepy.btle', 'Peripheral', 'peripheral'), ('bluepy.btle', 'Scanner', 'bluepy-scanner')]:
            if provider(node.func, module, name):
                return kind
        if provider(node.func, 'socket', 'socket'):
            if any(provider(arg, 'socket', 'AF_BLUETOOTH') for arg in list(node.args) + [kw.value for kw in node.keywords]):
                return 'socket'
        return None

    def key(node):
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == 'self':
            return 'self.' + node.attr
        return None

    bindings = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            kind = constructed(node.value)
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if kind:
                for target in targets:
                    if key(target):
                        bindings[key(target)] = kind
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if provider(node.func, 'bluetooth', 'discover_devices'):
            return True
        if not isinstance(node.func, ast.Attribute):
            continue
        receiver = node.func.value
        method = node.func.attr
        kind = constructed(receiver) or bindings.get(key(receiver))
        if method in ('discover', 'find_device') and (kind == 'scanner' or provider(receiver, 'bleak', 'BleakScanner')):
            return True
        if method == 'scan' and (kind == 'bluepy-scanner' or provider(receiver, 'bluepy.btle', 'Scanner')):
            return True
        methods = {'bleak': ('connect', 'read_gatt_char', 'write_gatt_char', 'start_notify', 'stop_notify'), 'pybluez': ('connect', 'send', 'recv'), 'socket': ('connect',), 'peripheral': ('connect',)}
        if method in methods.get(kind, ()):
            return True
    return False


def audit(root, ignore=(), fail_on='HIGH'):
    root = Path(root)
    if not root.is_dir():
        raise ValueError('root must be an existing readable directory')
    positive = negative = prod = test = False
    counts = {'documents': 0, 'sources': 0}
    warnings = []
    def excluded(relative):
        return any(fnmatch.fnmatchcase(relative, pattern) for pattern in ignore)
    def onerror(error):
        raise error
    for directory, dirs, files in os.walk(root, onerror=onerror, followlinks=False):
        dirs[:] = sorted(d for d in dirs if not (Path(directory) / d).is_symlink() and not excluded((Path(directory) / d).relative_to(root).as_posix()))
        for name in sorted(files):
            file = Path(directory) / name
            relative = file.relative_to(root)
            parts = relative.parts
            if file.is_symlink() or excluded(relative.as_posix()):
                continue
            if relative.as_posix() == 'README.md' or (file.suffix.lower() == '.md' and 'docs' in parts[:-1]):
                p, n = claims(file.read_text(encoding='utf-8'))
                positive |= p; negative |= n
                counts['documents'] += 1
            if file.suffix != '.py' or any(p in ('fixtures', 'docs', 'examples') for p in parts[:-1]):
                continue
            counts['sources'] += 1
            try:
                found = evidence(file.read_text(encoding='utf-8'))
            except (SyntaxError, UnicodeError) as error:
                warnings.append('{}: {}'.format(relative, error)); continue
            if 'tests' in parts[:-1] or name.startswith('test_') or name.endswith('_test.py'):
                test |= found
            else:
                prod |= found
    findings = []
    if positive and not prod:
        findings.append({'rule': 'documented-bluetooth-claim-false', 'severity': 'MEDIUM' if test else 'HIGH', 'message': 'Device claim has only test evidence.' if test else 'Device claim lacks production evidence.'})
    if negative and prod:
        findings.append({'rule': 'documented-no-bluetooth-claim-false', 'severity': 'HIGH', 'message': 'Negative device claim conflicts with production evidence.'})
    failed = any(f['severity'] == 'HIGH' or fail_on == 'MEDIUM' for f in findings)
    return {'verdict': 'FAIL' if failed else 'PASS', 'findings': findings, 'warnings': warnings, 'counts': counts}


class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(1, '{}: error: {}\n'.format(self.prog, message))


def main(argv=None):
    parser = Parser(description=__doc__)
    parser.add_argument('root')
    parser.add_argument('--json', action='store_true')
    parser.add_argument('--verbose', action='store_true')
    parser.add_argument('--ignore', action='append', default=[])
    parser.add_argument('--fail-on', choices=('HIGH', 'MEDIUM'), default='HIGH')
    parser.add_argument('--version', action='version', version=__version__)
    args = parser.parse_args(argv)
    try:
        result = audit(args.root, args.ignore, args.fail_on)
    except (OSError, ValueError, UnicodeError) as error:
        print(str(error), file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(result))
    else:
        print(result['verdict'])
        for finding in result['findings']:
            print('{severity} {rule}: {message}'.format(**finding))
        for warning in result['warnings']:
            print('WARNING: ' + warning)
        if args.verbose:
            print(json.dumps(result['counts']))
    return 2 if result['verdict'] == 'FAIL' else 0
