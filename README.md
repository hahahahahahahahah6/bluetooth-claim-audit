# bluetooth-claim-audit

Version 0.1.0. Python >=3.9. MIT licensed. No runtime dependencies.

Checks documented wireless device claims against Python AST evidence offline.
Audited source is never executed. Environment files are never opened.

```sh
python3 -m pip install .
bluetooth-claim-audit path/to/project --json
python3 -m bluetooth_claim_audit path/to/project --verbose
python3 -m unittest discover
python3 -m build
```

Root README.md and Markdown beneath any docs directory supply claims. Fenced
code is excluded; inline code counts. Matching lowercases, expands n't, replaces
hyphens with spaces, joins paragraph lines, and applies word boundaries.
Negative spans are removed before positive matching. Exact templates follow:

```text
connects to bluetooth devices
connect to bluetooth devices
connects to ble devices
connect to ble devices
connects via bluetooth
connect via bluetooth
connects over bluetooth
connect over bluetooth
pairs with bluetooth devices
pair with bluetooth devices
discovers bluetooth devices
discover bluetooth devices
discovers ble devices
discover ble devices
scans for bluetooth devices
scan for bluetooth devices
finds bluetooth devices
find bluetooth devices
sends data over bluetooth
send data over bluetooth
sends data via bluetooth
send data via bluetooth
transfers files over bluetooth
transfer files over bluetooth
transfers data over bluetooth
transfer data over bluetooth
communicates over bluetooth
communicate over bluetooth
communicates via bluetooth
communicate via bluetooth
supports bluetooth low energy
bluetooth low energy support
bluetooth file transfer
bluetooth data transfer
bluetooth connectivity
supports bluetooth
bluetooth support
supports ble
ble support
ble connectivity
uses bluetooth
use bluetooth
does not connect to bluetooth devices
does not connect via bluetooth
does not connect over bluetooth
does not pair with bluetooth devices
does not discover bluetooth devices
does not scan for bluetooth devices
does not send data over bluetooth
does not transfer files over bluetooth
does not communicate over bluetooth
does not communicate via bluetooth
does not support bluetooth low energy
does not support bluetooth
does not support ble
does not use bluetooth
bluetooth connectivity not supported
bluetooth not supported
ble not supported
no bluetooth support
without bluetooth support
no bluetooth connectivity
without bluetooth connectivity
no bluetooth
without bluetooth
```

At most one finding per family is emitted. The positive rule is
`documented-bluetooth-claim-false`: HIGH without production evidence, MEDIUM
when evidence occurs only in tests. The negative rule is

```text
documented-no-bluetooth-claim-false
```

This rule is HIGH when production evidence exists.
No claim means PASS. Without source, positive claims fail and negative ones pass.
Default threshold HIGH reports MEDIUM without failing; `--fail-on MEDIUM`
fails on either severity. Exit codes: 0 PASS, 2 FAIL, 1 usage or root error.
`--json` emits verdict and findings (rule, severity, message); `--verbose`
adds scanned-file counts. Repeat `--ignore GLOB` to exclude relative paths.
`--version` prints 0.1.0. Both entry points accept these options.

## Evidence and scope

Provider imports and aliases are resolved within each module for bleak,
pybluez's bluetooth module, socket, and bluepy.btle. Discovery, bound client
connection, GATT operations, bound pybluez socket send/receive, native sockets
with an explicit wireless address family, and bluepy scans are recognized.
Assignments to names and self attributes and chained construction are supported.
Imports, object construction alone, strings, comments and docstrings do not count.
Production excludes tests, test filenames, fixtures, docs and examples;
symlink files and directories are skipped. Test evidence can only lower the
positive finding to MEDIUM. Documentation location does not soften the negative rule.

## Limitations

Only the exact templates above count. A bare wireless technology name, user
instructions for phone setup, headset audio routing, wired/USB/plain network
links and file exports are outside this audit's dimension. System wireless
helpers invoked by subprocess are not recognized; shell command strings alone
are not evidence. Analysis is static and module local, with no runtime reachability,
inter-module binding, dynamic import or general data-flow proof. Syntax errors
are reported as warnings and yield no evidence for that file. A PASS is a
consistency result for these templates and routes, not a hardware test.
