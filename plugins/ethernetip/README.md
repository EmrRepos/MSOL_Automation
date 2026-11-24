# Ethernet/IP Security Pentest Framework

Python desktop workbench for authorized EtherNet/IP assessments in ICS/OT environments.
It implements bounded live EtherNet/IP/CIP baseline tests, identity discovery, an
attack-surface review catalog and developer-oriented packet evidence reports. It can
connect to an explicitly authorized real device, but has only been verified against
offline simulated responses here. It is not an exhaustive vulnerability scanner or
a complete implementation of the CIP specifications.

## Run

Use Python 3.10+ with Tkinter available. The implemented functionality uses only the
Python standard library; no pip installation is required. The existing
`requirements.txt` lists optional libraries reserved for future work, not runtime
requirements for this increment. Windows python.org installations normally include Tk.
On Linux, install your distribution's Tkinter package if needed.

```powershell
python main.py
```

The native desktop window opens directly; there is no web server or browser URL.
**Load sample** uses a synthetic controller at the documentation address `192.0.2.10`
and sends no traffic. Sample evidence remains explicitly labeled in exported reports.

For a real assessment, enter one literal unicast IPv4 address and an operator/scope
reference. Start a manual assessment, confirm a single identity probe, or select
**Run live suite** after attesting authorization. The main screen shows **Live tests & coverage**
on the left and **Live Logs** on the right, with progress and identity observations. Selecting
a test displays its details. To run one or more executable tests, use **Ctrl+click** to
select separate rows or **Shift+click** to select a range, then click **Run selected** and
confirm the target and tests. CIP and fuzz cases also perform the
necessary session registration and cleanup; session-related cases perform those supporting
operations as needed. Non-executable coverage, manual-review and excluded rows cannot be
run this way. Device applicability is not detected automatically. Click **Attack surface**
next to **Load sample** to open the review window, select an area, record a decision and
supporting evidence, and save the review before exporting. Closing the review window retains
unsaved edits in memory; save them before export. Changing the scope requires a new assessment;
existing evidence cannot be relabeled with another target. New assessments replace
in-memory evidence, so export anything that must be retained.

Each selected run replaces the previous assessment, just like a full suite. Export the
result before starting another run if it must be retained. Reports identify all selected
cases; other cases are marked `not_run`, except for session setup and cleanup when needed.
Fuzz cases require a separate fuzzing confirmation. If the selection mixes baseline and
fuzz cases, the baseline runs first and fuzzing runs in a separate session after at least
one second. Cancellation, baseline failure, or failed baseline cleanup prevents the fuzz
phase from starting. Mixed runs use at most two sessions and 42 requests in total; each
phase retains its own pacing and work budget.

### Bounded fuzz tests

Fuzzing is separate from the existing read-only live suite. In **Live tests & coverage**,
click **Run fuzz tests** after entering the target and operator reference and checking
the authorization box. Confirm the additional warning only when fuzzing that specific
target is approved. Wait for the run to finish, inspect the `FUZ-01` through `FUZ-04`
rows, and click **Export JSON**. Starting either suite replaces the current evidence and
reviews, so export the previous assessment first.

The four fixed cases probe class, instance and attribute boundaries and a mismatched CIP
path length using GetAttributeSingle. Their responses are observations, not automatic
pass/fail or vulnerability verdicts; boundary values may be valid for a particular device.
Timeouts and disconnects are inconclusive. An operator must monitor device and process
health and use **Stop** if necessary; this tool does not automatically monitor them.
This is not exhaustive fuzzing or protocol conformance testing.

For CLI use, from the repository root, replace the example IP with the authorized target:

```powershell
.\.venv\Scripts\python.exe .\plugins\ethernetip\main.py fuzz 192.0.2.10 --authorized --fuzz-authorized --operator "Name / approved ticket" --output "fuzz.json"
```

The output directory must already exist. The example IP is a documentation address, not a
real device. Omitting either authorization flag blocks the fuzz command.

## Safety Boundaries

- Obtain written authorization, approved network vantage points, a maintenance window,
	an operations contact, backups and a recovery/stop plan before sending traffic.
- Read-only does not mean risk-free. Fragile controllers and protocol stacks can be
	affected even by valid requests. Prefer a representative isolated lab first.
- **Probe identity** still sends just one ListIdentity request. **Run live suite** opens
	one TCP connection to `44818`, sends at most 12 requests and registers at most one
	session. The seven allowed CIP reads target Identity class `0x01`, instance `1`,
	attributes `1-7`, using GetAttributeSingle (`0x0E`). No arbitrary service executor exists.
- Live-suite request starts are spaced by at least 250 ms, with a 30-second work budget,
	no automatic retries and response payloads capped at 16 KiB. Individual connection or
	exchange deadlines default to 3 seconds and are configurable from 0.2-5 seconds via CLI.
	A cleanup-send attempt may extend the work budget by up to one pacing interval and
	one configured timeout, excluding OS scheduling overhead.
- **Stop** cancels subsequent test requests, not an already-blocking socket operation.
	After the current request finishes or times out, cleanup is attempted if the stream
	remains usable. A broken stream is closed without additional protocol requests.
	Force-closing the application can interrupt cleanup; stop and await completion first.
- There is no broadcast, subnet scan, automatic retry or background network polling.
- The opt-in fuzz suite sends up to 30 total requests including session setup and cleanup,
	with at least one second between requests, a 60-second work budget and no retries.
	It currently sends four fuzz cases. It stops after a timeout, transport failure,
	encapsulation rejection or malformed response. Cleanup may take an additional pacing
	interval and request timeout. A completed run does not establish device health.
- Write/reset/mode services, implicit I/O generation, ForwardOpen, flooding, credential
	attacks and broader fuzzing are not implemented or exposed in the UI or CLI.
- Authorization is an operator attestation, not a technical authorization enforcement
	system. Network controls and organizational approvals remain essential.

## Attack Surface

Potential impact labels describe what a failed control could affect. They are not
measured severity ratings or confirmed findings. All review areas begin **Not assessed**.
Identity discovery, a single session lifecycle and Identity-only CIP reads now have
live checks. Other assessment areas remain manual or explicitly unimplemented.

| ID | Area | Current assessment method |
| --- | --- | --- |
| EIP-01 | Identity disclosure / TCP 44818 | Single-target ListIdentity probe |
| EIP-02 | Discovery / UDP 44818 | Passive evidence and broadcast-domain review |
| EIP-03 | Session lifecycle and resource limits | One registration/cleanup lifecycle; limits remain manual |
| EIP-04 | Explicit CIP reads, objects and tags | Live Identity attributes 1-7; other objects remain uncovered |
| EIP-05 | Writes, resets and controller mode changes | Policy and physical safeguard review only |
| EIP-06 | CIP Security, trust and legacy paths | Profile, TLS/DTLS and certificate policy review |
| EIP-07 | Implicit I/O / UDP 2222 | Peer, multicast and approved capture review |
| EIP-08 | Connection ownership / ForwardOpen | Ownership and connection policy review |
| EIP-09 | Routed CIP / backplane / bridges | Architecture and conduit review |
| EIP-10 | Encapsulation, CPF and CIP parser robustness | Vendor evidence; isolated-lab planning only |
| EIP-11 | Firmware and published advisories | Exact product/build advisory matching |
| EIP-12 | Adjacent web, SNMP and engineering interfaces | Approved inventory and management review |
| EIP-13 | Segmentation and remote access | Firewall, zone and conduit review |
| EIP-14 | Detection, backups and recovery | Operations evidence and restoration review |

The catalog contains exposure, verification and mitigation guidance for each area.
Vendor-specific objects, device capabilities and deployed architecture require additional
review. This list is a starting point, not exhaustive or a conformance checklist.

A successful ListIdentity response is an **informational observation**, not proof of a
vulnerability, unrestricted CIP access or absent CIP Security. The reported revision is
not sufficient to establish firmware CVE applicability. Timeouts, rejected requests and
empty identity lists are inconclusive, not a clean bill of health. The returned identity
address is device-reported metadata and may differ from the actual scoped TCP endpoint.
Device metadata is unauthenticated and should be corroborated with approved inventory.

## CLI

Print the assessment catalog offline:

```powershell
python main.py assess
```

Print implemented live cases and explicit coverage gaps offline:

```powershell
python main.py coverage
```

The coverage output also traces all 46 cases from the Gen5 baseline workbook to
implemented read-only or partial fuzz coverage, profile-dependent checks, manual review,
or explicit exclusions. The two Identity-related enumeration cases are only partially covered:
the live suite reads Identity attributes 1-7 and does not establish whether that
exposure is authorized. Only the four explicitly listed fuzz cases are executable;
writes, flooding, and other excluded cases are not enabled by appearing in the catalog.

Authorized single-target request, using a documentation address as a placeholder:

```powershell
python main.py discover 192.0.2.10 --authorized --operator "Tester / approved ticket OT-123" --timeout 3 --output assessment.json
```

Run the bounded baseline after obtaining approval for the specific device:

```powershell
python main.py test 192.0.2.10 --authorized --operator "Tester / approved lab ticket OT-123" --timeout 3 --output device-baseline.json
```

To run selected cases instead, repeat the `--case` option, for example
`--case CIP-03 --case CIP-04` with `test`, or `--case FUZ-01 --case FUZ-02` with
`fuzz`. To mix baseline and fuzz cases, use the `selected` command with repeated
`--case` options and both `--authorized` and `--fuzz-authorized`. Reports include the
selection in reproduction arguments. Replace these examples with the cases and target
approved for your assessment.

Replace the placeholder only with an explicitly approved target. There are no live
network tests in the test suite. Discovery failures return exit code `1` and an
inconclusive report when the supplied scope is valid; missing required authorization
arguments return exit code `2`. An empty identity response returns `0` for a completed
exchange but remains inconclusive. The `assess` command does not contact a target.

The `test` and `fuzz` commands return `1` for an incomplete/cancelled suite or setup/export error
and `0` when the suite traversal completes. Exit code `0` does not mean all tests ran,
all controls passed, or no vulnerabilities exist. Inspect each case's status and any
skipped dependencies. Authorization arguments are mandatory for active commands.

## Live Baseline Cases

| Case | Request and observation |
| --- | --- |
| ENIP-01 | ListIdentity (`0x0063`): item lengths and identity metadata |
| ENIP-02 | ListServices (`0x0004`): item framing, version, capabilities and name |
| ENIP-03 | ListInterfaces (`0x0064`): count and item framing; unsupported is not a finding |
| ENIP-04 | RegisterSession (`0x0065`): version/options response and nonzero handle |
| CIP-01 | GetAttributeSingle: Identity vendor ID (`UINT`) |
| CIP-02 | Identity device type (`UINT`) |
| CIP-03 | Identity product code (`UINT`) |
| CIP-04 | Identity major/minor revision |
| CIP-05 | Identity status (`WORD`); not a process-state assertion |
| CIP-06 | Identity serial number (`UDINT`) |
| CIP-07 | Identity product name (`SHORT_STRING`) |
| ENIP-05 | UnregisterSession (`0x0066`) send, followed by local socket closure |

Encapsulation replies are checked for matching command, sender context, options,
session handle (where applicable) and payload limits. CIP checks validate CPF framing,
response service, additional-status lengths and successful Identity value lengths.
Stable metadata is compared between ListIdentity and CIP reads when one identity is
returned. Differences require investigation; gateways or configuration changes can
explain them. The dynamic status attribute is not compared.

Case statuses are `observed`, `unsupported`, `access_denied`, `protocol_anomaly`,
`inconclusive` and `not_run`. A malformed response stops subsequent test operations;
cleanup is still attempted when the encapsulation stream remains usable. The baseline suite
does not intentionally send malformed requests or invalid attribute paths.
No reply is specified for UnregisterSession, so the suite cannot assert remote session
deletion. Check device logs or vendor instrumentation for that assertion.

## Evidence and Reports

JSON exports include the scoped target, operator reference, authorization attestation,
live/sample/manual mode, request timestamp (when probed), outcome, identity metadata,
informational observations, all review decisions, limitations and reference links.
Live-suite reports additionally contain exact bounded request/response hex, partial
response bytes on receive failures, UTC timestamps, timings, CIP general/additional
status, decoded values, per-test exchange indices, consistency observations and the
coverage matrix. An SHA-256 digest covers the sorted-key JSON serialization of the
exchange list; it is not an authenticity signature.

`developer_review_candidates` separates observed protocol anomalies from confirmed
security findings. Entries include the expected structural behavior, actual result,
evidence indices and suggested verification. Reports provide CLI reproduction arguments,
but sender contexts and session handles will naturally change on another run.
Before submitting a device bug, attach the exact hardware/firmware, expected vendor
behavior, source network, logs, reproducibility and any demonstrated operational impact.
Do not assign vulnerability severity solely because the client rejected a response.
Only explicitly saved operator decisions are exported. Review decisions other than
**Not assessed** require evidence or a rationale; they are not machine-verified results.
Reports are local plaintext files without encryption or signing. Store them in an
approved evidence location and avoid entering passwords or other secrets in notes.
Keep original packet captures, change approvals and inventory records separately when
your evidence handling process requires them.

## Project Status

- `main.py`: desktop launcher and bounded CLI.
- `ui.py`: Tkinter inventory, review and evidence workflow; network work runs off the UI thread.
- `modules/discovery.py`: bounded TCP ListIdentity exchange and defensive packet parser.
- `modules/security.py`: attack-surface catalog and evidence-required review decisions.
- `modules/live_tests.py`: bounded live suite, result classifications and coverage matrix.
- `modules/fuzz_tests.py`: separately authorized bounded CIP boundary and malformed-path tests.
- `core/connection.py`, `core/session.py`, `core/cip.py`: bounded encapsulation transport,
  session lifecycle, CPF/CIP parsing and allowlisted Identity reads.
- `reports/report.py`: scoped JSON report generation.
- `tests/`: offline protocol, CLI, report and native desktop workflow tests.
- Remaining module skeletons, `dos/` and `fuzzing/`: not connected to the workbench.

## Coverage Limits and Device Profiles

No generic framework can guarantee **all EtherNet/IP/CIP test cases**. Coverage depends
on the applicable ODVA specifications, device capabilities, vendor objects and security
requirements. The UI and `coverage` command explicitly show these gaps:

- UDP discovery, implicit I/O, connected messaging, ownership and routed CIP: not implemented.
- Vendor objects, tags, assemblies and negative-access assertions: require a device profile.
- CIP Security TLS/DTLS handshakes and certificate validation: manual review only.
- CIP Safety, Motion, Sync and other specialized profiles: not implemented.
- CVE applicability and exact firmware matching: manual review only.
- Writes, resets, mode/firmware changes and exhaustion: excluded. Fuzzing is limited
  to the four opt-in CIP cases described above.
- The 46 workbook cases are retained in the coverage output with SRS references,
  associated live cases, and explicit coverage limits; the workbook's generic pass/fail
  criteria are not treated as device-specific expected results.

To define device-specific cases, collect vendor/model, hardware series, exact firmware
build, EDS or documented object/service map, expected access policy, network topology
and isolated-lab/recovery arrangements. A justified complete test plan must trace each
requirement to a case with expected results; unsupported capabilities should have an
explicit applicability decision, not a blanket pass.

## Next Increments

1. Import approved packet captures offline: inventory, explicit/implicit traffic and
	 engineering/I/O peer relationships, without replay or network requests.
2. Extend the existing Identity-only read allowlist using a reviewed device profile and
   expected results, first against a simulator and then approved isolated hardware.
3. Add structured CIP Security configuration evidence and certificate lifecycle checks.
4. Add exact model/hardware/firmware advisory correlation with source and applicability
	 evidence, without assuming that identity revision establishes a vulnerability.
5. Add assessment persistence, trusted evidence manifests and richer report formats.

Disruptive testing is not part of this implementation. Any separate robustness testing
needs its own isolated-lab scope, resource limits, instrumentation and recovery criteria.

## Verification

```powershell
python -m unittest discover -s tests -v
```

The tests use synthetic packets and mocked sockets. Native Tkinter UI tests need a
desktop/display and exercise normal and compact window sizes. Verified locally with
Python 3.14 on Windows; other supported interpreter versions have not been tested here.
No live controller interoperability, physical process safety or vendor conformance has
been validated.

## References

- [ODVA EtherNet/IP](https://www.odva.org/technology-standards/key-technologies/ethernet-ip/)
- [ODVA CIP Security](https://www.odva.org/technology-standards/key-technologies/cip-security/)
- [NIST SP 800-82 Rev. 3: Guide to OT Security](https://csrc.nist.gov/pubs/sp/800/82/r3/final)
- [CISA ICS advisories](https://www.cisa.gov/news-events/ics-advisories)

Use the applicable ODVA specifications and device-vendor documentation for normative
protocol details. The NIST publication page was consulted for OT safety, reliability
and performance considerations. ODVA page contents could not be retrieved during this
implementation; the links are reference starting points, not a claim of a completed
standards or advisory review.