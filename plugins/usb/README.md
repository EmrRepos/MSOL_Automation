# USB Validation & Security Testing Console

## 1. Overview

A Windows desktop application for discovering USB serial/COM devices, running
validation and security reviews, communicating over serial, capturing USB traffic,
and exporting evidence for development teams.

Device selection uses the connected device's identity, not a fixed VID/PID list.
Use only on authorized devices and protect captures and reports containing
sensitive information.

## 2. Prerequisites

- **Windows x64** with **Python 3.14 x64** installed; this is the CI-tested environment.
- A USB serial/COM device and its manufacturer-approved Windows driver for live testing.
- Internet access for the initial Python dependency installation.
- **Optional:** Wireshark with USBPcap installed for firmware USB capture; restart Windows if requested.
- **Capture only:** run the application from an administrator PowerShell terminal.
- **Firmware updates:** use the manufacturer's approved updater, firmware and maintenance procedure.

Offline capture analysis does not require connected hardware or USBPcap to be running.

## 3. Initial Setup

Download or clone this repository, then open PowerShell in its root folder.

### Create the Python environment

```powershell
py -3.14 -m venv .venv
```

### Install dependencies

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pip check
```

### Start the application

```powershell
.\.venv\Scripts\python.exe main.py
```

These commands use the virtual environment directly; activation and PowerShell
execution-policy changes are not required. Run from the repository root so
reports, device profiles and history use the expected locations.
Source execution is the maintained workflow; executable build configuration is
not maintained.

## 4. Project Architecture and Hardware Mode

The UI selects devices and workflows, the runner coordinates plugins and
hardware access, and the reporting/history components save results. Shared Python
modules live in the `core` package; only the application entry point remains at
the root. The startup command is unchanged.

```text
USB_Pentest_Framework/
|-- main.py                         # Application entry point
|-- requirements.txt                # Python dependencies
|-- TEST_PROFILES.md                # Detailed profile reference
|-- core/
|   |-- __init__.py
|   |-- theme.py                    # Application styling
|   |-- com_port_manager.py         # COM discovery and metadata
|   |-- device_manager.py           # Device management
|   |-- usb_class_mapper.py         # USB class labels
|   |-- test_runner.py              # Execution, cancellation and reporting
|   |-- test_suite.py               # Standard suite and revalidation
|   |-- plugin_loader.py            # Plugin discovery
|   |-- hardware_helpers.py         # USB/serial hardware operations
|   |-- device_profile.py           # Device-specific serial profiles
|   |-- serial_evidence.py          # Serial response evidence
|   |-- findings.py                 # Security finding representation
|   |-- firmware_capture.py         # Passive USBPcap recording
|   |-- packet_analysis.py          # Offline USB packet analysis
|   |-- report_generator.py         # PDF/CSV exports
|   `-- database.py                 # SQLite history storage
|-- ui/
|   |-- main_window.py              # Main application and workflow guards
|   |-- header.py
|   |-- top_toolbar.py
|   |-- dashboard_panel.py
|   |-- com_port_panel.py
|   |-- device_details_panel.py
|   |-- test_panel.py
|   |-- suite_results_panel.py
|   |-- firmware_capture_panel.py
|   |-- packet_analysis_dialog.py
|   |-- report_center.py
|   |-- log_panel.py
|   `-- settings_dialog.py
|-- plugins/
|   |-- base.py
|   |-- enumeration_test.py
|   |-- descriptor_test.py
|   |-- descriptor_robustness_test.py
|   |-- endpoint_test.py
|   |-- cdc_test.py
|   |-- hid_test.py
|   |-- storage_test.py
|   |-- enumeration_stress_test.py
|   |-- cdc_security_review.py
|   |-- hid_attack_surface_review.py
|   |-- storage_exposure_review.py
|   |-- reconnect_test.py
|   |-- stability_test.py
|   |-- serial_comm_test.py
|   `-- serial_console.py
|-- device_profiles/                # JSON serial-protocol configuration
|-- tests/                          # Unit and headless GUI tests
|-- reports/                        # Generated PDF/CSV reports
|-- logs/                           # Local log files, where used
|-- usb_tests.db                    # Local SQLite test history
`-- .github/workflows/ci.yml         # Windows/Python CI
```

### What is Hardware mode?

- **On:** allows the selected profile to access real USB/serial hardware, subject to driver permissions.
- **Off:** uses metadata-only behavior; the standard suite does not perform device I/O and hardware-dependent results remain BLOCKED.
- **Serial Console:** connects manually with its own settings; it does not require Hardware mode.
- **Capture and analysis:** separate workflows; Hardware mode does not start them.

Do not replace a production device's driver just to obtain a passing descriptor
result. Unavailable evidence is not a hardware pass.

## 5. Key Features and Coverage

| Feature | Scope and coverage |
|---|---|
| COM discovery | Detects COM ports and displays available device identity and USB metadata. |
| Standard USB Validation | Runs seven grouped validations once and finishes automatically after a 10-second post-check period. |
| Enumeration Validation | Validates available enumeration and selected-device identity evidence. |
| Descriptor Validation | Validates available USB descriptor fields and identity evidence. |
| Descriptor Robustness | Evaluates basic metadata/identifier consistency, not exhaustive fuzzing. |
| Endpoint Validation | Evaluates available endpoint descriptors. |
| CDC Validation | Evaluates CDC descriptors or correlated Windows driver evidence for the selected COM port. |
| HID Validation | Evaluates HID interface evidence when accessible. |
| Storage Validation | Evaluates mass-storage interface evidence when accessible. |
| Enumeration Stress Test | Performs repeated descriptor reads as a separately confirmed workflow. |
| CDC Security Review | Reviews serial exposure and may send a configured read-only profile probe in Hardware mode. |
| HID Attack Surface Review | Reviews HID interface exposure; does not inject keystrokes. |
| Storage Exposure Review | Reviews mass-storage interface exposure; does not establish access to sensitive files. |
| Reconnect Validation | Runs the separate reconnect-observation workflow. |
| Stability Validation | Performs repeated observations; not long-duration stability certification. |
| Serial Console | Sends user-supplied ASCII/HEX and observes responses using configurable serial settings. |
| Firmware USB Capture | Passively records whole-hub USB traffic while the user runs the vendor updater. |
| Packet Security Analysis | Reviews supported USB captures for credential-like text, readable data, transfer issues and repeated payloads. |
| Live Results and Event Log | Displays evidence, outcomes, durations, timestamped boundaries and check separators. |
| Dashboard | Summarizes detected/authorized devices, test runs and passed results. |
| Reporting and History | Saves PDF/CSV evidence reports and automated test summaries in SQLite. |

The seven standard validations are grouped under **Standard USB Validation**,
not duplicated as individual selector entries. Detailed profile documentation is
available in [TEST_PROFILES.md](TEST_PROFILES.md).

## 6. How to Run

### Standard validation

1. Connect the authorized device and start the application using the setup command.
2. Select its COM port and confirm the displayed identity.
3. Disconnect the Serial Console and other applications using that port.
4. Choose **Standard USB Validation** and enable **Hardware mode** for live access.
5. Click **START TEST** and review the live results and event log.
6. Wait for automatic completion and report saving; use **View Results** to reopen the latest session results.
7. Open **Report Center** to view saved PDF/CSV reports.

Automated profiles finish automatically 10 seconds after their checks complete,
whether results pass, fail, are blocked or are skipped. Report saving runs during
that period and may extend it if slow. **STOP TEST** can still request cancellation;
native driver calls may take time to return. Stopping during the post-check wait
preserves completed results. The standard suite does not repeat the checks.

### Other workflows

- **Separate profiles:** select the required stress, security, reconnect or stability profile, then click START TEST; review any confirmation first.
- **Serial Console:** select it, click START TEST, configure device-specific framing, then Connect; a missing reply does not prove rejection.
- **Firmware capture:** open FIRMWARE USB CAPTURE, select the correct root hub and a new capture file, confirm authorization, start recording, perform the approved update externally, then Stop Capture.
- **Packet analysis:** after capture stops, click Analyze Capture or browse to an existing capture, then Analyze and Save PDF/CSV; select an observation row for packet evidence.

Capture records every device on the selected hub and may include sensitive
traffic. It does not launch the updater, send commands or flash firmware.
Automated tests and serial connections are blocked during capture.
**STOP TEST does not stop capture or the vendor updater.**

### Interpreting results

- **PASS / FAIL:** the stated requirement succeeded or failed.
- **BLOCKED / SKIPPED:** evidence/access is unavailable, or an interface is verified as not applicable.
- **ERROR / CANCELLED:** an operation failed, or the run was stopped.

Interface exposure and pattern matches are not automatically confirmed
vulnerabilities. Standard USB validation does not establish HART/protocol
acceptance, firmware-signature enforcement or update success.

### Packet-analysis boundaries

Classic USBPcap PCAP (link type 249) is supported, including Wireshark exports,
both byte orders and microsecond/nanosecond timestamps. PCAPNG and other link
types are not yet supported. Large declared snapshot limits are accepted;
actual captured packets are limited to 1 MiB each.

Analysis is local and read-only, labels observations by bus/address without
claiming target identity, and omits raw payloads and credential values from
reports. Evidence includes frame numbers, timestamps, offsets and SHA-256 hashes.
There is no decryption or cross-packet reassembly; capture issues and analysis
limits are disclosed. No matches is **not a security pass**, and generic packet
analysis cannot guarantee detection of every vulnerability.

## 7. Supported Report Formats

- **PDF:** readable summaries, evidence, limitations and abbreviation definitions.
- **CSV:** tabular results with labelled evidence for further review.
- **JSON reports are not generated.** Device-profile JSON remains configuration.

Standard validation saves the following pair in `reports`, replacing the previous
pair on each run:

```text
USB_Suite_Validation_Report.pdf
USB_Suite_Validation_Report.csv
```

Independent test profiles use timestamped report names. Packet analysis asks for
an output destination and confirms replacement of existing PDF/CSV reports.
Older differently named reports are left untouched. Report Center lists PDF/CSV;
analysis reports saved elsewhere can be opened from their chosen location.
Export errors are explicitly logged.

## 8. Test History

Automated test summaries are stored locally in the SQLite database `usb_tests.db`,
including timestamp, device name, profile and result. Standard validation adds
one suite summary; detailed evidence remains in its reports.

Manual Serial Console sessions and offline packet analysis do not create
automated test-history entries. Keep the database and required reports when
archiving results; the standard suite report pair is replaced by the next run.

## Development and CI

Run the software tests without connected hardware:

```powershell
$env:QT_QPA_PLATFORM = "offscreen"
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -p "test_*.py" -v
```

[Python CI](.github/workflows/ci.yml) runs on pushes, pull requests and manual
workflow dispatch using Windows/Python 3.14. It checks dependencies, syntax and
tests with mocks, synthetic captures and serial loopback; it does not certify
physical devices, flash firmware, build executables or deploy the application.
The entry point disables bytecode-cache writes; use `-B` for other Python runs.

## Author

Kishor Rankhamb

Engineer II Product Security

USB Validation & Security Testing Console Development Project

## Version

Current Version: v1.0
