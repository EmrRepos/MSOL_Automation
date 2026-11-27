# MSOL Automation

MSOL Automation provides two desktop frameworks for testing authorized devices:

- **USB:** discover serial/COM devices, run USB validation and security
  reviews, use a serial console, and capture or analyze USB traffic.
- **EtherNet/IP:** inspect a single authorized target, run bounded baseline or
  selected tests, and record attack-surface review evidence.

Use the tools only with permission and an approved scope. Live tests can affect
devices or processes; use a lab or approved maintenance window, and have a
recovery plan. A completed run does not by itself prove a device is secure.

## Setup

The shared environment is tested on **Windows x64 with Python 3.14 x64**.
Install Python first, then open PowerShell in the repository root:

```powershell
py -3.14 setup_environment.py
```

The script creates or reuses `.venv`, installs the packages listed in
[requirements.txt](requirements.txt), and checks for dependency conflicts.
Internet access is needed for the initial installation. Run the same command
after dependencies change. If an existing environment uses a different Python
version or is invalid, setup reports an error instead of replacing it.

## Start a framework

Run these commands from the repository root:

```powershell
# See available frameworks
.\.venv\Scripts\python.exe launcher.py --list

# Open the USB application
.\.venv\Scripts\python.exe launcher.py usb

# Open the EtherNet/IP application
.\.venv\Scripts\python.exe launcher.py ethernetip
```

Each command opens the selected application; choose and start tests in its UI.
Starting the USB application scans for COM ports. Opening the EtherNet/IP UI
does not itself send traffic to a target.

### USB: first run

1. Connect the authorized device, launch USB, and select its COM port. Check
   the displayed device identity.
2. Select **Standard USB Validation**. Leave **Hardware mode** off for
   metadata-only checks, or enable it for supported live USB/serial access.
   Hardware-dependent checks can be blocked when evidence is unavailable.
3. Click **START TEST**. The seven grouped checks appear in the
   **Standard USB Validation** tab; switch to **Live Event Log** for the log.
4. Wait for the run and report saving to finish. Checks run once, with a
   10-second post-check completion period. Use **VIEW REPORTS** to open saved
   results.

The USB application also offers separate profiles, a serial console, and
firmware USB capture. Capture requires additional tools and approval and can
record traffic from other devices on the same hub. See the
[USB guide](plugins/usb/README.md) for prerequisites, test limitations,
capture setup and troubleshooting.

### EtherNet/IP: first run

1. Launch EtherNet/IP and select **Load sample** to explore the UI without
   sending network traffic.
2. For a real assessment, enter the approved target IPv4 address and operator
   or scope reference, and attest authorization in the UI.
3. In **Runnable tests**, select one or more applicable cases and click
   **Run selected**, or choose **Run live suite** for the bounded baseline.
   Fuzz tests require separate approval and confirmation.
4. Review the results and use **Export PDF** to save them. The export dialog
   also allows JSON.

The **Excel cases (46)** tab shows the baseline workbook cases and their
coverage. Some are only partially covered, manual, profile-dependent or
excluded; they are not all runnable. Device applicability is not automatically
determined. Export evidence before starting another assessment if it must be
retained, since a new run replaces the current assessment.

See the [EtherNet/IP guide](plugins/ethernetip/README.md) for test selection,
traffic limits, safety requirements and interpretation of results.

## Reports and results

When launched from the repository root, default report locations are:

| Framework | Location | Format and saving |
| --- | --- | --- |
| USB | `reports\usb` | Automated tests save PDF and CSV reports. The Report Center can open them. |
| EtherNet/IP | `reports\ethernetip` | The UI export dialog defaults here; saving a PDF or JSON report is manual. |

For source runs, USB test history is stored in `plugins\usb\usb_tests.db`,
regardless of the launch directory. An existing root `usb_tests.db` is not
moved or merged automatically. Report paths are relative to the directory from
which the launcher is run. Protect history, reports, logs and captures: they
may contain device or assessment information.

Interpret results in context: **BLOCKED**, **SKIPPED**, **ERROR** and
**CANCELLED** are not passes. EtherNet/IP observations, timeouts and incomplete
coverage do not establish a vulnerability or prove its absence.

## EtherNet/IP command line

The launcher forwards arguments to EtherNet/IP. These commands are offline:

```powershell
# Show the assessment catalog and test coverage
.\.venv\Scripts\python.exe launcher.py ethernetip assess
.\.venv\Scripts\python.exe launcher.py ethernetip coverage

# Show all EtherNet/IP CLI options
.\.venv\Scripts\python.exe launcher.py ethernetip --help
```

Active commands require an explicitly authorized target, `--authorized`, and
an operator/scope reference; fuzzing also requires separate authorization.
CLI output is JSON on the console. To save a report, provide `--output` with a
`.pdf` or `.json` path. See the
[EtherNet/IP CLI guide](plugins/ethernetip/README.md#cli) for examples and
the meaning of exit codes.

## Build Windows executables

On Windows x64, set up the shared Python 3.14 environment first, then run:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-build.txt
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\build_release.ps1
```

The script creates `release\USB.exe` and `release\Ethernetip.exe` and checks
that essential modules and resources are present. It refuses to overwrite an
existing output directory. For another build, choose a new directory:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\build_release.ps1 -OutputDirectory release-1.0.0
```

Share only the two `.exe` files, not the `_build` and `_spec` folders. Before
publishing, test each executable on a clean Windows machine without Python,
including report export and the approved target-device workflows. The tester
still needs the device driver; USB capture separately requires USBPcap and
appropriate permissions. These builds open the GUI; the EtherNet/IP CLI is not
intended for use through the windowed executable.

After verification, upload the executables to a versioned release. Generate
SHA-256 checksums for recipients with:

```powershell
Get-FileHash .\release\USB.exe, .\release\Ethernetip.exe -Algorithm SHA256
```

The USB executable writes reports and history under
`%LOCALAPPDATA%\USB_Pentest_Framework`. Its bundled device profiles are
read-only resources, not persistent user-editable files. EtherNet/IP exports
are saved manually to the destination selected in the UI.

## Repository layout

```text
MSOL_Automation/
|-- launcher.py              # Lists and launches a framework
|-- setup_environment.py     # Creates or updates the shared environment
|-- build_release.ps1        # Builds and checks both Windows executables
|-- requirements.txt         # Dependencies for both frameworks
|-- requirements-build.txt   # Additional executable build dependency
|-- framework/
|   `-- plugin_loader/       # Discovery, lifecycle and process isolation
|-- plugins/
|   |-- usb/                 # USB application and tests
|   `-- ethernetip/          # EtherNet/IP application and tests
`-- tests/                   # Launcher and setup tests
```

The launcher discovers plugin adapters in `plugins`. The USB and EtherNet/IP
adapters run their applications in separate processes. The other folders under
`framework` are reserved for future shared implementations; protocol-specific
code remains inside its plugin.

To add a framework, create `plugins\<name>\__init__.py` and `plugin.py`.
The latter exports a `Plugin` subclass of
[`FrameworkPlugin`](framework/plugin_loader/base.py), accepting forwarded
arguments and implementing `initialize()`, `execute_tests()` and `shutdown()`.
`execute_tests()` returns an integer exit code. The launcher calls `shutdown()`
even when initialization or execution fails.

## Verification

To run the offline launcher and setup tests from the repository root:

```powershell
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -v
```

For framework-specific tests and display requirements, see the
[USB guide](plugins/usb/README.md#development-and-ci) and
[EtherNet/IP guide](plugins/ethernetip/README.md#verification). Offline tests
do not establish interoperability with a physical device.
